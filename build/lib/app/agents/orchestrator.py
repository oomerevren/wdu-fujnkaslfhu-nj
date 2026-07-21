"""PentestOrchestrator — LangGraph-driven autonomous pentest pipeline.

The orchestrator defines a state graph with 6 nodes that form a complete
penetration testing workflow:
  1. recon     → Analyze target, fingerprint tech, discover endpoints
  2. plan      → Select scanners based on recon data
  3. execute   → Run selected scanners in parallel
  4. exploit   → Verify high/critical findings with PoC exploits
  5. analyze   → Correlate, deduplicate, CVSS score, prioritize
  6. report    → Build final report data structure

Conditional edges enable dynamic scanner selection based on real-time
reconnaissance data.
"""

import json
import time
from typing import TypedDict, Annotated, Optional, Any
from datetime import datetime
from uuid import UUID
from enum import Enum

from app.core.logging import logger
from app.config import settings
from app.agents.recon_agent import ReconAgent
from app.agents.scanner_agent import ScannerAgent
from app.agents.exploit_agent import ExploitAgent
from app.agents.analyzer_agent import AnalyzerAgent
from app.agents.knowledge_graph import knowledge_graph


# ---------------------------------------------------------------------------
# State definition
# ---------------------------------------------------------------------------

class PipelineStage(str, Enum):
    INIT = "init"
    RECON = "recon"
    PLAN = "plan"
    EXECUTE = "execute"
    EXPLOIT = "exploit"
    ANALYZE = "analyze"
    REPORT = "report"
    COMPLETE = "complete"
    FAILED = "failed"


class PentestState(TypedDict):
    """Complete state for a pentest pipeline run.

    This TypedDict flows through all LangGraph nodes, accumulating
    data at each stage. Each node reads from and writes to this state.
    """
    # Configuration
    target_url: str
    target_type: str  # "web", "api", "llm"
    auth_header: Optional[str]
    scan_id: Optional[str]
    user_id: Optional[str]
    target_id: Optional[str]

    # Pipeline control
    stage: PipelineStage
    errors: list[str]
    start_time: Optional[float]
    end_time: Optional[float]

    # Recon results
    tech_stack: list[dict]
    attack_surface: dict
    endpoints: list[dict]
    risk_indicators: list[dict]
    llm_insights: dict

    # Plan results
    scan_plan: dict  # scanners, configs, depth

    # Execute results
    findings_raw: list[dict]
    scanner_results: dict
    scanner_errors: list[str]

    # Exploit results
    findings_verified: list[dict]
    confirmed_findings: list[dict]
    false_positive_findings: list[dict]

    # Analyze results
    findings_analyzed: list[dict]
    analysis_summary: dict
    cvss_scores: dict
    remediation_priorities: list[dict]

    # Report results
    report_data: dict
    knowledge_graph_id: Optional[str]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class PentestOrchestrator:
    """LangGraph-based orchestrator for AI-driven penetration testing.

    The orchestrator builds a state graph and executes it asynchronously.
    Each stage is a separate node function that transforms the state.
    Conditional edges enable dynamic branching based on pipeline results.

    Usage:
        orchestrator = PentestOrchestrator()
        result = await orchestrator.run(
            target_url="https://example.com",
            user_id="uuid-here",
        )
    """

    def __init__(self, llm_client=None):
        self._llm = llm_client
        self._recon_agent = ReconAgent(llm_client=llm_client)
        self._scanner_agent = ScannerAgent()
        self._exploit_agent = ExploitAgent()
        self._analyzer_agent = AnalyzerAgent(llm_client=llm_client)
        self._graph = None
        self._app = None

    def _build_graph(self):
        """Build the LangGraph state graph with all nodes and edges.

        Graph structure:
            [START] → recon → plan → execute → exploit → analyze → report → [END]
                        │        │         │          │
                        └── retry ┘         └── skip if no high/crit findings
        """
        try:
            from langgraph.graph import StateGraph, START, END
        except ImportError:
            logger.error(
                "LangGraph not installed. Install with: pip install langgraph"
            )
            raise

        graph = StateGraph(PentestState)

        # Add nodes
        graph.add_node("recon", self._node_recon)
        graph.add_node("plan", self._node_plan)
        graph.add_node("execute", self._node_execute)
        graph.add_node("exploit", self._node_exploit)
        graph.add_node("analyze", self._node_analyze)
        graph.add_node("report", self._node_report)

        # Add edges: linear flow with conditional branches
        graph.add_edge(START, "recon")
        graph.add_edge("recon", "plan")
        graph.add_edge("plan", "execute")

        # Conditional: skip exploitation if no high/critical findings
        graph.add_conditional_edges(
            "execute",
            self._route_after_execute,
            {
                "exploit": "exploit",
                "analyze": "analyze",
            },
        )

        graph.add_edge("exploit", "analyze")
        graph.add_edge("analyze", "report")
        graph.add_edge("report", END)

        self._graph = graph
        self._app = graph.compile()

        logger.info("LangGraph pipeline compiled with 6 nodes")

    def _route_after_execute(self, state: PentestState) -> str:
        """Determine whether to run exploitation or skip to analysis."""
        findings = state.get("findings_raw", [])
        high_or_critical = [
            f for f in findings
            if (f.get("severity") or "info").lower() in ("high", "critical")
        ]
        if high_or_critical:
            logger.info(
                "Routing to exploit stage",
                extra={"high_critical_count": len(high_or_critical)},
            )
            return "exploit"
        logger.info("No high/critical findings, skipping exploit stage")
        return "analyze"

    # ------------------------------------------------------------------
    # Node implementations
    # ------------------------------------------------------------------

    async def _node_recon(self, state: PentestState) -> dict:
        """Node 1: Reconnaissance — analyze target and fingerprint tech."""
        logger.info("NODE: recon", extra={"url": state.get("target_url")})

        target_url = state.get("target_url", "")
        auth_header = state.get("auth_header")

        # Get tech stack knowledge from previous scans
        await knowledge_graph.initialize()
        tech_history = await knowledge_graph.get_tech_stack_knowledge(target_url)

        # Run reconnaissance
        recon_result = await self._recon_agent.analyze(target_url, auth_header)

        # Check if target type was provided, otherwise infer
        target_type = state.get("target_type", "web")
        if not state.get("target_type"):
            if recon_result.get("attack_surface", {}).get("is_json_api"):
                target_type = "api"
            elif "graphql" in [t.get("name", "") for t in recon_result.get("tech_stack", [])]:
                target_type = "api"
            elif "llm" in target_url.lower() or "openai" in target_url.lower():
                target_type = "llm"

        # Store target in knowledge graph
        kg_id = await knowledge_graph.store_target({
            "url": target_url,
            "tech_stack": recon_result.get("tech_stack", []),
            "target_type": target_type,
            "attack_surface": recon_result.get("attack_surface", {}),
        })

        return {
            "stage": PipelineStage.RECON,
            "target_type": target_type,
            "tech_stack": recon_result.get("tech_stack", []),
            "attack_surface": recon_result.get("attack_surface", {}),
            "endpoints": recon_result.get("endpoints", []),
            "risk_indicators": recon_result.get("risk_indicators", []),
            "llm_insights": recon_result.get("llm_insights", {}),
            "knowledge_graph_id": kg_id,
            "tech_history": tech_history,
        }

    async def _node_plan(self, state: PentestState) -> dict:
        """Node 2: Plan — select scanners and configure based on recon."""
        logger.info("NODE: plan", extra={"url": state.get("target_url")})

        # Build scan plan from recon data
        scan_plan = self._recon_agent._generate_scan_plan(
            url=state.get("target_url", ""),
            tech_stack=state.get("tech_stack", []),
            attack_surface=state.get("attack_surface", {}),
            risk_indicators=state.get("risk_indicators", []),
        )

        # If LLM is available, enhance plan with AI reasoning
        if self._llm:
            try:
                prompt = f"""Given this recon data, suggest the optimal scanner configuration:

Tech Stack: {json.dumps(state.get('tech_stack', []), indent=2)}
Attack Surface: {json.dumps(state.get('attack_surface', {}), indent=2)}
Risk Indicators: {json.dumps(state.get('risk_indicators', []), indent=2)}
Recommended Scanners: {json.dumps(scan_plan, indent=2)}

Suggest any adjustments to the scanner selection or configuration.
Respond in JSON format with 'adjustments' (string) and 'additional_scanners' (list of strings).
If no changes needed, respond with {{"adjustments": "Current plan is optimal", "additional_scanners": []}}"""

                response = await self._llm.ainvoke(prompt)
                content = response.content if hasattr(response, "content") else str(response)
                try:
                    json_match = __import__("re").search(r"\{.*\}", content, __import__("re").DOTALL)
                    if json_match:
                        llm_plan = json.loads(json_match.group())
                        additional = llm_plan.get("additional_scanners", [])
                        for scanner in additional:
                            if scanner not in scan_plan["scanners"] and scanner in self._scanner_agent.get_available_scanners():
                                scan_plan["scanners"].append(scanner)
                                if scanner not in scan_plan["configs"]:
                                    scan_plan["configs"][scanner] = {"enabled": True}
                except (json.JSONDecodeError, AttributeError):
                    pass
            except Exception as exc:
                logger.warning("LLM plan enhancement failed", extra={"error": str(exc)})

        logger.info(
            "Scan plan generated",
            extra={
                "scanners": scan_plan.get("scanners"),
                "depth": scan_plan.get("depth"),
            },
        )

        return {
            "stage": PipelineStage.PLAN,
            "scan_plan": scan_plan,
        }

    async def _node_execute(self, state: PentestState) -> dict:
        """Node 3: Execute — run selected scanners in parallel."""
        logger.info("NODE: execute", extra={"url": state.get("target_url")})

        scan_plan = state.get("scan_plan", {})
        target_url = state.get("target_url", "")
        auth_header = state.get("auth_header")
        scan_id = state.get("scan_id")

        async def progress_callback(scanner: str, status: str, progress: int, finding_count: int = 0):
            logger.info(
                "Scanner progress",
                extra={
                    "scan_id": scan_id,
                    "scanner": scanner,
                    "status": status,
                    "progress": progress,
                    "findings": finding_count,
                },
            )
            # Update scan in database if scan_id provided
            if scan_id:
                try:
                    from app.database import SessionLocal
                    from app.models.scan import Scan

                    db = SessionLocal()
                    try:
                        scan = db.query(Scan).filter(Scan.id == scan_id).first()
                        if scan:
                            scan.progress = 20 + int(progress * 0.6)  # Map 0-100 to 20-80%
                            if status == "failed":
                                from app.models.scan import ScanStatus
                                scan.status = ScanStatus.FAILED
                            db.commit()
                    finally:
                        db.close()
                except Exception:
                    pass

        # Execute scanners
        scan_result = await self._scanner_agent.execute_scan_plan(
            target_url=target_url,
            scan_plan=scan_plan,
            auth_header=auth_header,
            scan_id=scan_id,
            progress_callback=progress_callback,
        )

        # Store scanner results in knowledge graph
        for scanner_name, result_summary in scan_result.get("scanner_results", {}).items():
            await knowledge_graph.store_scanner_result(
                scanner_name=scanner_name,
                target_type=state.get("target_type", "web"),
                success="error" not in str(result_summary),
                finding_count=len(scan_result.get("findings", [])),
            )

        logger.info(
            "Scan execution complete",
            extra={
                "findings": len(scan_result.get("findings", [])),
                "scanners": len(scan_result.get("scanner_results", {})),
                "errors": len(scan_result.get("errors", [])),
                "duration": scan_result.get("total_duration"),
            },
        )

        return {
            "stage": PipelineStage.EXECUTE,
            "findings_raw": scan_result.get("findings", []),
            "scanner_results": scan_result.get("scanner_results", {}),
            "scanner_errors": scan_result.get("errors", []),
        }

    async def _node_exploit(self, state: PentestState) -> dict:
        """Node 4: Exploit — verify high/critical findings with PoC exploits."""
        logger.info("NODE: exploit", extra={"url": state.get("target_url")})

        findings = state.get("findings_raw", [])
        target_url = state.get("target_url", "")
        auth_header = state.get("auth_header")

        # Run exploit verification
        verified_findings = await self._exploit_agent.verify_findings(
            target_url=target_url,
            findings=findings,
            auth_header=auth_header,
        )

        # Separate confirmed vs false positives
        confirmed = [f for f in verified_findings if f.get("exploit_verified")]
        false_positives = [f for f in verified_findings if f.get("exploit_attempted") and not f.get("exploit_verified")]
        unverified = [f for f in verified_findings if not f.get("exploit_attempted")]

        # Store exploit results in knowledge graph
        target_hash = knowledge_graph._hash_target(target_url)
        for f in confirmed:
            await knowledge_graph.store_finding(f, target_hash)
            if f.get("exploit_technique"):
                await knowledge_graph.store_exploit_result(
                    finding_id=f.get("id", ""),
                    exploit_successful=True,
                    technique=f.get("exploit_technique", "unknown"),
                )

        # For false positives, also store the negative result
        for f in false_positives:
            await knowledge_graph.store_finding({**f, "status": "false_positive"}, target_hash)

        logger.info(
            "Exploit verification complete",
            extra={
                "confirmed": len(confirmed),
                "false_positives": len(false_positives),
                "unverified": len(unverified),
            },
        )

        return {
            "stage": PipelineStage.EXPLOIT,
            "findings_verified": verified_findings,
            "confirmed_findings": confirmed,
            "false_positive_findings": false_positives,
        }

    async def _node_analyze(self, state: PentestState) -> dict:
        """Node 5: Analyze — correlate, deduplicate, score, and prioritize."""
        logger.info("NODE: analyze", extra={"url": state.get("target_url")})

        # Use verified findings if available, otherwise raw findings
        findings = state.get("findings_verified", state.get("findings_raw", []))

        analysis_result = await self._analyzer_agent.analyze(
            findings=findings,
            target_url=state.get("target_url", ""),
            scan_plan=state.get("scan_plan"),
            scanner_results=state.get("scanner_results"),
        )

        # Store analyzed findings in knowledge graph
        target_hash = knowledge_graph._hash_target(state.get("target_url", ""))
        for f in analysis_result.get("findings", []):
            await knowledge_graph.store_finding(f, target_hash)

        logger.info(
            "Analysis complete",
            extra={
                "final_findings": len(analysis_result.get("findings", [])),
                "critical": analysis_result.get("summary", {}).get("critical", 0),
                "high": analysis_result.get("summary", {}).get("high", 0),
                "medium": analysis_result.get("summary", {}).get("medium", 0),
                "avg_cvss": analysis_result.get("summary", {}).get("avg_cvss", 0),
            },
        )

        return {
            "stage": PipelineStage.ANALYZE,
            "findings_analyzed": analysis_result.get("findings", []),
            "analysis_summary": analysis_result.get("summary", {}),
            "cvss_scores": analysis_result.get("cvss_scores", {}),
            "remediation_priorities": analysis_result.get("remediation_priorities", []),
            "report_data": analysis_result.get("report_data", {}),
        }

    async def _node_report(self, state: PentestState) -> dict:
        """Node 6: Report — finalize report data and mark completion."""
        logger.info("NODE: report", extra={"url": state.get("target_url")})

        report_data = state.get("report_data", {})
        if not report_data:
            # Build report from available data
            analysis = await self._analyzer_agent.analyze(
                findings=state.get("findings_verified", state.get("findings_raw", [])),
                target_url=state.get("target_url", ""),
                scan_plan=state.get("scan_plan"),
                scanner_results=state.get("scanner_results"),
            )
            report_data = analysis.get("report_data", {})

        # Enrich report with metadata
        report_data["pipeline"] = {
            "started_at": state.get("start_time"),
            "completed_at": time.time(),
            "duration_seconds": round(time.time() - (state.get("start_time") or time.time()), 2),
            "scanners_used": state.get("scan_plan", {}).get("scanners", []),
            "errors_encountered": state.get("scanner_errors", []) + state.get("errors", []),
        }

        report_data["metadata"] = {
            "generated_by": "PentestAI Agent System",
            "pipeline_version": "2.0",
            "exploit_verification_enabled": True,
            "knowledge_graph_enabled": True,
        }

        # Update scan in database if scan_id provided
        scan_id = state.get("scan_id")
        if scan_id:
            try:
                from app.database import SessionLocal
                from app.models.scan import Scan, ScanStatus

                db = SessionLocal()
                try:
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.COMPLETED
                        scan.progress = 100
                        scan.completed_at = datetime.utcnow()
                        scan.raw_results = {
                            "summary": state.get("analysis_summary", {}),
                            "findings_count": len(state.get("findings_analyzed", [])),
                            "pipeline": report_data.get("pipeline", {}),
                            "scanner_results": state.get("scanner_results", {}),
                        }
                        db.commit()
                finally:
                    db.close()
            except Exception as exc:
                logger.warning("Failed to update scan record", extra={"error": str(exc)})

        logger.info(
            "Report generation complete",
            extra={
                "total_findings": len(report_data.get("findings", [])),
                "duration": report_data.get("pipeline", {}).get("duration_seconds"),
            },
        )

        return {
            "stage": PipelineStage.COMPLETE,
            "report_data": report_data,
            "end_time": time.time(),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        target_url: str,
        user_id: Optional[str] = None,
        target_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        auth_header: Optional[str] = None,
        target_type: str = "web",
    ) -> dict:
        """Execute the full pentest pipeline.

        Args:
            target_url: URL of the target to test.
            user_id: UUID of the requesting user.
            target_id: UUID of the target record.
            scan_id: UUID of the scan record.
            auth_header: Optional Authorization header value.
            target_type: Type of target ("web", "api", "llm").

        Returns:
            Final state dict containing all pipeline results including
            report_data with findings, summary, and remediation priorities.
        """
        # Initialize knowledge graph
        await knowledge_graph.initialize()

        # Build graph if not already built
        if self._graph is None:
            self._build_graph()

        # Initialize state
        initial_state: PentestState = {
            "target_url": target_url,
            "target_type": target_type,
            "auth_header": auth_header,
            "scan_id": scan_id,
            "user_id": user_id,
            "target_id": target_id,
            "stage": PipelineStage.INIT,
            "errors": [],
            "start_time": time.time(),
            "end_time": None,
            "tech_stack": [],
            "attack_surface": {},
            "endpoints": [],
            "risk_indicators": [],
            "llm_insights": {},
            "scan_plan": {},
            "findings_raw": [],
            "scanner_results": {},
            "scanner_errors": [],
            "findings_verified": [],
            "confirmed_findings": [],
            "false_positive_findings": [],
            "findings_analyzed": [],
            "analysis_summary": {},
            "cvss_scores": {},
            "remediation_priorities": [],
            "report_data": {},
            "knowledge_graph_id": None,
        }

        logger.info(
            "Pipeline execution started",
            extra={
                "target_url": target_url,
                "target_type": target_type,
                "scan_id": scan_id,
            },
        )

        try:
            # Execute the graph
            if self._app:
                final_state = await self._app.ainvoke(initial_state)
            else:
                # Fallback: execute nodes sequentially if LangGraph not available
                final_state = await self._run_sequential(initial_state)

            duration = time.time() - initial_state["start_time"]

            logger.info(
                "Pipeline execution complete",
                extra={
                    "target_url": target_url,
                    "duration_seconds": round(duration, 2),
                    "findings": len(final_state.get("findings_analyzed", [])),
                    "stage": final_state.get("stage", "unknown"),
                },
            )

            return final_state

        except Exception as exc:
            logger.error(
                "Pipeline execution failed",
                extra={
                    "target_url": target_url,
                    "error": str(exc),
                    "stage": initial_state.get("stage", "init"),
                },
            )

            # Return partial results on failure
            initial_state["stage"] = PipelineStage.FAILED
            initial_state["errors"].append(str(exc))
            initial_state["end_time"] = time.time()

            # Build partial report
            if not initial_state.get("report_data"):
                initial_state["report_data"] = {
                    "target": {"url": target_url},
                    "error": str(exc),
                    "partial": True,
                    "pipeline": {
                        "started_at": initial_state.get("start_time"),
                        "completed_at": initial_state.get("end_time"),
                        "failed": True,
                    },
                }

            return initial_state
        finally:
            await knowledge_graph.close()

    async def _run_sequential(self, state: PentestState) -> PentestState:
        """Fallback execution without LangGraph (sequential node calls)."""
        logger.info("Running pipeline in sequential mode (LangGraph unavailable)")

        pipeline = [
            self._node_recon,
            self._node_plan,
            self._node_execute,
            self._node_exploit,
            self._node_analyze,
            self._node_report,
        ]

        current_state = dict(state)

        for i, node_fn in enumerate(pipeline):
            stage_name = type(self)._node_fn_name(node_fn)
            logger.info(f"Sequential node {i+1}/{len(pipeline)}: {stage_name}")

            try:
                updates = await node_fn(current_state)
                current_state.update(updates)
            except Exception as exc:
                logger.error(
                    f"Sequential node {stage_name} failed",
                    extra={"error": str(exc)},
                )
                current_state["errors"].append(f"{stage_name}: {str(exc)}")
                current_state["stage"] = PipelineStage.FAILED
                break

        return current_state  # type: ignore

    @staticmethod
    def _node_fn_name(node_fn) -> str:
        """Get human-readable name from a node function."""
        name = getattr(node_fn, "__name__", str(node_fn))
        return name.replace("_node_", "")
