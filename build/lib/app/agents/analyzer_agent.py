"""Analysis Agent — Correlates, scores, and prioritizes findings.

This agent takes raw findings from all scanners, plus exploit verification
results, and produces the final structured output:
1. Cross-scanner correlation (deduplication)
2. CVSS score assignment using LLM reasoning
3. Remediation priority ranking
4. Final report data structure
"""

import json
import re
import hashlib
from typing import Optional
from datetime import datetime

from app.core.logging import logger


class AnalyzerAgent:
    """Correlates findings across scanners, removes duplicates, assigns CVSS scores.

    Analysis pipeline:
    1. Normalize: Convert all findings to a canonical format
    2. Deduplicate: Remove duplicate findings across scanners
    3. Correlate: Group related findings (same CVE, same vuln type)
    4. Score: Assign CVSS v3.1 scores using LLM reasoning
    5. Prioritize: Rank findings by severity, exploitability, impact
    6. Report: Build final report data structure
    """

    # CVSS v3.1 severity ranges
    CVSS_RANGES = {
        "critical": (9.0, 10.0),
        "high": (7.0, 8.9),
        "medium": (4.0, 6.9),
        "low": (0.1, 3.9),
        "info": (0.0, 0.0),
    }

    # Duplicate detection similarity threshold
    SIMILARITY_THRESHOLD = 0.75

    def __init__(self, llm_client=None):
        self._llm = llm_client

    async def analyze(
        self,
        findings: list[dict],
        target_url: str,
        scan_plan: dict = None,
        scanner_results: dict = None,
    ) -> dict:
        """Full analysis pipeline.

        Args:
            findings: List of finding dicts (raw from scanners + exploited).
            target_url: The target URL.
            scan_plan: The original scan plan for context.
            scanner_results: Per-scanner execution results.

        Returns:
            Dict with keys:
                - findings: Deduplicated, scored finding list
                - summary: Aggregated summary statistics
                - cvss_scores: Per-finding CVSS assignments
                - remediation_priorities: Ordered list of what to fix first
                - report_data: Structured data ready for report generation
        """
        logger.info(
            "AnalyzerAgent analyzing findings",
            extra={"target_url": target_url, "input_count": len(findings)},
        )

        # Step 1: Normalize all findings
        normalized = self._normalize_findings(findings)

        # Step 2: Deduplicate
        deduplicated = self._deduplicate(normalized)

        # Step 3: Correlate related findings
        correlated = self._correlate_findings(deduplicated)

        # Step 4: Assign CVSS scores
        scored = await self._assign_cvss_scores(correlated, target_url)

        # Step 5: Extract remediation priorities
        remediation = self._generate_remediation_priorities(scored)

        # Step 6: Build summary
        summary = self._build_summary(scored, scanner_results)

        # Step 7: Build report data
        report_data = self._build_report_data(scored, summary, target_url, scan_plan)

        logger.info(
            "AnalyzerAgent analysis complete",
            extra={
                "input": len(findings),
                "after_dedup": len(deduplicated),
                "after_correlation": len(correlated),
                "final": len(scored),
                "critical": summary.get("critical", 0),
                "high": summary.get("high", 0),
                "medium": summary.get("medium", 0),
                "low": summary.get("low", 0),
                "false_positives": summary.get("false_positives", 0),
            },
        )

        return {
            "findings": scored,
            "summary": summary,
            "cvss_scores": {f.get("id", str(i)): f.get("cvss_score") for i, f in enumerate(scored)},
            "remediation_priorities": remediation,
            "report_data": report_data,
        }

    def _normalize_findings(self, findings: list[dict]) -> list[dict]:
        """Normalize all findings to a canonical format."""
        normalized = []
        for i, finding in enumerate(findings):
            norm = {
                "id": finding.get("id") or hashlib.md5(
                    f"{finding.get('source_scanner', 'unknown')}:{finding.get('name', '')}:{finding.get('template_id', '')}".encode()
                ).hexdigest()[:12],
                "source_scanner": finding.get("source_scanner", finding.get("source", "unknown")),
                "source": finding.get("source", finding.get("source_scanner", "unknown")),
                "template_id": finding.get("template_id"),
                "name": (finding.get("name") or "Unknown finding").strip(),
                "severity": (finding.get("severity") or "info").lower(),
                "description": (finding.get("description") or "").strip(),
                "remediation": (finding.get("remediation") or "").strip(),
                "evidence": finding.get("evidence", {}),
                "cvss_score": finding.get("cvss_score"),
                "cve_id": finding.get("cve_id"),
                "status": finding.get("status", "open"),
                "exploit_attempted": finding.get("exploit_attempted", False),
                "exploit_verified": finding.get("exploit_verified", False),
                "exploit_payload": finding.get("exploit_payload"),
                "exploit_evidence": finding.get("exploit_evidence"),
                "exploit_technique": finding.get("exploit_technique"),
                "exploit_note": finding.get("exploit_note"),
                "normalized_at": datetime.utcnow().isoformat(),
            }
            normalized.append(norm)
        return normalized

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings using multi-key fingerprinting."""
        # Stage 1: Exact dedup by CVE ID
        cve_groups: dict[str, list[dict]] = {}
        non_cve_findings = []

        for f in findings:
            cve = f.get("cve_id")
            if cve:
                cve_groups.setdefault(cve, []).append(f)
            else:
                non_cve_findings.append(f)

        deduped = []
        for cve, group in cve_groups.items():
            # Keep the most severe, most verified finding for each CVE
            best = max(
                group,
                key=lambda f: (
                    1 if f.get("exploit_verified") else 0,
                    self._severity_score(f.get("severity", "info")),
                    len(str(f.get("evidence", {}))),
                ),
            )
            deduped.append(best)

        # Stage 2: Fuzzy dedup by name similarity
        seen_signatures: set[str] = set()
        for f in non_cve_findings:
            # Create a signature from name + template_id
            sig_source = (f.get("name", "") + "|" + (f.get("template_id") or "")).lower()
            sig_source = re.sub(r"\s+", " ", sig_source)

            # Also create a signature from just the name stem
            name_stem = re.sub(r"[-_\s]+", " ", f.get("name", "")).lower().strip()[:60]

            if sig_source in seen_signatures or name_stem in seen_signatures:
                continue

            seen_signatures.add(sig_source)
            seen_signatures.add(name_stem)
            deduped.append(f)

        # Also check for cross-scanner duplicates by comparing names
        final_deduped = []
        final_signatures: set[str] = set()

        for f in deduped:
            # Generate a fuzzy signature
            name = f.get("name", "").lower().strip()
            # Remove common prefixes like "Nuclei:", "ZAP:", etc.
            name_clean = re.sub(r"^(nuclei|zap|promptfoo)\s*[:\-]\s*", "", name)
            # Take first 80 chars as signature
            sig = name_clean[:80]

            if sig in final_signatures:
                continue
            final_signatures.add(sig)
            final_deduped.append(f)

        logger.info(
            "Deduplication complete",
            extra={"input": len(findings), "output": len(final_deduped)},
        )

        return final_deduped

    def _correlate_findings(self, findings: list[dict]) -> list[dict]:
        """Correlate related findings (same vuln class, same endpoint)."""
        correlated = []

        for finding in findings:
            # Check if this finding relates to a previously seen endpoint
            evidence = finding.get("evidence", {})
            matched_url = ""
            if isinstance(evidence, dict):
                matched_url = str(evidence.get("matched_at") or evidence.get("url") or "")

            # Add correlation metadata
            finding["correlation"] = {
                "related_findings": [],
                "vuln_class": self._classify_vulnerability(finding),
                "endpoint": matched_url,
            }

            correlated.append(finding)

        # Group findings by endpoint and vulnerability class
        groups: dict[str, list[dict]] = {}
        for f in correlated:
            endpoint = f.get("correlation", {}).get("endpoint", "")
            vuln_class = f.get("correlation", {}).get("vuln_class", "")
            group_key = f"{endpoint}::{vuln_class}"
            groups.setdefault(group_key, []).append(f)

        # Mark related findings within each group
        for group_key, group in groups.items():
            if len(group) > 1:
                ids = [f.get("id", "") for f in group]
                for f in group:
                    f["correlation"]["related_findings"] = [i for i in ids if i != f.get("id", "")]

        return correlated

    async def _assign_cvss_scores(
        self, findings: list[dict], target_url: str
    ) -> list[dict]:
        """Assign CVSS v3.1 scores using LLM reasoning when available.

        Falls back to severity-based estimation when LLM is unavailable.
        """
        if self._llm:
            # Use LLM for precise CVSS scoring
            for finding in findings:
                score = await self._llm_cvss_score(finding, target_url)
                if score is not None:
                    finding["cvss_score"] = round(score, 1)
                    finding["cvss_vector"] = self._cvss_score_to_vector(score)
                    finding["cvss_source"] = "llm"
                else:
                    fallback = self._estimate_cvss(finding.get("severity", "info"))
                    finding["cvss_score"] = fallback
                    finding["cvss_vector"] = self._cvss_score_to_vector(fallback)
                    finding["cvss_source"] = "severity_fallback"
        else:
            # Fallback: estimate from severity
            for finding in findings:
                score = self._estimate_cvss(finding.get("severity", "info"))
                # Adjust based on exploitability evidence
                if finding.get("exploit_verified"):
                    score = min(10.0, score + 1.0)
                if finding.get("exploit_attempted") and not finding.get("exploit_verified"):
                    score = max(0.0, score - 1.5)
                finding["cvss_score"] = round(score, 1)
                finding["cvss_vector"] = self._cvss_score_to_vector(score)
                finding["cvss_source"] = "estimated"

        return findings

    async def _llm_cvss_score(self, finding: dict, target_url: str) -> Optional[float]:
        """Use LLM to compute a precise CVSS v3.1 score."""
        if not self._llm:
            return None

        try:
            prompt = f"""You are a CVSS v3.1 scoring specialist. Score the following security finding:

Target URL: {target_url}
Finding Name: {finding.get('name', 'Unknown')}
Description: {finding.get('description', 'No description')}
Severity (original): {finding.get('severity', 'info')}
CVE ID: {finding.get('cve_id', 'None')}
Exploit Verified: {finding.get('exploit_verified', False)}
Exploit Technique: {finding.get('exploit_technique', 'N/A')}

Consider:
1. Attack Vector (AV): Network/Adjacent/Local/Physical
2. Attack Complexity (AC): Low/High
3. Privileges Required (PR): None/Low/High
4. User Interaction (UI): None/Required
5. Scope (S): Unchanged/Changed
6. Confidentiality (C): None/Low/High
7. Integrity (I): None/Low/High
8. Availability (A): None/Low/High

Respond with ONLY a single number between 0.0 and 10.0 representing the CVSS v3.1 base score.
Do not include any other text."""

            response = await self._llm.ainvoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)

            # Extract the number
            numbers = re.findall(r"(\d+\.?\d*)", content)
            for num in numbers:
                val = float(num)
                if 0.0 <= val <= 10.0:
                    return val

        except Exception as exc:
            logger.warning("LLM CVSS scoring failed", extra={"error": str(exc)})

        return None

    def _estimate_cvss(self, severity: str) -> float:
        """Estimate CVSS score from severity level."""
        estimates = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 2.5,
            "info": 0.0,
        }
        return estimates.get(severity.lower(), 5.0)

    def _cvss_score_to_vector(self, score: float) -> str:
        """Convert a numeric CVSS score to an approximate vector string."""
        if score >= 9.0:
            return f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Score: {score})"
        elif score >= 7.0:
            return f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L (Score: {score})"
        elif score >= 4.0:
            return f"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L (Score: {score})"
        elif score >= 0.1:
            return f"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (Score: {score})"
        else:
            return f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (Score: {score})"

    def _generate_remediation_priorities(self, findings: list[dict]) -> list[dict]:
        """Generate ordered remediation priority list."""
        scored_findings = []
        for f in findings:
            if f.get("status") == "false_positive":
                continue

            cvss = f.get("cvss_score") or self._estimate_cvss(f.get("severity", "info"))
            exploitability_bonus = 1.0 if f.get("exploit_verified") else 0.0
            priority_score = cvss + exploitability_bonus

            scored_findings.append({
                "id": f.get("id", ""),
                "name": f.get("name", "Unknown"),
                "severity": f.get("severity", "info"),
                "cvss_score": cvss,
                "priority_score": round(priority_score, 1),
                "exploit_verified": f.get("exploit_verified", False),
                "remediation": f.get("remediation", "No remediation provided."),
                "cve_id": f.get("cve_id"),
            })

        # Sort by priority score descending
        scored_findings.sort(key=lambda x: x["priority_score"], reverse=True)

        return scored_findings

    def _build_summary(self, findings: list[dict], scanner_results: dict = None) -> dict:
        """Build aggregated summary statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        status_counts = {}
        scanner_source_counts = {}
        total_cvss = 0.0
        cvss_count = 0

        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

            status = f.get("status", "open")
            status_counts[status] = status_counts.get(status, 0) + 1

            source = f.get("source_scanner", f.get("source", "unknown"))
            scanner_source_counts[source] = scanner_source_counts.get(source, 0) + 1

            cs = f.get("cvss_score")
            if cs is not None:
                total_cvss += cs
                cvss_count += 1

        avg_cvss = round(total_cvss / cvss_count, 1) if cvss_count > 0 else 0.0

        # Calculate exploit stats
        exploit_attempted = sum(1 for f in findings if f.get("exploit_attempted"))
        exploit_confirmed = sum(1 for f in findings if f.get("exploit_verified"))

        summary = {
            **severity_counts,
            "total": len(findings),
            "false_positives": status_counts.get("false_positive", 0),
            "open": status_counts.get("open", 0),
            "acknowledged": status_counts.get("acknowledged", 0),
            "fixed": status_counts.get("fixed", 0),
            "avg_cvss": avg_cvss,
            "scanner_breakdown": scanner_source_counts,
            "exploit_attempted": exploit_attempted,
            "exploit_confirmed": exploit_confirmed,
            "scanner_results": scanner_results or {},
        }

        return summary

    def _build_report_data(
        self,
        findings: list[dict],
        summary: dict,
        target_url: str,
        scan_plan: dict = None,
    ) -> dict:
        """Build structured data ready for report generation."""
        return {
            "target": {
                "url": target_url,
                "scanned_at": datetime.utcnow().isoformat(),
            },
            "summary": summary,
            "findings": [
                {
                    "id": f.get("id"),
                    "name": f.get("name"),
                    "severity": f.get("severity"),
                    "cvss_score": f.get("cvss_score"),
                    "cvss_vector": f.get("cvss_vector"),
                    "cve_id": f.get("cve_id"),
                    "description": f.get("description"),
                    "remediation": f.get("remediation"),
                    "evidence": f.get("evidence"),
                    "status": f.get("status"),
                    "exploit_verified": f.get("exploit_verified", False),
                    "exploit_payload": f.get("exploit_payload"),
                    "exploit_evidence": f.get("exploit_evidence"),
                    "source": f.get("source_scanner", f.get("source")),
                    "template_id": f.get("template_id"),
                    "correlation": f.get("correlation"),
                }
                for f in findings
            ],
            "remediation_priorities": self._generate_remediation_priorities(findings),
            "scan_configuration": scan_plan or {},
        }

    def _classify_vulnerability(self, finding: dict) -> str:
        """Classify a finding's vulnerability type."""
        name = (finding.get("name") or "").lower()
        description = (finding.get("description") or "").lower()
        template_id = (finding.get("template_id") or "").lower()
        combined = f"{name} {description} {template_id}"

        classifications = {
            "xss": r"cross.?site.?script|xss|script.*inject",
            "sqli": r"sql.*inject|sqli|sql.*error",
            "lfi": r"local.*file.*includ|lfi|path.*traversal|directory.*traversal",
            "rce": r"remote.*code.*exec|rce|command.*inject|os.*command",
            "idor": r"idor|insecure.*direct.*object|auth.*bypass",
            "open_redirect": r"open.*redirect|url.*redirect",
            "ssrf": r"ssrf|server.*side.*request.*forg",
            "ssti": r"template.*inject|ssti|jinja|twig",
            "information_disclosure": r"information.*disclos|path.*disclos|debug.*enabl|directory.*list",
            "misconfiguration": r"misconfig|security.*misconfig|cors|hsts|csp|clickjack",
            "exposure": r"exposure|sensitive.*data|credentials|api.*key|token.*expos",
            "authentication": r"auth.*bypass|weak.*password|brute.*force|rate.*limit|session.*fix",
        }

        for vuln_type, pattern in classifications.items():
            if re.search(pattern, combined, re.IGNORECASE):
                return vuln_type

        return "general"

    @staticmethod
    def _severity_score(severity: str) -> int:
        """Convert severity string to numeric score for sorting."""
        scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return scores.get(severity.lower(), 0)
