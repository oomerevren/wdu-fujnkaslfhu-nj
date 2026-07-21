"""Knowledge Graph — Neo4j integration for pentest knowledge persistence.

Each pentest run enriches a shared knowledge graph that agents can query
for context-aware decision making. The graph stores:
- Targets (URLs, tech stacks, domains)
- Findings (vulnerabilities, CVEs, severity)
- Scanner profiles and their effectiveness
- Attack patterns and exploit success rates
"""

import json
import hashlib
from typing import Optional, Any
from datetime import datetime
from uuid import UUID

from app.config import settings
from app.core.logging import logger


class KnowledgeGraph:
    """Neo4j-backed knowledge graph for pentest intelligence.

    Stores and queries relationships between targets, findings, scanners,
    and attack patterns. When Neo4j is unavailable, falls back to an
    in-memory cache to maintain system resilience.
    """

    def __init__(self):
        self._driver = None
        self._use_neo4j = False
        self._memory_store: dict[str, list[dict]] = {
            "targets": [],
            "findings": [],
            "scanner_profiles": [],
            "attack_patterns": [],
        }
        self._initialized = False

    async def initialize(self) -> bool:
        """Attempt to connect to Neo4j; fall back to in-memory if unavailable."""
        if self._initialized:
            return self._use_neo4j

        neo4j_uri = getattr(settings, "NEO4J_URI", None)
        neo4j_user = getattr(settings, "NEO4J_USER", "neo4j")
        neo4j_password = getattr(settings, "NEO4J_PASSWORD", "pentestai")

        if neo4j_uri:
            try:
                from neo4j import GraphDatabase, AsyncGraphDatabase

                self._driver = AsyncGraphDatabase.driver(
                    neo4j_uri,
                    auth=(neo4j_user, neo4j_password),
                    connection_timeout=5,
                )
                # Verify connectivity
                async with self._driver.session() as session:
                    await session.run("RETURN 1")
                self._use_neo4j = True
                logger.info("KnowledgeGraph connected to Neo4j", extra={"uri": neo4j_uri})
            except Exception as exc:
                logger.warning(
                    "Neo4j unavailable, using in-memory fallback",
                    extra={"error": str(exc), "uri": neo4j_uri},
                )
                self._use_neo4j = False
        else:
            logger.info("No NEO4J_URI configured, using in-memory knowledge graph")
            self._use_neo4j = False

        self._initialized = True
        return self._use_neo4j

    async def close(self):
        """Close the Neo4j driver connection."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            self._initialized = False

    # ------------------------------------------------------------------
    # Target operations
    # ------------------------------------------------------------------

    async def store_target(self, target_data: dict) -> str:
        """Store a target node in the graph. Returns the node ID."""
        target_hash = self._hash_target(target_data.get("url", ""))
        target_data["hash"] = target_hash
        target_data["stored_at"] = datetime.utcnow().isoformat()

        if self._use_neo4j:
            return await self._neo4j_store_target(target_data)
        else:
            return self._memory_store_target(target_data)

    async def get_target_history(self, url: str) -> list[dict]:
        """Get historical scan data for a target URL."""
        target_hash = self._hash_target(url)
        if self._use_neo4j:
            return await self._neo4j_get_target_history(target_hash)
        else:
            return self._memory_get_target_history(target_hash)

    async def get_tech_stack_knowledge(self, url: str) -> dict:
        """Get known tech stack information for similar targets."""
        if self._use_neo4j:
            return await self._neo4j_get_tech_stack_knowledge(url)
        else:
            return self._memory_get_tech_stack_knowledge(url)

    # ------------------------------------------------------------------
    # Finding operations
    # ------------------------------------------------------------------

    async def store_finding(self, finding: dict, target_hash: str):
        """Store a finding node and link it to its target."""
        finding_id = hashlib.sha256(
            f"{target_hash}:{finding.get('name', '')}:{finding.get('template_id', '')}".encode()
        ).hexdigest()[:16]
        finding["id"] = finding_id
        finding["stored_at"] = datetime.utcnow().isoformat()

        if self._use_neo4j:
            await self._neo4j_store_finding(finding, target_hash)
        else:
            self._memory_store_finding(finding, target_hash)

    async def get_similar_findings(self, finding: dict) -> list[dict]:
        """Get findings similar to the given one (for FP correlation)."""
        if self._use_neo4j:
            return await self._neo4j_get_similar_findings(finding)
        else:
            return self._memory_get_similar_findings(finding)

    # ------------------------------------------------------------------
    # Scanner profile operations
    # ------------------------------------------------------------------

    async def store_scanner_result(
        self, scanner_name: str, target_type: str, success: bool, finding_count: int
    ):
        """Store scanner effectiveness profile."""
        profile = {
            "scanner": scanner_name,
            "target_type": target_type,
            "success": success,
            "finding_count": finding_count,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if self._use_neo4j:
            await self._neo4j_store_scanner_result(profile)
        else:
            self._memory_store["scanner_profiles"].append(profile)

    async def get_best_scanner_for_target(self, target_type: str) -> Optional[str]:
        """Query which scanner is most effective for a given target type."""
        if self._use_neo4j:
            return await self._neo4j_get_best_scanner(target_type)
        else:
            return self._memory_get_best_scanner(target_type)

    # ------------------------------------------------------------------
    # Attack pattern operations
    # ------------------------------------------------------------------

    async def store_exploit_result(
        self, finding_id: str, exploit_successful: bool, technique: str
    ):
        """Store exploit attempt result for learning."""
        pattern = {
            "finding_id": finding_id,
            "exploit_successful": exploit_successful,
            "technique": technique,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if self._use_neo4j:
            await self._neo4j_store_attack_pattern(pattern)
        else:
            self._memory_store["attack_patterns"].append(pattern)

    async def get_exploit_success_rate(self, technique: str) -> float:
        """Get historical success rate for an exploit technique."""
        if self._use_neo4j:
            return await self._neo4j_get_exploit_success_rate(technique)
        else:
            return self._memory_get_exploit_success_rate(technique)

    # ------------------------------------------------------------------
    # Neo4j implementations
    # ------------------------------------------------------------------

    async def _neo4j_store_target(self, target_data: dict) -> str:
        query = """
        MERGE (t:Target {hash: $hash})
        SET t.url = $url,
            t.tech_stack = $tech_stack,
            t.target_type = $target_type,
            t.last_scanned = $stored_at
        RETURN t.hash as hash
        """
        async with self._driver.session() as session:
            result = await session.run(query, target_data)
            record = await result.single()
            return record["hash"] if record else target_data["hash"]

    async def _neo4j_get_target_history(self, target_hash: str) -> list[dict]:
        query = """
        MATCH (t:Target {hash: $hash})
        OPTIONAL MATCH (t)-[:HAS_FINDING]->(f:Finding)
        RETURN t, collect(f) as findings
        """
        async with self._driver.session() as session:
            result = await session.run(query, {"hash": target_hash})
            records = await result.data()
            return records

    async def _neo4j_get_tech_stack_knowledge(self, url: str) -> dict:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        query = """
        MATCH (t:Target)
        WHERE t.url CONTAINS $domain
        RETURN DISTINCT t.tech_stack
        LIMIT 10
        """
        async with self._driver.session() as session:
            result = await session.run(query, {"domain": domain})
            records = await result.data()
            tech_stacks = [r.get("t", {}).get("tech_stack") for r in records if r.get("t", {}).get("tech_stack")]  # noqa: E501
            return {"tech_stacks": tech_stacks}

    async def _neo4j_store_finding(self, finding: dict, target_hash: str):
        query = """
        MATCH (t:Target {hash: $target_hash})
        MERGE (f:Finding {id: $id})
        SET f.name = $name,
            f.severity = $severity,
            f.cvss_score = $cvss_score,
            f.cve_id = $cve_id,
            f.status = $status,
            f.stored_at = $stored_at
        MERGE (t)-[:HAS_FINDING]->(f)
        """
        async with self._driver.session() as session:
            await session.run(query, {**finding, "target_hash": target_hash})

    async def _neo4j_get_similar_findings(self, finding: dict) -> list[dict]:
        query = """
        MATCH (f:Finding)
        WHERE f.name CONTAINS $name OR f.cve_id = $cve_id
        RETURN f
        LIMIT 20
        """
        async with self._driver.session() as session:
            result = await session.run(
                query,
                {
                    "name": finding.get("name", ""),
                    "cve_id": finding.get("cve_id", ""),
                },
            )
            return await result.data()

    async def _neo4j_store_scanner_result(self, profile: dict):
        query = """
        MERGE (s:ScannerProfile {
            scanner: $scanner,
            target_type: $target_type
        })
        SET s.last_run = $timestamp,
            s.success_count = COALESCE(s.success_count, 0) + CASE WHEN $success THEN 1 ELSE 0 END,
            s.total_runs = COALESCE(s.total_runs, 0) + 1,
            s.total_findings = COALESCE(s.total_findings, 0) + $finding_count
        """
        async with self._driver.session() as session:
            await session.run(query, profile)

    async def _neo4j_get_best_scanner(self, target_type: str) -> Optional[str]:
        query = """
        MATCH (s:ScannerProfile {target_type: $target_type})
        WHERE s.total_runs > 0
        RETURN s.scanner as scanner,
               (s.success_count * 1.0 / s.total_runs) as success_rate,
               s.total_findings as findings
        ORDER BY success_rate DESC, findings DESC
        LIMIT 1
        """
        async with self._driver.session() as session:
            result = await session.run(query, {"target_type": target_type})
            record = await result.single()
            return record["scanner"] if record else None

    async def _neo4j_store_attack_pattern(self, pattern: dict):
        query = """
        MERGE (a:AttackPattern {technique: $technique})
        SET a.last_used = $timestamp,
            a.success_count = COALESCE(a.success_count, 0) + CASE WHEN $exploit_successful THEN 1 ELSE 0 END,
            a.total_attempts = COALESCE(a.total_attempts, 0) + 1
        """
        async with self._driver.session() as session:
            await session.run(query, pattern)

    async def _neo4j_get_exploit_success_rate(self, technique: str) -> float:
        query = """
        MATCH (a:AttackPattern {technique: $technique})
        WHERE a.total_attempts > 0
        RETURN a.success_count * 1.0 / a.total_attempts as rate
        """
        async with self._driver.session() as session:
            result = await session.run(query, {"technique": technique})
            record = await result.single()
            return record["rate"] if record else 0.0

    # ------------------------------------------------------------------
    # In-memory fallback implementations
    # ------------------------------------------------------------------

    def _memory_store_target(self, target_data: dict) -> str:
        # Remove existing entry for same hash if present
        self._memory_store["targets"] = [
            t for t in self._memory_store["targets"]
            if t.get("hash") != target_data.get("hash")
        ]
        self._memory_store["targets"].append(target_data)
        return target_data.get("hash", "")

    def _memory_get_target_history(self, target_hash: str) -> list[dict]:
        return [
            t for t in self._memory_store["targets"]
            if t.get("hash") == target_hash
        ]

    def _memory_get_tech_stack_knowledge(self, url: str) -> dict:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        tech_stacks = []
        for t in self._memory_store["targets"]:
            if domain in t.get("url", ""):
                ts = t.get("tech_stack")
                if ts:
                    tech_stacks.append(ts)
        return {"tech_stacks": tech_stacks[-10:]}

    def _memory_store_finding(self, finding: dict, target_hash: str):
        finding["target_hash"] = target_hash
        self._memory_store["findings"].append(finding)

    def _memory_get_similar_findings(self, finding: dict) -> list[dict]:
        name = (finding.get("name") or "").lower()
        cve = finding.get("cve_id") or ""
        results = []
        for f in self._memory_store["findings"]:
            f_name = (f.get("name") or "").lower()
            if name and (name in f_name or f_name in name):
                results.append(f)
            elif cve and f.get("cve_id") == cve:
                results.append(f)
        return results[:20]

    def _memory_get_best_scanner(self, target_type: str) -> Optional[str]:
        profiles = [
            p for p in self._memory_store["scanner_profiles"]
            if p["target_type"] == target_type
        ]
        if not profiles:
            return None
        # Simple heuristic: most recent successful scanner
        successful = [p for p in profiles if p["success"]]
        if successful:
            return max(successful, key=lambda p: (p["finding_count"], p["timestamp"]))["scanner"]
        return profiles[-1]["scanner"]

    def _memory_get_exploit_success_rate(self, technique: str) -> float:
        patterns = [
            p for p in self._memory_store["attack_patterns"]
            if p["technique"] == technique
        ]
        if not patterns:
            return 0.0
        successful = sum(1 for p in patterns if p["exploit_successful"])
        return successful / len(patterns)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_target(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]


# Singleton instance
knowledge_graph = KnowledgeGraph()
