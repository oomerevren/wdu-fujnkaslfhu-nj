"""PentestAI Agent System — AI-driven penetration testing orchestration.

This package implements a multi-agent system using LangGraph for autonomous
security scanning. The agent pipeline consists of 6 stages:

1. **Recon Agent**: Analyzes target URL to determine tech stack and attack surface.
2. **Plan Agent**: Selects optimal scanner configuration based on recon data.
3. **Scanner Agent**: Executes selected scanners (Nuclei, ZAP, PromptFoo) in parallel.
4. **Exploit Agent**: Attempts to verify high/critical findings with proof-of-concept exploits.
5. **Analyzer Agent**: Correlates findings, removes duplicates, assigns CVSS scores.
6. **Report Agent**: Produces final structured report data.

Usage:
    orchestrator = PentestOrchestrator()
    result = await orchestrator.run(target_url="https://example.com", user_id=...)
"""

from app.agents.orchestrator import PentestOrchestrator, PentestState

__all__ = ["PentestOrchestrator", "PentestState"]
