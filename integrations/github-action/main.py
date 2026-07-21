"""PentestAI GitHub Action — main entry point.

Reads environment variables, creates a target & scan via the PentestAI SDK,
waits for completion, posts findings as PR comments, sets action outputs,
and fails the build if the severity threshold is exceeded.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, NoReturn

import httpx

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "none"]
SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}


def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def fail(msg: str) -> NoReturn:
    log(msg, "ERROR")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"PENTESTAI_ERROR={msg}\n")
    sys.exit(1)


def get_env(name: str, required: bool = True, default: str | None = None) -> str:
    val = os.environ.get(name)
    if val is not None and val.strip():
        return val.strip()
    if default is not None:
        return default
    if required:
        fail(f"Missing required environment variable: {name}")
    return ""


def set_output(name: str, value: str | int) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"{name}={value}\n")


def set_summary(markdown: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    with open(os.environ.get("GITHUB_STEP_SUMMARY", "/dev/null"), "a") as f:
        f.write(markdown + "\n")


def get_pr_context() -> dict[str, Any] | None:
    """Extract PR context from GitHub event payload if this is a PR event."""
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.isfile(event_path):
        return None
    try:
        with open(event_path) as f:
            event = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    pr = event.get("pull_request") or event.get("issue", {}).get("pull_request")
    if not pr:
        return None

    return {
        "owner": os.environ.get("GITHUB_REPOSITORY", "").split("/")[0],
        "repo": os.environ.get("GITHUB_REPOSITORY", "").split("/")[1] if "/" in os.environ.get("GITHUB_REPOSITORY", "") else "",
        "pr_number": pr.get("number"),
        "sha": os.environ.get("GITHUB_SHA", ""),
    }


def post_pr_comment(token: str, owner: str, repo: str, pr_number: int, body: str) -> bool:
    """Post a comment on a pull request using the GitHub API."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "pentestai-action",
    }
    try:
        resp = httpx.post(url, headers=headers, json={"body": body}, timeout=30)
        resp.raise_for_status()
        log(f"PR comment posted to #{pr_number}")
        return True
    except Exception as exc:
        log(f"Failed to post PR comment: {exc}", "WARN")
        return False


def severity_score(name: str) -> int:
    return SEVERITY_WEIGHTS.get(name.lower(), -1)


def should_fail(fail_on: str, findings: list[dict[str, Any]]) -> bool:
    threshold = severity_score(fail_on)
    if threshold < 0:
        return False
    for f in findings:
        if severity_score(f.get("severity", "info")) >= threshold:
            return True
    return False


def build_findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "_No findings discovered._"
    rows = ["| Severity | Name | Source |", "|----------|------|--------|"]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings, key=lambda f: sev_order.get(f.get("severity", "info"), 99)
    )
    for f in sorted_findings:
        sev = f.get("severity", "info").upper()
        name = f.get("name", "Unknown")
        source = f.get("source", "-")
        rows.append(f"| **{sev}** | {name} | {source} |")
    return "\n".join(rows)


def main() -> None:
    log("PentestAI Security Scan — Starting")

    # ── Read configuration ──────────────────────────────────────────────────
    api_key = get_env("PENTESTAI_API_KEY")
    target_url = get_env("PENTESTAI_TARGET_URL")
    scan_type = get_env("PENTESTAI_SCAN_TYPE", default="ai")
    fail_on = get_env("PENTESTAI_FAIL_ON", default="high").lower()
    wait_str = get_env("PENTESTAI_WAIT", default="true").lower()
    github_token = get_env("GITHUB_TOKEN", required=False, default="")

    wait = wait_str in ("true", "1", "yes")

    valid_scan_types = {"nuclei", "zap", "promptfoo", "full", "ai"}
    if scan_type not in valid_scan_types:
        fail(f"Invalid scan-type '{scan_type}'. Must be one of: {', '.join(sorted(valid_scan_types))}")

    valid_fail_on = {"critical", "high", "medium", "low", "none"}
    if fail_on not in valid_fail_on:
        fail(f"Invalid fail-on '{fail_on}'. Must be one of: {', '.join(sorted(valid_fail_on))}")

    pr_context = get_pr_context() if github_token else None

    log(f"Target:     {target_url}")
    log(f"Scan type:  {scan_type}")
    log(f"Fail on:    {fail_on}")
    log(f"Wait:       {wait}")
    log(f"PR context: {'yes' if pr_context else 'no'}")

    # ── API base URL ────────────────────────────────────────────────────────
    base_url = os.environ.get("PENTESTAI_BASE_URL", "https://api.pentestai.com")

    # ── Phase 1: Create target ──────────────────────────────────────────────
    log("Creating target...")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "pentestai-github-action/1.0",
    }

    try:
        with httpx.Client(base_url=base_url, headers=headers, timeout=30) as client:
            resp = client.post("/api/v1/targets/", json={"url": target_url, "target_type": "web"})
            if resp.status_code == 401:
                fail("Authentication failed. Check your PENTESTAI_API_KEY.")
            resp.raise_for_status()
            target = resp.json()
            target_id = str(target["id"])
            log(f"Target created: {target_id}")
    except httpx.RequestError as exc:
        fail(f"Cannot reach PentestAI API at {base_url}: {exc}")

    # ── Phase 2: Create scan ────────────────────────────────────────────────
    log(f"Creating {scan_type} scan...")
    try:
        with httpx.Client(base_url=base_url, headers=headers, timeout=30) as client:
            scan_body: dict[str, Any] = {
                "target_id": target_id,
                "scan_type": scan_type,
            }
            resp = client.post("/api/v1/scans/", json=scan_body)
            resp.raise_for_status()
            scan_data = resp.json()
            scan_ids: list[str] = []
            if isinstance(scan_data, list):
                scan_ids = [str(s["id"]) for s in scan_data]
            else:
                scan_ids = [str(scan_data["id"])]
            log(f"Scan(s) created: {', '.join(scan_ids)}")
    except httpx.RequestError as exc:
        fail(f"Failed to create scan: {exc}")

    set_output("scan-id", scan_ids[0] if scan_ids else "")

    # ── Phase 3: Wait for completion (optional) ─────────────────────────────
    all_findings: list[dict[str, Any]] = []
    if wait and scan_ids:
        log("Waiting for scan completion...")
        for sid in scan_ids:
            try:
                with httpx.Client(base_url=base_url, headers=headers, timeout=30) as client:
                    while True:
                        resp = client.get(f"/api/v1/scans/{sid}/progress")
                        resp.raise_for_status()
                        progress = resp.json()
                        status = progress.get("status", "unknown")
                        pct = progress.get("progress", 0)
                        print(f"  [{sid[:8]}] {status} ({pct}%)", flush=True)

                        if status in ("completed", "failed"):
                            if status == "completed":
                                log(f"Scan {sid[:8]} completed successfully")
                            else:
                                err = progress.get("error_message", "Unknown error")
                                log(f"Scan {sid[:8]} failed: {err}", "WARN")
                            break

                        time.sleep(5)
            except httpx.RequestError as exc:
                log(f"Error polling scan {sid}: {exc}", "WARN")
                continue

        # ── Phase 4: Fetch findings ─────────────────────────────────────────
        log("Fetching findings...")
        try:
            with httpx.Client(base_url=base_url, headers=headers, timeout=30) as client:
                resp = client.get(
                    "/api/v1/findings/",
                    params={"target_id": target_id, "size": 500},
                )
                resp.raise_for_status()
                findings_page = resp.json()
                all_findings = findings_page.get("items", [])
        except httpx.RequestError as exc:
            log(f"Failed to fetch findings: {exc}", "WARN")
    else:
        log("Skipping wait for completion (wait-for-completion is false)")

    # ── Phase 5: Compute outputs ────────────────────────────────────────────
    total = len(all_findings)
    critical_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "critical")
    high_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "high")
    medium_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "medium")
    low_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "low")

    # Rough security score (0-100)
    max_score = 100
    deductions = critical_count * 15 + high_count * 8 + medium_count * 4 + low_count * 1
    score = max(0, min(100, max_score - deductions))

    set_output("findings-count", total)
    set_output("critical-count", critical_count)
    set_output("score", score)

    log(f"Findings: {total} total ({critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low)")
    log(f"Security score: {score}/100")

    # ── Phase 6: Post PR comment ────────────────────────────────────────────
    if pr_context and (total > 0 or fail_on != "none"):
        summary_parts = [
            f"## PentestAI Security Scan Results",
            f"",
            f"**Target:** `{target_url}`  ",
            f"**Scan Type:** `{scan_type}`  ",
            f"**Security Score:** `{score}/100`  ",
            f"",
            f"### Summary",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {critical_count} |",
            f"| 🟠 High | {high_count} |",
            f"| 🟡 Medium | {medium_count} |",
            f"| 🔵 Low | {low_count} |",
            f"",
            f"### Findings",
            f"{build_findings_table(all_findings)}",
            f"",
            f"---",
            f"_Scan ID: {scan_ids[0] if scan_ids else 'N/A'}_",
        ]
        body = "\n".join(summary_parts)
        post_pr_comment(
            token=github_token,
            owner=pr_context["owner"],
            repo=pr_context["repo"],
            pr_number=pr_context["pr_number"],
            body=body,
        )

    # ── Phase 7: Build summary (GHA step summary) ───────────────────────────
    summary_lines = [
        f"# PentestAI Security Scan",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Target | `{target_url}` |",
        f"| Scan Type | `{scan_type}` |",
        f"| Scan ID | `{scan_ids[0] if scan_ids else 'N/A'}` |",
        f"| Total Findings | {total} |",
        f"| Critical | {critical_count} |",
        f"| High | {high_count} |",
        f"| Medium | {medium_count} |",
        f"| Low | {low_count} |",
        f"| Security Score | {score}/100 |",
        f"",
    ]
    if all_findings:
        summary_lines.append("### Findings\n")
        summary_lines.append(build_findings_table(all_findings))
    set_summary("\n".join(summary_lines))

    # ── Phase 8: Fail check ─────────────────────────────────────────────────
    if fail_on != "none" and should_fail(fail_on, all_findings):
        log(
            f"Build failed: found findings at or above '{fail_on}' severity threshold",
            "ERROR",
        )
        sys.exit(1)

    log("PentestAI Security Scan — Completed successfully")


if __name__ == "__main__":
    main()
