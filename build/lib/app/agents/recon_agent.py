"""Reconnaissance Agent — Target analysis and scan planning.

This agent analyzes a target URL to determine:
- Technology stack (web server, frameworks, CMS, JS libraries)
- Attack surface (endpoints, forms, authentication)
- Optimal scanner configuration
- Recommended scan depth and scope
"""

import re
import json
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.core.logging import logger


class ReconAgent:
    """Analyzes a target URL and produces a scan plan.

    Uses multiple techniques:
    1. HTTP response analysis (headers, body patterns)
    2. Technology fingerprinting via known patterns
    3. Endpoint discovery via common paths
    4. LLM-based reasoning for advanced context analysis
    """

    # Technology fingerprint signatures
    TECH_SIGNATURES: dict[str, list[dict]] = {
        "nginx": [
            {"header": "server", "pattern": r"nginx"},
        ],
        "apache": [
            {"header": "server", "pattern": r"apache", "flags": re.IGNORECASE},
        ],
        "cloudflare": [
            {"header": "server", "pattern": r"cloudflare"},
            {"header": "cf-ray", "pattern": r"."},
        ],
        "python-django": [
            {"header": "server", "pattern": r"WSGIServer|gunicorn"},
            {"cookie": "csrftoken", "pattern": r"."},
        ],
        "python-flask": [
            {"header": "server", "pattern": r"Werkzeug"},
            {"cookie": "session", "pattern": r"\."},
        ],
        "node-express": [
            {"header": "x-powered-by", "pattern": r"Express"},
        ],
        "php": [
            {"header": "x-powered-by", "pattern": r"PHP"},
            {"cookie": "PHPSESSID", "pattern": r"."},
        ],
        "wordpress": [
            {"header": "x-powered-by", "pattern": r"WordPress"},
            {"body": "wp-content", "pattern": r"."},
            {"body": "wp-includes", "pattern": r"."},
        ],
        "laravel": [
            {"cookie": "laravel_session", "pattern": r"."},
            {"header": "x-powered-by", "pattern": r"Laravel"},
        ],
        "ruby-rails": [
            {"header": "server", "pattern": r"Phusion|Passenger|puma"},
            {"cookie": "_session_id", "pattern": r"."},
        ],
        "java-spring": [
            {"header": "x-application-context", "pattern": r"."},
            {"cookie": "JSESSIONID", "pattern": r"."},
        },
        "aspnet": [
            {"header": "x-powered-by", "pattern": r"ASP\.NET"},
            {"cookie": "ASP.NET", "pattern": r"."},
            {"header": "x-aspnet-version", "pattern": r"."},
        ],
        "shutterstock-akamai": [
            {"header": "server", "pattern": r"Akamai"},
        ],
        "amazon-aws": [
            {"header": "server", "pattern": r"AmazonS3|CloudFront"},
            {"header": "x-amz-", "pattern": r"."},
        ],
        "google-cloud": [
            {"header": "via", "pattern": r"google"},
            {"header": "server", "pattern": r"Google"},
        ],
        "graphql": [
            {"body": "graphql", "pattern": r"."},
            {"path": "/graphql", "pattern": r""},
            {"path": "/gql", "pattern": r""},
        ],
        "swagger": [
            {"path": "/api/docs", "pattern": r""},
            {"path": "/swagger", "pattern": r""},
            {"path": "/openapi", "pattern": r""},
            {"body": "swagger", "pattern": r"."},
        ],
    }

    # Common discovery endpoints
    DISCOVERY_PATHS = [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/.env",
        "/.git/config",
        "/admin",
        "/api",
        "/api/v1",
        "/graphql",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/api/docs",
        "/health",
        "/healthcheck",
        "/.htaccess",
        "/wp-admin",
        "/wp-content",
        "/login",
        "/register",
        "/reset-password",
        "/api/health",
        "/version",
        "/.env.example",
    ]

    def __init__(self, llm_client=None):
        self._llm = llm_client
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                verify=False,  # Allow self-signed certs in pentests
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/json,*/*",
                },
            )
        return self._http_client

    async def analyze(self, url: str, auth_header: Optional[str] = None) -> dict:
        """Analyze a target URL and produce a comprehensive scan plan.

        Args:
            url: Target URL to analyze.
            auth_header: Optional Authorization header value.

        Returns:
            Dict with keys:
                - url: The target URL
                - parsed_url: Parsed URL components
                - tech_stack: Detected technologies
                - attack_surface: Discovered endpoints and features
                - scan_plan: Recommended scanner configuration
                - risk_indicators: Notable security-relevant observations
        """
        logger.info("ReconAgent analyzing target", extra={"url": url})

        client = await self._get_client()

        # Step 1: Fetch target homepage and analyze response
        response_data = await self._fetch_target(client, url, auth_header)

        # Step 2: Fingerprint technology stack
        tech_stack = self._fingerprint_tech(response_data)

        # Step 3: Discover endpoints
        endpoints = await self._discover_endpoints(client, url, auth_header)

        # Step 4: Build attack surface summary
        attack_surface = self._build_attack_surface(response_data, endpoints)

        # Step 5: Identify risk indicators
        risk_indicators = self._identify_risks(response_data, tech_stack)

        # Step 6: Generate scan plan
        scan_plan = self._generate_scan_plan(url, tech_stack, attack_surface, risk_indicators)

        # Step 7: Use LLM for advanced analysis if available
        llm_insights = await self._llm_analysis(url, tech_stack, attack_surface, risk_indicators)

        result = {
            "url": url,
            "parsed_url": {
                "scheme": urlparse(url).scheme,
                "hostname": urlparse(url).hostname,
                "port": urlparse(url).port,
                "path": urlparse(url).path,
            },
            "tech_stack": tech_stack,
            "attack_surface": attack_surface,
            "endpoints": endpoints,
            "risk_indicators": risk_indicators,
            "scan_plan": scan_plan,
            "llm_insights": llm_insights,
        }

        logger.info(
            "ReconAgent analysis complete",
            extra={
                "url": url,
                "tech_count": len(tech_stack),
                "endpoints_found": len(endpoints),
                "risks": len(risk_indicators),
                "scanners_selected": scan_plan.get("scanners", []),
            },
        )

        return result

    async def _fetch_target(
        self, client: httpx.AsyncClient, url: str, auth_header: Optional[str] = None
    ) -> dict:
        """Fetch the target URL and gather response metadata."""
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        response_data = {
            "status_code": None,
            "headers": {},
            "cookies": {},
            "body_snippet": "",
            "body_length": 0,
            "content_type": None,
            "accessible": False,
        }

        try:
            response = await client.get(url, headers=headers)
            response_data["status_code"] = response.status_code
            response_data["headers"] = dict(response.headers)
            response_data["cookies"] = dict(response.cookies)
            body = response.text
            response_data["body_snippet"] = body[:5000]  # Store first 5KB
            response_data["body_length"] = len(body)
            response_data["content_type"] = response.headers.get("content-type", "")
            response_data["accessible"] = response.status_code < 500

            # Check for specific response characteristics
            response_data["has_form"] = bool(re.search(r"<form", body, re.IGNORECASE))
            response_data["has_login"] = bool(
                re.search(r"(login|signin|sign-in|log in)", body, re.IGNORECASE)
            )
            response_data["has_file_upload"] = bool(
                re.search(r"type=[\"']file[\"']", body, re.IGNORECASE)
            )
            response_data["has_input_fields"] = len(re.findall(r"<input", body, re.IGNORECASE))

            # Detect API response (JSON)
            try:
                json.loads(body[:10000])
                response_data["is_json_api"] = True
            except (json.JSONDecodeError, ValueError):
                response_data["is_json_api"] = False

        except httpx.TimeoutException:
            logger.warning("ReconAgent timeout fetching target", extra={"url": url})
            response_data["error"] = "timeout"
        except httpx.ConnectError:
            logger.warning("ReconAgent connection refused", extra={"url": url})
            response_data["error"] = "connection_refused"
        except Exception as exc:
            logger.warning("ReconAgent fetch error", extra={"url": url, "error": str(exc)})
            response_data["error"] = str(exc)

        return response_data

    def _fingerprint_tech(self, response_data: dict) -> list[dict]:
        """Identify technology stack from HTTP response signatures."""
        detected = []
        headers = {k.lower(): str(v) for k, v in response_data.get("headers", {}).items()}
        body = response_data.get("body_snippet", "").lower()
        cookies = response_data.get("cookies", {})

        for tech_name, signatures in self.TECH_SIGNATURES.items():
            match_count = 0
            matched_evidence = []

            for sig in signatures:
                if "header" in sig:
                    header_key = sig["header"].lower()
                    header_val = headers.get(header_key, "")
                    if header_val and re.search(sig["pattern"], header_val, re.IGNORECASE):
                        match_count += 1
                        matched_evidence.append(f"header:{sig['header']}={header_val[:80]}")
                elif "cookie" in sig:
                    cookie_val = cookies.get(sig["cookie"], cookies.get(sig["cookie"].lower(), ""))
                    if cookie_val and re.search(sig["pattern"], str(cookie_val)):
                        match_count += 1
                        matched_evidence.append(f"cookie:{sig['cookie']}")
                elif "body" in sig:
                    if re.search(sig["pattern"], body, re.IGNORECASE):
                        match_count += 1
                        matched_evidence.append(f"body:{sig['body']}")
                elif "path" in sig:
                    # Path-based signatures checked during endpoint discovery
                    pass

            if match_count > 0:
                confidence = min(match_count / max(len([s for s in signatures if "path" not in s]), 1), 1.0)
                detected.append({
                    "name": tech_name,
                    "confidence": round(confidence, 2),
                    "evidence": matched_evidence[:3],
                })

        # Sort by confidence descending
        detected.sort(key=lambda x: x["confidence"], reverse=True)
        return detected

    async def _discover_endpoints(
        self, client: httpx.AsyncClient, base_url: str, auth_header: Optional[str] = None
    ) -> list[dict]:
        """Probe common paths to discover endpoints."""
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        discovered = []
        for path in self.DISCOVERY_PATHS:
            try:
                url = base_url.rstrip("/") + path
                resp = await client.get(url, headers=headers)
                if resp.status_code < 400:
                    discovered.append({
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "content_length": len(resp.text),
                    })
            except Exception:
                continue

        return discovered

    def _build_attack_surface(self, response_data: dict, endpoints: list[dict]) -> dict:
        """Build a structured attack surface summary."""
        return {
            "accessible": response_data.get("accessible", False),
            "status_code": response_data.get("status_code"),
            "content_type": response_data.get("content_type"),
            "body_length": response_data.get("body_length", 0),
            "has_login_form": response_data.get("has_login", False),
            "has_file_upload": response_data.get("has_file_upload", False),
            "has_forms": response_data.get("has_form", False),
            "input_field_count": response_data.get("has_input_fields", 0),
            "is_json_api": response_data.get("is_json_api", False),
            "discovered_endpoints": len(endpoints),
            "endpoint_list": [e["path"] for e in endpoints],
            "auth_configured": bool(response_data.get("headers", {}).get("authorization")),
        }

    def _identify_risks(self, response_data: dict, tech_stack: list[dict]) -> list[dict]:
        """Identify security-relevant observations about the target."""
        risks = []
        headers = {k.lower(): str(v) for k, v in response_data.get("headers", {}).items()}

        # Missing security headers
        security_headers = {
            "strict-transport-security": "HSTS (HTTP Strict Transport Security) not set",
            "content-security-policy": "CSP (Content Security Policy) not set",
            "x-content-type-options": "X-Content-Type-Options not set",
            "x-frame-options": "X-Frame-Options not set (clickjacking risk)",
            "x-xss-protection": "X-XSS-Protection not set",
        }
        for header, risk_msg in security_headers.items():
            if header not in headers:
                risks.append({
                    "type": "missing_security_header",
                    "header": header,
                    "description": risk_msg,
                    "severity": "medium",
                })

        # Server information disclosure
        server = headers.get("server", "")
        if server and server not in ("cloudflare", ""):
            risks.append({
                "type": "server_disclosure",
                "header": "server",
                "description": f"Server header discloses: {server}",
                "severity": "low",
            })

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            risks.append({
                "type": "technology_disclosure",
                "header": "x-powered-by",
                "description": f"X-Powered-By header discloses: {powered_by}",
                "severity": "low",
            })

        # Debug mode indicators
        if "debug" in response_data.get("body_snippet", "").lower():
            risks.append({
                "type": "debug_mode",
                "description": "Response body contains 'debug' references",
                "severity": "medium",
            })

        # Error disclosure
        error_patterns = [
            r"stack trace",
            r"traceback",
            r"warning:",
            r"parse error",
            r"syntax error",
            r"uncaught exception",
            r"fatal error",
            r"internal server error",
        ]
        body_lower = response_data.get("body_snippet", "").lower()
        for pattern in error_patterns:
            if re.search(pattern, body_lower):
                risks.append({
                    "type": "error_disclosure",
                    "description": f"Error information may be disclosed (matched: {pattern})",
                    "severity": "medium",
                })
                break

        return risks

    def _generate_scan_plan(
        self,
        url: str,
        tech_stack: list[dict],
        attack_surface: dict,
        risk_indicators: list[dict],
    ) -> dict:
        """Determine optimal scanner configuration based on recon data."""
        tech_names = [t["name"] for t in tech_stack]
        high_confidence_techs = [t["name"] for t in tech_stack if t["confidence"] >= 0.5]
        tech_set = set(high_confidence_techs)
        highest_risk = max(
            [r.get("severity", "info") for r in risk_indicators],
            default="info",
        )

        scanners = []
        scanner_configs = {}

        # Always include nuclei for general vuln scanning
        nuclei_config = {
            "enabled": True,
            "tags": ["cve", "exposure", "misconfig"],
            "severity": "critical,high,medium",
        }

        # Add tech-specific nuclei tags
        if "wordpress" in tech_set:
            nuclei_config["tags"].append("wordpress")
        if "laravel" in tech_set:
            nuclei_config["tags"].append("laravel")
        if "java-spring" in tech_set:
            nuclei_config["tags"].append("spring")
        if "aspnet" in tech_set:
            nuclei_config["tags"].append("aspnet")

        scanners.append("nuclei")
        scanner_configs["nuclei"] = nuclei_config

        # Include ZAP for deep web scanning
        if attack_surface.get("accessible") and not attack_surface.get("is_json_api"):
            zap_config = {
                "enabled": True,
                "spider": True,
                "active_scan": highest_risk in ("critical", "high", "medium"),
            }
            scanners.append("zap")
            scanner_configs["zap"] = zap_config

        # Include PromptFoo for LLM/AI targets or API endpoints
        if attack_surface.get("is_json_api") or "graphql" in tech_set or "swagger" in tech_set:
            promptfoo_config = {
                "enabled": True,
                "plugins": ["harmful", "pii", "jailbreak", "imitation", "excessive-agency"],
            }
            scanners.append("promptfoo")
            scanner_configs["promptfoo"] = promptfoo_config

        return {
            "scanners": scanners,
            "configs": scanner_configs,
            "depth": "deep" if highest_risk in ("critical", "high") else "standard",
            "priority": highest_risk,
            "estimated_duration_minutes": len(scanners) * 5,
        }

    async def _llm_analysis(
        self,
        url: str,
        tech_stack: list[dict],
        attack_surface: dict,
        risk_indicators: list[dict],
    ) -> dict:
        """Use LLM for advanced context-aware analysis if available."""
        if not self._llm:
            return {"available": False, "analysis": None}

        try:
            prompt = f"""Analyze this web target for penetration testing:

Target URL: {url}

Detected Technologies: {json.dumps(tech_stack, indent=2)}
Attack Surface: {json.dumps(attack_surface, indent=2)}
Risk Indicators: {json.dumps(risk_indicators, indent=2)}

Provide:
1. Overall risk assessment (low/medium/high/critical)
2. Most likely vulnerabilities based on tech stack
3. Recommended testing approach
4. Specific things to look for

Respond in JSON format with keys: risk_level, likely_vulnerabilities (list),
testing_approach (string), specific_checks (list of strings)."""

            response = await self._llm.ainvoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)

            # Try to parse JSON from response
            try:
                json_match = re.search(r"\{.*\}", content, re.DOTALL)
                if json_match:
                    return {"available": True, "analysis": json.loads(json_match.group())}
            except (json.JSONDecodeError, AttributeError):
                pass

            return {"available": True, "analysis": {"raw": content[:2000]}}

        except Exception as exc:
            logger.warning("LLM analysis failed", extra={"error": str(exc)})
            return {"available": False, "analysis": None, "error": str(exc)}
