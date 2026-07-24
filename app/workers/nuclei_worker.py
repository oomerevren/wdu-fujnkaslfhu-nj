import docker
import os
import json
import subprocess
import secrets
from app.core.logging import logger

client = docker.from_env()

async def run_nuclei_scan(target_url: str, use_subprocess_fallback: bool = False):
    logger.info(f"Starting isolated Nuclei scan for {target_url}", extra={"subprocess_fallback": use_subprocess_fallback})

    container_name = f"nuclei_scan_{secrets.token_hex(4)}"

    # Primary: Docker-based sandbox (isolated, safe)
    try:
        container = client.containers.run(
            "projectdiscovery/nuclei:latest",
            command=f"-u {target_url} -json",
            name=container_name,
            detach=False,
            remove=True,
            network_mode="none",
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=50000,
        )
        results = []
        for line in container.decode("utf-8").splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                continue
        logger.info("Nuclei Docker scan completed", extra={"findings": len(results), "target": target_url})
        return results
    except Exception as exc:
        logger.error("Nuclei Docker sandbox failure", extra={"error": str(exc), "target": target_url})

    # Fallback: subprocess-based direct execution (production environment with binary installed)
    if use_subprocess_fallback:
        try:
            result = subprocess.run(
                ["nuclei", "-u", target_url, "-json"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            findings = []
            for line in result.stdout.splitlines():
                try:
                    findings.append(json.loads(line))
                except Exception:
                    continue
            logger.info("Nuclei subprocess fallback completed", extra={"findings": len(findings), "returncode": result.returncode})
            return findings
        except Exception as exc_fallback:
            logger.error("Nuclei subprocess fallback also failed", extra={"error": str(exc_fallback), "target": target_url})

    return []