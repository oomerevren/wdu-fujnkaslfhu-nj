import docker
import os
import json
import tempfile
import secrets
from pathlib import Path
from app.core.logging import logger

client = docker.from_env()

async def run_promptfoo_eval(target_app_url: str, prompt_file_content: str = None):
    logger.info(f"Starting isolated Promptfoo eval for {target_app_url}")

    container_name = f"promptfoo_eval_{secrets.token_hex(4)}"
    temp_path = None

    try:
        # Write prompt content to temporary file if content provided
        if prompt_file_content:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
                tmp.write(prompt_file_content)
                temp_path = tmp.name
            prompt_file = temp_path
        else:
            prompt_file = "/default/prompts/security.json"

        container = client.containers.run(
            "promptfoo/promptfoo:latest",
            command=f"eval -p {prompt_file} --view-only",
            name=container_name,
            environment={"TARGET_URL": target_app_url},
            detach=False,
            remove=True,
            network_mode="none",
            mem_limit="1g",
            volumes={
                temp_path: {"bind": prompt_file, "mode": "ro"} if temp_path else None
            } if temp_path else {},
        )

        result = {"status": "completed", "output": container.decode("utf-8")}
        return result
    except Exception as e:
        logger.error(f"Promptfoo sandbox failure: {str(e)}", extra={"container": container_name})
        return {"status": "error", "message": str(e)}
    finally:
        # Cleanup temporary prompt file
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
                logger.info("Promptfoo temp file cleaned up", extra={"path": temp_path})
            except Exception as exc:
                logger.warning("Failed to clean up temp file", extra={"path": temp_path, "error": str(exc)})
