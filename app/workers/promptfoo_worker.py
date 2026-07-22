import docker
import os
import json
from app.core.logging import logger

client = docker.from_env()

async def run_promptfoo_eval(target_app_url: str, prompt_file: str):
    logger.info(f"Starting isolated Promptfoo eval for {target_app_url}")
    
    container_name = f"promptfoo_eval_{os.urandom(4).hex()}"
    try:
        # Ephemeral container for prompt injection and LLM security testing
        container = client.containers.run(
            "promptfoo/promptfoo:latest",
            command=f"eval -p {prompt_file} --view-only",
            name=container_name,
            environment={"TARGET_URL": target_app_url},
            detach=False,
            remove=True,
            network_mode="none",
            mem_limit="1g"
        )
        
        return {"status": "completed", "output": container.decode('utf-8')}
    except Exception as e:
        logger.error(f"Promptfoo sandbox failure: {str(e)}")
        return {"status": "error", "message": str(e)}