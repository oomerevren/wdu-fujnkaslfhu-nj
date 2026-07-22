import docker
import os
import json
from app.core.logging import logger

client = docker.from_env()

async def run_nuclei_scan(target_url: str):
    logger.info(f"Starting isolated Nuclei scan for {target_url}")
    
    container_name = f"nuclei_scan_{os.urandom(4).hex()}"
    try:
        # In production, we use the project's specific nuclei image
        container = client.containers.run(
            "projectdiscovery/nuclei:latest",
            command=f"-u {target_url} -json",
            name=container_name,
            detach=False,
            remove=True,
            network_mode="none", # Egress isolation
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=50000
        )
        
        results = []
        for line in container.decode('utf-8').splitlines():
            try:
                results.append(json.loads(line))
            except:
                continue
                
        return results
    except Exception as e:
        logger.error(f"Nuclei sandbox failure: {str(e)}")
        return []