import httpx
import uuid
from app.core.logging import logger

class OASTClient:
    def __init__(self, server_url='interact.sh'):
        self.server_url = server_url
        self.correlation_id = str(uuid.uuid4())

    def get_oob_domain(self):
        return f"{self.correlation_id}.{self.server_url}"

    async def fetch_interactions(self):
        # Simulated fetch logic for Interactsh API
        logger.info(f"Fetching OOB interactions for {self.correlation_id}")
        return []