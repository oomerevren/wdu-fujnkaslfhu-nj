
from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePlugin(ABC):
    def __init__(self, plugin_id: str, version: str = '1.0.0'):
        self.plugin_id = plugin_id
        self.version = version

    @abstractmethod
    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        pass
