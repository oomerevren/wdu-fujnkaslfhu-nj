
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseAgent(ABC):
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    @abstractmethod
    async def execute(self, task_input: Dict[str, Any]) -> Dict[str, Any]:
        pass
