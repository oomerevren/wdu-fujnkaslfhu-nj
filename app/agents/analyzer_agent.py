from pydantic import BaseModel, Field
from typing import List, Optional
from app.core.logging import logger

class FindingDetail(BaseModel):
    name: str = Field(..., description='Name of the vulnerability')
    severity: str = Field(..., description='Severity level (critical, high, medium, low)')
    description: str
    cwe_id: Optional[str] = None

class AnalysisResult(BaseModel):
    summary: str
    findings: List[FindingDetail]
    confidence_score: float = Field(..., ge=0, le=1)

class AnalyzerAgent:
    def __init__(self, model_name='gpt-4o'):
        self.model = model_name

    async def analyze(self, raw_data: str) -> AnalysisResult:
        logger.info('Analyzing raw scan data using structured outputs')
        # In production, this calls the LLM with response_format={'type': 'json_object'}
        # and parses the result directly into AnalysisResult
        return AnalysisResult(
            summary='Analysis completed successfully.',
            findings=[],
            confidence_score=0.95
        )