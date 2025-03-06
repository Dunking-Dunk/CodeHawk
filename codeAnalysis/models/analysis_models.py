from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AnalysisType(str, Enum):
    SYNTAX = "syntax"
    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    METRICS = "metrics"
    RULE_BASED = "rule_based"
    PATTERN = "pattern"
    SYMBOLIC = "symbolic"
    TAINT = "taint"
    LEXICAL = "lexical"
    MEMORY = "memory"

class CodeLocation(BaseModel):
    file: str = Field(..., description="Path to the file")
    line_start: int = Field(..., description="Starting line number")
    line_end: Optional[int] = Field(None, description="Ending line number")
    column_start: Optional[int] = Field(None, description="Starting column")
    column_end: Optional[int] = Field(None, description="Ending column")

class AnalysisFinding(BaseModel):
    type: AnalysisType = Field(..., description="Type of analysis that found the issue")
    severity: SeverityLevel = Field(..., description="Severity level of the finding")
    message: str = Field(..., description="Description of the issue")
    location: CodeLocation = Field(..., description="Location of the issue in the code")
    fix_suggestions: List[str] = Field(default_factory=list, description="Suggested fixes for the issue")
    code_snippet: Optional[str] = Field(None, description="Relevant code snippet")
    rule_id: Optional[str] = Field(None, description="ID of the rule that was violated")
    additional_info: Dict[str, Any] = Field(default_factory=dict, description="Additional analysis-specific information")

class AnalysisResult(BaseModel):
    findings: List[AnalysisFinding] = Field(default_factory=list, description="List of analysis findings")
    summary: Dict[str, int] = Field(default_factory=dict, description="Summary of findings by type and severity")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Code metrics (complexity, coverage, etc.)")
    errors: List[str] = Field(default_factory=list, description="Analysis errors or failures")

class AnalysisConfig(BaseModel):
    enabled_analyzers: List[AnalysisType] = Field(default_factory=lambda: list(AnalysisType), description="Enabled analyzers")
    severity_threshold: SeverityLevel = Field(default=SeverityLevel.LOW, description="Minimum severity level to report")
    max_findings_per_file: int = Field(default=100, description="Maximum findings to report per file")
    ignore_patterns: List[str] = Field(default_factory=list, description="Patterns to ignore")
    custom_rules: Dict[str, Any] = Field(default_factory=dict, description="Custom analysis rules")
    language_specific_config: Dict[str, Any] = Field(default_factory=dict, description="Language-specific configuration") 