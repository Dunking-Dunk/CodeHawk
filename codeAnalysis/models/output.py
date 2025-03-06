"""
Pydantic models for the output of code analysis.
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from pydantic import BaseModel, Field


class Location(BaseModel):
    """Location of an issue in code."""
    path: str = Field(..., description="Path to the file")
    line: Optional[int] = Field(None, description="Line number")
    column: Optional[int] = Field(None, description="Column number")
    character: Optional[int] = Field(None, description="Character position")


class AnalysisIssue(BaseModel):
    """Base class for all analysis issues."""
    location: Location
    message: str = Field(..., description="Issue description")
    severity: str = Field(..., description="Severity level")
    source: str = Field(..., description="Tool that generated the issue")
    code: str = Field(..., description="Issue code/rule")
    line_src: Optional[str] = Field(None, description="Source code line where the issue was found")
    fix_recommendation: Optional[str] = Field(None, description="Detailed recommendation on how to fix the issue")
    # Advanced analysis data fields
    analysis_type: str = Field("generic", description="Type of analysis that found the issue (syntax, data_flow, control_flow, etc.)")
    impacted_lines: Optional[List[int]] = Field(None, description="All line numbers impacted by this issue")
    related_issues: Optional[List[str]] = Field(None, description="IDs of related issues")
    pattern_name: Optional[str] = Field(None, description="Name of the code pattern if pattern-based analysis")
    dataflow_path: Optional[List[Dict[str, Any]]] = Field(None, description="Path of data flow if relevant")
    memory_impact: Optional[Dict[str, Any]] = Field(None, description="Details about memory impact if memory-related")
    security_impact: Optional[str] = Field(None, description="Description of security impact if relevant")
    symbolic_trace: Optional[List[Dict[str, Any]]] = Field(None, description="Symbolic execution trace if relevant")
    fix_complexity: Optional[str] = Field(None, description="Complexity of implementing the fix: easy, medium, hard")


class FilteringSummary(BaseModel):
    """Summary of filtering applied to analysis results."""
    total_issues_found: int = Field(..., description="Total issues found before filtering")
    filtered_count: int = Field(..., description="Number of issues filtered out")
    ignored_sources: Dict[str, List[str]] = Field(
        ..., description="Sources and codes that were ignored during filtering"
    )
    severity_threshold: str = Field(..., description="Minimum severity threshold used for filtering")


class AnalysisSummary(BaseModel):
    """Summary of the analysis run."""
    started: Optional[datetime] = Field(None, description="When the analysis started")
    completed: Optional[datetime] = Field(None, description="When the analysis completed")
    time_taken: Optional[str] = Field(None, description="Time taken for analysis")
    message_count: int = Field(..., description="Total number of issues found after filtering")
    filtering_details: Optional[FilteringSummary] = Field(None, description="Details of issue filtering")
    tools: List[str] = Field(default_factory=list, description="Tools used for analysis")
    # Additional analysis summary data
    analysis_types_performed: List[str] = Field(default_factory=list, description="Types of analyses performed")
    issues_by_analysis_type: Dict[str, int] = Field(default_factory=dict, description="Count of issues by analysis type")
    files_analyzed: int = Field(0, description="Number of files analyzed")
    lines_analyzed: int = Field(0, description="Number of code lines analyzed")


class AnalysisResult(BaseModel):
    """Base class for all analysis results."""
    summary: AnalysisSummary
    messages: List[AnalysisIssue] = Field(default_factory=list, description="List of issues found")
    error: Optional[str] = Field(None, description="Error message if analysis failed")


class PythonIssue(AnalysisIssue):
    """Python-specific analysis issue."""
    solution: Optional[str] = Field(None, description="Suggested solution")


class PythonAnalysisResult(AnalysisResult):
    """Python analysis result."""
    messages: List[PythonIssue] = Field(default_factory=list, description="List of Python issues")
    
    class Config:
        schema_extra = {
            "example": {
                "summary": {
                    "started": "2025-03-06T13:04:14.509969",
                    "completed": "2025-03-06T13:04:15.691958",
                    "time_taken": "1.18",
                    "message_count": 10,
                    "filtering_details": {
                        "total_issues_found": 17,
                        "filtered_count": 7,
                        "ignored_sources": {
                            "pep8": ["E501"],
                            "pylint": ["missing-docstring"]
                        },
                        "severity_threshold": "low"
                    },
                    "tools": ["dodgy", "mccabe", "pyflakes", "pylint"],
                    "analysis_types_performed": ["syntax", "data_flow", "control_flow", "metrics", "rule_based", "pattern_based"],
                    "issues_by_analysis_type": {
                        "syntax": 2,
                        "data_flow": 3,
                        "control_flow": 1,
                        "metrics": 2,
                        "rule_based": 1,
                        "pattern_based": 1
                    },
                    "files_analyzed": 5,
                    "lines_analyzed": 1250
                },
                "messages": [
                    {
                        "location": {
                            "path": "sample.py",
                            "line": 15,
                            "column": 5
                        },
                        "message": "F841: Local variable 'result_status' is assigned to but never used",
                        "severity": "medium",
                        "source": "pyflakes",
                        "code": "F841",
                        "line_src": "    result_status = process_data(input_data)",
                        "fix_recommendation": "Either remove the variable if it's not needed, or use it in subsequent code.",
                        "analysis_type": "data_flow",
                        "fix_complexity": "easy"
                    }
                ]
            }
        }


class JavaScriptIssue(AnalysisIssue):
    """JavaScript-specific analysis issue."""
    rule_id: str = Field(..., description="ESLint rule ID")
    line_text: Optional[str] = Field(None, description="Source code line")
    fix: Optional[Dict[str, Any]] = Field(None, description="Suggested fix")


class JavaScriptAnalysisResult(AnalysisResult):
    """JavaScript analysis result."""
    messages: List[JavaScriptIssue] = Field(default_factory=list, description="List of JavaScript issues")
    files_analyzed: int = Field(0, description="Number of files analyzed")


class JavaViolation(AnalysisIssue):
    """Java-specific violation from PMD or SpotBugs."""
    rule: str = Field(..., description="Rule name")
    ruleset: str = Field(..., description="Ruleset name")
    priority: int = Field(..., description="Priority (1-5)")


class JavaAnalysisResult(AnalysisResult):
    """Java analysis result."""
    pmd: Optional[Dict[str, Any]] = Field(None, description="PMD analysis results")
    spotbugs: Optional[Dict[str, Any]] = Field(None, description="SpotBugs analysis results")


class CppIssue(AnalysisIssue):
    """C/C++-specific issue from Clang-Tidy."""
    check: str = Field(..., description="Clang-Tidy check name")


class CppAnalysisResult(AnalysisResult):
    """C/C++ analysis result."""
    messages: List[CppIssue] = Field(default_factory=list, description="List of C/C++ issues")
    files_analyzed: int = Field(0, description="Number of files analyzed")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Raw issues data") 