"""
Models for CodeHawk code analysis.
"""

from .output import (
    AnalysisResult,
    PythonAnalysisResult,
    JavaScriptAnalysisResult,
    JavaAnalysisResult,
    CppAnalysisResult
)

from .input_config import (
    AnalyzerConfig,
    PythonAnalyzerConfig,
    JavaScriptAnalyzerConfig,
    JavaAnalyzerConfig,
    CppAnalyzerConfig
)

__all__ = [
    'AnalysisResult',
    'PythonAnalysisResult',
    'JavaScriptAnalysisResult',
    'JavaAnalysisResult',
    'CppAnalysisResult',
    'AnalyzerConfig',
    'PythonAnalyzerConfig',
    'JavaScriptAnalyzerConfig',
    'JavaAnalyzerConfig',
    'CppAnalyzerConfig'
] 