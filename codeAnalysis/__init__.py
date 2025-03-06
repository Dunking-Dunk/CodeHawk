"""
CodeHawk - A Multi-language Static Code Analysis Tool

This package provides comprehensive code analysis for multiple programming languages,
including Python, JavaScript, Java, and C/C++.
"""

# Import main components to expose at the package level
from .code_analysis import CodeAnalysis, main
from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .java_analyzer import JavaAnalyzer
from .cpp_analyzer import CppAnalyzer

# Version information
__version__ = "1.0.0"
__author__ = "CodeHawk Team"

# Export public interface
__all__ = [
    'CodeAnalysis',
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'CppAnalyzer',
    'main'
]