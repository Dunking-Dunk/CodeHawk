'''Contain the tools and other things the agent can use'''

# Import code analysis tools
try:
    from .code_analysis import CodeAnalysis
    from .python_analyzer import PythonAnalyzer
    from .javascript_analyzer import JavaScriptAnalyzer
    from .java_analyzer import JavaAnalyzer
    from .cpp_analyzer import CppAnalyzer
except ImportError as e:
    print(f"Warning: Some code analysis tools could not be imported: {e}")

__all__ = [
    'CodeAnalysis',
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'CppAnalyzer'
]