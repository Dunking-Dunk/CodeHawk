"""
Configuration dataclasses for code analyzers.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


@dataclass
class AnalysisTypeConfig:
    """Configuration for specific types of analysis."""
    enabled: bool = True
    severity_threshold: str = "low"  # low, medium, high
    # Specific settings for each analysis type
    max_complexity: int = 10  # For metrics-based analysis
    max_depth: int = 5  # For control flow analysis
    memory_analysis_depth: int = 3  # For memory leak detection


@dataclass
class AnalyzerConfig:
    """Base configuration for all analyzers."""
    enabled: bool = True
    config_path: Optional[str] = None
    ignored_patterns: List[str] = field(default_factory=list)
    severity_threshold: str = "low"
    
    # Enable/disable specific analysis types
    syntax_analysis: bool = True
    data_flow_analysis: bool = True
    control_flow_analysis: bool = True
    metrics_analysis: bool = True
    rule_analysis: bool = True
    pattern_analysis: bool = True
    symbolic_execution: bool = True
    taint_analysis: bool = True
    lexical_analysis: bool = True
    memory_leak_detection: bool = True
    
    # Detailed configuration for each analysis type
    analysis_config: Dict[str, AnalysisTypeConfig] = field(default_factory=lambda: {
        "syntax": AnalysisTypeConfig(),
        "data_flow": AnalysisTypeConfig(),
        "control_flow": AnalysisTypeConfig(),
        "metrics": AnalysisTypeConfig(),
        "rule": AnalysisTypeConfig(),
        "pattern": AnalysisTypeConfig(),
        "symbolic": AnalysisTypeConfig(),
        "taint": AnalysisTypeConfig(),
        "lexical": AnalysisTypeConfig(),
        "memory_leak": AnalysisTypeConfig()
    })
    
    # Specify which analysis types should generate recommendations
    generate_recommendations: bool = True


@dataclass
class PythonAnalyzerConfig(AnalyzerConfig):
    """Configuration for Python analyzer (Prospector)."""
    # Prospector-specific configuration
    strictness: str = "medium"  # Options: verylow, low, medium, high, veryhigh
    
    # Tool-specific settings
    run_pyflakes: bool = True
    run_pylint: bool = True
    run_mccabe: bool = True
    run_dodgy: bool = True
    run_pep8: bool = True
    run_bandit: bool = True
    
    # Filtering settings
    max_complexity: int = 10
    ignored_messages: Dict[str, List[str]] = field(default_factory=lambda: {
        "pep8": ["E501"],
        "pylint": []
    })
    
    # Advanced analysis options
    enable_mypy: bool = True  # For advanced static type checking
    enable_vulture: bool = True  # For finding dead code (control flow)
    enable_pydocstyle: bool = True  # For documentation quality


@dataclass
class JavaScriptAnalyzerConfig(AnalyzerConfig):
    """Configuration for JavaScript analyzer (ESLint)."""
    # ESLint specific configuration
    eslint_plugins: List[str] = field(default_factory=lambda: [
        "eslint-plugin-import", 
        "eslint-plugin-react", 
        "eslint-plugin-security"
    ])
    
    # ESLint rule categories to enable/disable
    enable_style_rules: bool = False
    enable_security_rules: bool = True
    enable_best_practices: bool = True
    
    # ESLint file extensions to analyze
    file_extensions: List[str] = field(default_factory=lambda: [
        ".js", ".jsx", ".ts", ".tsx"
    ])
    
    # Specific rules to ignore
    ignored_rules: List[str] = field(default_factory=list)
    
    # Advanced analysis options
    enable_flow: bool = True  # Flow type analyzer for data flow analysis
    enable_closure_compiler: bool = False  # Google Closure Compiler for advanced static analysis


@dataclass
class JavaAnalyzerConfig(AnalyzerConfig):
    """Configuration for Java analyzer (PMD and SpotBugs)."""
    # PMD configuration
    pmd_path: Optional[str] = None
    pmd_ruleset: str = "rulesets/java/quickstart.xml"
    
    # SpotBugs configuration
    spotbugs_path: Optional[str] = None
    enable_spotbugs: bool = True
    
    # Priority settings
    priority_threshold: int = 4  # PMD priorities 1-4, ignore 5
    
    # Specific rules to ignore
    ignored_rulesets: Dict[str, List[str]] = field(default_factory=lambda: {
        "java-controversial": ["OnlyOneReturn"],
        "java-optimizations": ["MethodArgumentCouldBeFinal", "LocalVariableCouldBeFinal"]
    })
    
    # Advanced analysis options
    enable_checkstyle: bool = True  # For style and pattern analysis
    enable_infer: bool = False  # Facebook Infer for advanced static analysis


@dataclass
class CppAnalyzerConfig(AnalyzerConfig):
    """Configuration for C/C++ analyzer (Clang-Tidy)."""
    # Clang-Tidy configuration
    compilation_db_path: Optional[str] = None
    checks: str = "*,-clang-analyzer-alpha.*"
    
    # Severity settings
    ignore_notes: bool = True
    
    # Categories to enable/disable
    enable_readability: bool = True
    enable_performance: bool = True
    enable_modernize: bool = True
    enable_bugprone: bool = True
    
    # Specific checks to ignore
    ignored_checks: List[str] = field(default_factory=lambda: [
        "readability-magic-numbers",
        "readability-braces-around-statements"
    ])
    
    # Advanced analysis options
    enable_cppcheck: bool = True  # For additional static analysis
    enable_asan: bool = False  # AddressSanitizer for memory issues
    enable_valgrind: bool = False  # Valgrind for memory leak detection 