import os
import sys
import json
import ast
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass

try:
    from .models.analysis_models import (
        AnalysisResult, AnalysisFinding, CodeLocation,
        SeverityLevel, AnalysisType, AnalysisConfig
    )
except ImportError:
    from models.analysis_models import (
        AnalysisResult, AnalysisFinding, CodeLocation,
        SeverityLevel, AnalysisType, AnalysisConfig
    )

class PythonAnalyzer:
    """
    Enhanced Python code analyzer that performs comprehensive code analysis
    including syntax, data flow, control flow, and other advanced analyses.
    """
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize all required analysis tools."""
        self.tools = {
            "prospector": self._check_tool("prospector"),
            "bandit": self._check_tool("bandit"),
            "mypy": self._check_tool("mypy"),
            "vulture": self._check_tool("vulture"),
            "radon": self._check_tool("radon")
        }
        
        # Try to install missing tools
        for tool, available in self.tools.items():
            if not available:
                self._install_tool(tool)
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        return bool(shutil.which(tool_name))
    
    def _install_tool(self, tool_name: str):
        """Attempt to install a missing tool."""
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", tool_name],
                check=True,
                capture_output=True
            )
            self.tools[tool_name] = True
        except Exception as e:
            print(f"Failed to install {tool_name}: {str(e)}")
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single Python file using all available analysis types."""
        if not os.path.exists(file_path):
            return AnalysisResult(errors=[f"File not found: {file_path}"])
        
        if not file_path.endswith('.py'):
            return AnalysisResult(errors=[f"Not a Python file: {file_path}"])
        
        result = AnalysisResult()
        
        # Run all enabled analyzers
        for analysis_type in self.config.enabled_analyzers:
            try:
                findings = []
                if analysis_type == AnalysisType.SYNTAX:
                    findings = self._syntax_analysis(file_path)
                elif analysis_type == AnalysisType.DATA_FLOW:
                    findings = self._data_flow_analysis(file_path)
                elif analysis_type == AnalysisType.CONTROL_FLOW:
                    findings = self._control_flow_analysis(file_path)
                elif analysis_type == AnalysisType.METRICS:
                    findings = self._metrics_analysis(file_path)
                elif analysis_type == AnalysisType.RULE_BASED:
                    findings = self._rule_based_analysis(file_path)
                elif analysis_type == AnalysisType.PATTERN:
                    findings = self._pattern_analysis(file_path)
                elif analysis_type == AnalysisType.SYMBOLIC:
                    findings = self._symbolic_analysis(file_path)
                elif analysis_type == AnalysisType.TAINT:
                    findings = self._taint_analysis(file_path)
                elif analysis_type == AnalysisType.LEXICAL:
                    findings = self._lexical_analysis(file_path)
                elif analysis_type == AnalysisType.MEMORY:
                    findings = self._memory_analysis(file_path)
                
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"Error in {analysis_type} analysis: {str(e)}")
        
        # Update summary
        for finding in result.findings:
            result.summary[finding.type.value] = result.summary.get(finding.type.value, 0) + 1
            severity_key = f"{finding.type.value}_{finding.severity.value}"
            result.summary[severity_key] = result.summary.get(severity_key, 0) + 1
        
        return result
    
    def _syntax_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform syntax analysis using ast module and Prospector."""
        findings = []
        
        # AST-based syntax analysis
        try:
            with open(file_path, 'r') as f:
                source = f.read()
            ast.parse(source)
        except SyntaxError as e:
            findings.append(AnalysisFinding(
                type=AnalysisType.SYNTAX,
                severity=SeverityLevel.CRITICAL,
                message=str(e),
                location=CodeLocation(
                    file=file_path,
                    line_start=e.lineno,
                    column_start=e.offset
                ),
                fix_suggestions=["Fix the syntax error according to Python syntax rules"]
            ))
        
        # Prospector analysis for additional syntax checks
        if self.tools["prospector"]:
            cmd = ["prospector", "--output-format=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode in (0, 1):
                    data = json.loads(result.stdout)
                    for msg in data.get("messages", []):
                        findings.append(AnalysisFinding(
                            type=AnalysisType.SYNTAX,
                            severity=self._map_severity(msg.get("severity", "medium")),
                            message=msg.get("message", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=msg.get("location", {}).get("line", 1),
                                column_start=msg.get("location", {}).get("character", 1)
                            ),
                            rule_id=msg.get("code")
                        ))
            except Exception as e:
                print(f"Prospector analysis failed: {str(e)}")
        
        return findings
    
    def _data_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform data flow analysis using mypy."""
        findings = []
        
        if self.tools["mypy"]:
            cmd = ["mypy", "--show-column-numbers", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.DATA_FLOW,
                                severity=SeverityLevel.MEDIUM,
                                message=parts[3].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1]),
                                    column_start=int(parts[2])
                                )
                            ))
            except Exception as e:
                print(f"MyPy analysis failed: {str(e)}")
        
        return findings
    
    def _control_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform control flow analysis using vulture and custom AST analysis."""
        findings = []
        
        # Vulture for dead code detection
        if self.tools["vulture"]:
            cmd = ["vulture", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.CONTROL_FLOW,
                                severity=SeverityLevel.LOW,
                                message=f"Dead code detected: {parts[-1].strip()}",
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1])
                                )
                            ))
            except Exception as e:
                print(f"Vulture analysis failed: {str(e)}")
        
        # Custom AST analysis for control flow
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
            
            class ControlFlowVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.issues = []
                
                def visit_While(self, node):
                    # Check for potential infinite loops
                    if isinstance(node.test, ast.Constant) and node.test.value:
                        self.issues.append((
                            node.lineno,
                            "Potential infinite loop detected"
                        ))
                    self.generic_visit(node)
            
            visitor = ControlFlowVisitor()
            visitor.visit(tree)
            
            for line, msg in visitor.issues:
                findings.append(AnalysisFinding(
                    type=AnalysisType.CONTROL_FLOW,
                    severity=SeverityLevel.HIGH,
                    message=msg,
                    location=CodeLocation(
                        file=file_path,
                        line_start=line
                    )
                ))
        except Exception as e:
            print(f"AST control flow analysis failed: {str(e)}")
        
        return findings
    
    def _metrics_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform metrics-based analysis using radon."""
        findings = []
        
        if self.tools["radon"]:
            # Cyclomatic Complexity
            cmd = ["radon", "cc", "-j", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for file_data in data.values():
                    for func in file_data:
                        if func["complexity"] > 10:  # High complexity threshold
                            findings.append(AnalysisFinding(
                                type=AnalysisType.METRICS,
                                severity=SeverityLevel.MEDIUM,
                                message=f"High cyclomatic complexity ({func['complexity']}) in function {func['name']}",
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=func["lineno"]
                                ),
                                fix_suggestions=["Consider breaking down the function into smaller functions",
                                               "Reduce nested conditionals",
                                               "Use early returns to reduce nesting"]
                            ))
            except Exception as e:
                print(f"Radon complexity analysis failed: {str(e)}")
            
            # Maintainability Index
            cmd = ["radon", "mi", "-j", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for file_path, mi_score in data.items():
                    if mi_score < 65:  # Low maintainability threshold
                        findings.append(AnalysisFinding(
                            type=AnalysisType.METRICS,
                            severity=SeverityLevel.HIGH,
                            message=f"Low maintainability index ({mi_score})",
                            location=CodeLocation(
                                file=file_path,
                                line_start=1
                            ),
                            fix_suggestions=["Improve code documentation",
                                           "Reduce function complexity",
                                           "Break down large functions and classes"]
                        ))
            except Exception as e:
                print(f"Radon maintainability analysis failed: {str(e)}")
        
        return findings
    
    def _rule_based_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform rule-based analysis using bandit and custom rules."""
        findings = []
        
        # Bandit security analysis
        if self.tools["bandit"]:
            cmd = ["bandit", "-f", "json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for issue in data.get("results", []):
                    findings.append(AnalysisFinding(
                        type=AnalysisType.RULE_BASED,
                        severity=self._map_severity(issue.get("issue_severity", "medium")),
                        message=issue.get("issue_text", ""),
                        location=CodeLocation(
                            file=file_path,
                            line_start=issue.get("line_number", 1)
                        ),
                        rule_id=issue.get("test_id"),
                        fix_suggestions=[issue.get("more_info", "")]
                    ))
            except Exception as e:
                print(f"Bandit analysis failed: {str(e)}")
        
        # Custom rules from config
        for rule_id, rule in self.config.custom_rules.items():
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                if rule.get("pattern") and rule["pattern"] in content:
                    findings.append(AnalysisFinding(
                        type=AnalysisType.RULE_BASED,
                        severity=SeverityLevel[rule.get("severity", "MEDIUM").upper()],
                        message=rule.get("message", "Custom rule violation"),
                        location=CodeLocation(
                            file=file_path,
                            line_start=1
                        ),
                        rule_id=rule_id
                    ))
            except Exception as e:
                print(f"Custom rule analysis failed: {str(e)}")
        
        return findings
    
    def _pattern_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform pattern-based analysis for common anti-patterns."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
            
            class PatternVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.issues = []
                
                def visit_Compare(self, node):
                    # Check for is/is not usage with literals
                    for op in node.ops:
                        if isinstance(op, (ast.Is, ast.IsNot)):
                            for comparator in node.comparators:
                                if isinstance(comparator, ast.Constant):
                                    self.issues.append((
                                        node.lineno,
                                        f"Use == instead of 'is' for literal comparisons",
                                        SeverityLevel.MEDIUM
                                    ))
                    self.generic_visit(node)
                
                def visit_Try(self, node):
                    # Check for bare except clauses
                    for handler in node.handlers:
                        if handler.type is None:
                            self.issues.append((
                                handler.lineno,
                                "Avoid bare except clauses",
                                SeverityLevel.HIGH
                            ))
                    self.generic_visit(node)
            
            visitor = PatternVisitor()
            visitor.visit(tree)
            
            for line, msg, severity in visitor.issues:
                findings.append(AnalysisFinding(
                    type=AnalysisType.PATTERN,
                    severity=severity,
                    message=msg,
                    location=CodeLocation(
                        file=file_path,
                        line_start=line
                    )
                ))
        except Exception as e:
            print(f"Pattern analysis failed: {str(e)}")
        
        return findings
    
    def _symbolic_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform basic symbolic execution analysis."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
            
            class SymbolicVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.issues = []
                
                def visit_BinOp(self, node):
                    # Check for potential division by zero
                    if isinstance(node.op, ast.Div):
                        if isinstance(node.right, ast.Constant) and node.right.value == 0:
                            self.issues.append((
                                node.lineno,
                                "Division by zero detected"
                            ))
                    self.generic_visit(node)
                
                def visit_Subscript(self, node):
                    # Check for potential index errors
                    if isinstance(node.slice, ast.Constant):
                        if isinstance(node.slice.value, int) and node.slice.value < 0:
                            self.issues.append((
                                node.lineno,
                                "Negative index access might cause IndexError"
                            ))
                    self.generic_visit(node)
            
            visitor = SymbolicVisitor()
            visitor.visit(tree)
            
            for line, msg in visitor.issues:
                findings.append(AnalysisFinding(
                    type=AnalysisType.SYMBOLIC,
                    severity=SeverityLevel.HIGH,
                    message=msg,
                    location=CodeLocation(
                        file=file_path,
                        line_start=line
                    )
                ))
        except Exception as e:
            print(f"Symbolic analysis failed: {str(e)}")
        
        return findings
    
    def _taint_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform taint analysis for security vulnerabilities."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
            
            class TaintVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.issues = []
                    self.taint_sources = {
                        'input', 'request', 'get', 'post',
                        'files', 'cookies', 'headers'
                    }
                    self.dangerous_sinks = {
                        'eval', 'exec', 'os.system', 'subprocess.run',
                        'subprocess.Popen', 'open'
                    }
                
                def visit_Call(self, node):
                    # Check for direct use of tainted data in dangerous sinks
                    func_name = ''
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                    
                    if func_name in self.dangerous_sinks:
                        self.issues.append((
                            node.lineno,
                            f"Potential security vulnerability: {func_name} might be called with tainted data"
                        ))
                    
                    self.generic_visit(node)
            
            visitor = TaintVisitor()
            visitor.visit(tree)
            
            for line, msg in visitor.issues:
                findings.append(AnalysisFinding(
                    type=AnalysisType.TAINT,
                    severity=SeverityLevel.CRITICAL,
                    message=msg,
                    location=CodeLocation(
                        file=file_path,
                        line_start=line
                    ),
                    fix_suggestions=[
                        "Sanitize input data before using it in sensitive operations",
                        "Use safe alternatives to dangerous functions",
                        "Implement proper input validation"
                    ]
                ))
        except Exception as e:
            print(f"Taint analysis failed: {str(e)}")
        
        return findings
    
    def _lexical_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform lexical analysis."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            import tokenize
            from io import StringIO
            
            # Track various lexical issues
            line_lengths = []
            indentation_levels = set()
            string_delimiter_types = set()
            
            for tok in tokenize.generate_tokens(StringIO(content).readline):
                token_type = tok.type
                token_string = tok.string
                start_line, start_col = tok.start
                
                # Check line length
                if len(token_string) > 79:  # PEP 8 line length limit
                    findings.append(AnalysisFinding(
                        type=AnalysisType.LEXICAL,
                        severity=SeverityLevel.LOW,
                        message=f"Line exceeds recommended length of 79 characters",
                        location=CodeLocation(
                            file=file_path,
                            line_start=start_line,
                            column_start=start_col
                        )
                    ))
                
                # Check indentation consistency
                if token_type == tokenize.INDENT:
                    indentation_levels.add(len(token_string))
                
                # Check string delimiter consistency
                if token_type == tokenize.STRING:
                    if token_string.startswith("'"):
                        string_delimiter_types.add("single")
                    elif token_string.startswith('"'):
                        string_delimiter_types.add("double")
            
            # Report inconsistent indentation
            if len(indentation_levels) > 1:
                findings.append(AnalysisFinding(
                    type=AnalysisType.LEXICAL,
                    severity=SeverityLevel.MEDIUM,
                    message="Inconsistent indentation detected",
                    location=CodeLocation(
                        file=file_path,
                        line_start=1
                    ),
                    fix_suggestions=["Use consistent indentation (preferably 4 spaces)"]
                ))
            
            # Report inconsistent string delimiters
            if len(string_delimiter_types) > 1:
                findings.append(AnalysisFinding(
                    type=AnalysisType.LEXICAL,
                    severity=SeverityLevel.LOW,
                    message="Inconsistent string delimiters (mixed use of single and double quotes)",
                    location=CodeLocation(
                        file=file_path,
                        line_start=1
                    ),
                    fix_suggestions=["Use consistent string delimiters throughout the code"]
                ))
        
        except Exception as e:
            print(f"Lexical analysis failed: {str(e)}")
        
        return findings
    
    def _memory_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform memory leak analysis."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
            
            class MemoryVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.issues = []
                    self.resource_types = {
                        'open': 'file handle',
                        'socket': 'socket connection',
                        'Lock': 'threading lock',
                        'connect': 'database connection'
                    }
                
                def visit_With(self, node):
                    # Track proper resource management
                    self.generic_visit(node)
                
                def visit_Call(self, node):
                    # Check for resource allocation without proper cleanup
                    func_name = ''
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    
                    if func_name in self.resource_types:
                        # Check if the call is not within a with statement
                        parent = node
                        while hasattr(parent, 'parent'):
                            if isinstance(parent, ast.With):
                                break
                            parent = parent.parent
                        else:
                            self.issues.append((
                                node.lineno,
                                f"Potential resource leak: {self.resource_types[func_name]} not managed with context manager"
                            ))
                    
                    self.generic_visit(node)
            
            visitor = MemoryVisitor()
            visitor.visit(tree)
            
            for line, msg in visitor.issues:
                findings.append(AnalysisFinding(
                    type=AnalysisType.MEMORY,
                    severity=SeverityLevel.HIGH,
                    message=msg,
                    location=CodeLocation(
                        file=file_path,
                        line_start=line
                    ),
                    fix_suggestions=[
                        "Use 'with' statement for proper resource management",
                        "Ensure resources are properly closed after use",
                        "Implement proper cleanup in try-finally blocks"
                    ]
                ))
        except Exception as e:
            print(f"Memory analysis failed: {str(e)}")
        
        return findings
    
    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map tool-specific severity levels to our standardized levels."""
        severity = severity.lower()
        if severity in ('critical', 'high'):
            return SeverityLevel.HIGH
        elif severity in ('medium', 'moderate'):
            return SeverityLevel.MEDIUM
        elif severity in ('low', 'minor'):
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def analyze_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, AnalysisResult]:
        """Analyze all Python files in a directory."""
        if not os.path.isdir(directory_path):
            return {"error": AnalysisResult(errors=[f"Directory not found: {directory_path}"])}
        
        results = {}
        pattern = '**/*.py' if recursive else '*.py'
        
        for file_path in Path(directory_path).glob(pattern):
            if any(p in str(file_path) for p in self.config.ignore_patterns):
                continue
            results[str(file_path)] = self.analyze_file(str(file_path))
        
        return results


if __name__ == "__main__":
    # Simple CLI for testing
    if len(sys.argv) < 2:
        print("Usage: python python_analyzer.py <file_or_directory_path>")
        sys.exit(1)
        
    path = sys.argv[1]
    analyzer = PythonAnalyzer()
    
    if os.path.isfile(path):
        results = analyzer.analyze_file(path)
    elif os.path.isdir(path):
        results = analyzer.analyze_directory(path)
    else:
        print(f"Error: {path} is not a valid file or directory")
        sys.exit(1)
        
    print(json.dumps(results, indent=2)) 