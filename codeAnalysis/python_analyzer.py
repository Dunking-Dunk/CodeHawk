import os
import sys
import json
import ast
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass

# Fix imports to handle both package and direct imports
try:
    from .models.analysis_models import (
        AnalysisResult, AnalysisFinding, CodeLocation,
        SeverityLevel, AnalysisType, AnalysisConfig
    )
except ImportError:
    try:
        from models.analysis_models import (
            AnalysisResult, AnalysisFinding, CodeLocation,
            SeverityLevel, AnalysisType, AnalysisConfig
        )
    except ImportError:
        from codeAnalysis.models.analysis_models import (
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
        """Try to install a missing tool using pip."""
        try:
            # Map tool names to pip package names if different
            tool_to_package = {
                "prospector": "prospector[with_everything]",
                # Add more mappings if needed
            }
            
            package_name = tool_to_package.get(tool_name, tool_name)
            
            # Check if pip is available
            pip_cmd = [sys.executable, "-m", "pip"]
            try:
                subprocess.run(
                    pip_cmd + ["--version"],
                    check=True,
                    capture_output=True,
                    text=True
                )
            except (subprocess.SubprocessError, FileNotFoundError):
                print(f"Warning: Cannot install {tool_name}. pip not available. Python analysis may be limited.")
                return
            
            print(f"Installing {package_name}...")
            result = subprocess.run(
                pip_cmd + ["install", package_name],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                print(f"Successfully installed {package_name}")
                self.tools[tool_name] = True
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print(f"Failed to install {package_name}: {error_msg}")
                
                # Try with --user flag if permission error
                if "Permission denied" in error_msg or "Access is denied" in error_msg:
                    print(f"Trying to install {package_name} with --user flag...")
                    result = subprocess.run(
                        pip_cmd + ["install", "--user", package_name],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode == 0:
                        print(f"Successfully installed {package_name} with --user flag")
                        self.tools[tool_name] = True
                    else:
                        error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                        print(f"Failed to install {package_name} with --user flag: {error_msg}")
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
        """Analyze data flow issues with tools like mypy."""
        findings = []
        
        # Run mypy for type checking (which helps find data flow issues)
        if self.tools["mypy"]:
            try:
                cmd = ["mypy", "--show-column-numbers", file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                # Process mypy output
                for line in result.stdout.splitlines():
                    # Parse mypy output format: file:line:column: severity: message
                    parts = line.split(":", 4)
                    if len(parts) >= 5:
                        try:
                            if parts[0] == file_path:  # Make sure it's for our file
                                line_num = int(parts[1])
                                col_num = int(parts[2]) if parts[2].strip().isdigit() else 0
                                severity_text = parts[3].strip()
                                msg = parts[4].strip()
                                
                                # Map severity
                                severity = SeverityLevel.MEDIUM
                                if "error" in severity_text.lower():
                                    severity = SeverityLevel.HIGH
                                
                                findings.append(AnalysisFinding(
                                    type=AnalysisType.DATA_FLOW,
                                    severity=severity,
                                    message=f"Type check issue: {msg}",
                                    location=CodeLocation(
                                        file=file_path,
                                        line_start=line_num,
                                        column_start=col_num
                                    ),
                                    rule_id="MYPY"
                                ))
                        except (ValueError, IndexError) as e:
                            print(f"MyPy analysis parsing error on line: {line} - {str(e)}")
                
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
        """Analyze code metrics like complexity, maintainability, etc."""
        findings = []
        
        # Run radon to calculate maintainability index
        try:
            # Call radon mi on the file
            cmd = ["radon", "mi", file_path, "-s"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                # Parse the maintainability index
                for line in result.stdout.splitlines():
                    if " - " in line:
                        parts = line.split(" - ")
                        if len(parts) >= 2:
                            file_info = parts[0].strip()
                            mi_score_text = parts[1].strip()
                            
                            try:
                                mi_score = float(mi_score_text.split()[0])  # Extract numeric part
                                severity = SeverityLevel.LOW
                                
                                if mi_score < 20:
                                    severity = SeverityLevel.CRITICAL
                                    message = f"Extremely low maintainability index: {mi_score}"
                                elif mi_score < 40:
                                    severity = SeverityLevel.HIGH
                                    message = f"Very low maintainability index: {mi_score}"
                                elif mi_score < 60:
                                    severity = SeverityLevel.MEDIUM
                                    message = f"Low maintainability index: {mi_score}"
                                else:
                                    continue  # Skip good maintainability scores
                                
                                findings.append(AnalysisFinding(
                                    type=AnalysisType.METRICS,
                                    severity=severity,
                                    message=message,
                                    location=CodeLocation(
                                        file=file_path,
                                        line_start=1  # Maintainability is for the whole file
                                    ),
                                    rule_id="RADON-MI",
                                    additional_info={"mi_score": mi_score}
                                ))
                            except (ValueError, IndexError):
                                print(f"Radon maintainability analysis failed: Invalid score format")
            else:
                print(f"Radon maintainability analysis failed: {result.stderr.strip()}")
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
        """Identify potential security issues from data flow."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                code = f.read()
            
            tree = ast.parse(code, filename=file_path)
            
            # Track tainted variables from inputs
            tainted_sources = {
                'input', 'raw_input',  # Python 2 & 3 input functions
                'request.form', 'request.args', 'request.json', 'request.data',  # Flask/web inputs
                'request.GET', 'request.POST',  # Django inputs
                'readline', 'sys.stdin.read', 'sys.stdin.readline',  # Standard input
                'urlopen', 'open',  # File and URL reading
            }
            
            dangerous_sinks = {
                'eval', 'exec', 'subprocess.call', 'subprocess.Popen', 'os.system',  # Code execution
                'execute', 'executemany',  # SQL execution
                'run', 'shell',  # Shell commands
                'render_template_string',  # Template rendering
            }
            
            class TaintVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.tainted_vars = set()
                    self.findings = []
                
                def get_name(self, node):
                    """Safely extract name from various node types"""
                    try:
                        if isinstance(node, ast.Name):
                            return node.id
                        elif isinstance(node, ast.Attribute):
                            # Handle multi-level attributes like request.form.get
                            parts = []
                            current = node
                            while isinstance(current, ast.Attribute):
                                parts.append(current.attr)
                                current = current.value
                            if isinstance(current, ast.Name):
                                parts.append(current.id)
                            return '.'.join(reversed(parts))
                        elif isinstance(node, ast.Call):
                            return self.get_name(node.func)
                        return None
                    except Exception:
                        return None
                
                def visit_Call(self, node):
                    # Check if this is a tainted source
                    func_name = self.get_name(node.func)
                    if func_name:
                        if func_name in tainted_sources:
                            # Mark the variable as tainted if it's assigned
                            parent = getattr(node, 'parent', None)
                            if isinstance(parent, ast.Assign):
                                for target in parent.targets:
                                    if isinstance(target, ast.Name):
                                        self.tainted_vars.add(target.id)
                        
                        # Check for dangerous sinks with tainted data
                        elif func_name in dangerous_sinks:
                            for arg in node.args:
                                arg_name = self.get_name(arg)
                                if arg_name in self.tainted_vars:
                                    self.findings.append((node, arg_name, func_name))
                    
                    # Continue visiting child nodes
                    self.generic_visit(node)
            
            # Add parent references for better analysis
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child.parent = node
            
            visitor = TaintVisitor()
            visitor.visit(tree)
            
            # Create findings from taint analysis
            for node, tainted_var, sink_name in visitor.findings:
                findings.append(AnalysisFinding(
                    type=AnalysisType.TAINT,
                    severity=SeverityLevel.CRITICAL,
                    message=f"Potential security vulnerability: tainted data from '{tainted_var}' used in dangerous sink '{sink_name}'",
                    location=CodeLocation(
                        file=file_path,
                        line_start=node.lineno,
                        column_start=node.col_offset
                    ),
                    fix_suggestions=[
                        f"Sanitize input from '{tainted_var}' before using it in '{sink_name}'",
                        "Use parameterized queries or prepared statements for database operations",
                        "Use safe APIs that prevent code injection"
                    ],
                    rule_id="TAINT-FLOW"
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