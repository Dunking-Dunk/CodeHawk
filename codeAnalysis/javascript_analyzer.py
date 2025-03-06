import os
import sys
import json
import subprocess
import shutil
import tempfile
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

class JavaScriptAnalyzer:
    """
    Enhanced JavaScript code analyzer that performs comprehensive code analysis
    including syntax, data flow, control flow, and other advanced analyses.
    """
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize all required analysis tools."""
        # Store npm directory for locally installed tools
        self.npm_bin_path = None
        try:
            if os.name == 'nt':  # Windows
                # Get npm prefix path
                result = subprocess.run(
                    ["npm", "prefix", "-g"],
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=True
                )
                if result.returncode == 0:
                    prefix = result.stdout.strip()
                    # On Windows, global installations usually go to /node_modules/.bin
                    self.npm_global_bin_path = os.path.join(prefix, "node_modules", ".bin")
                
                # Also try to get the local npm bin path
                result = subprocess.run(
                    ["npm", "bin"],
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=True
                )
                if result.returncode == 0:
                    self.npm_bin_path = result.stdout.strip()
            else:
                # For non-Windows systems
                result = subprocess.run(
                    ["npm", "bin", "-g"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if result.returncode == 0:
                    self.npm_global_bin_path = result.stdout.strip()
                
                result = subprocess.run(
                    ["npm", "bin"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if result.returncode == 0:
                    self.npm_bin_path = result.stdout.strip()
        except Exception as e:
            print(f"Failed to determine npm bin paths: {str(e)}")
        
        self.tools = {
            "eslint": self._check_tool("eslint"),
            "jshint": self._check_tool("jshint"),
            "flow": self._check_tool("flow"),
            "complexity-report": self._check_tool("cr"),
            "retire": self._check_tool("retire")
        }
        
        # Try to install missing tools
        for tool, available in self.tools.items():
            if not available:
                self._install_tool(tool)
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH or in npm bin directories."""
        # First check regular PATH
        if shutil.which(tool_name):
            return True
        
        # Then check in npm global bin directory
        if hasattr(self, 'npm_global_bin_path') and self.npm_global_bin_path:
            tool_path = os.path.join(self.npm_global_bin_path, tool_name)
            if os.path.isfile(tool_path) or os.path.isfile(tool_path + '.cmd'):  # Windows uses .cmd files
                return True
        
        # Then check in npm local bin directory
        if hasattr(self, 'npm_bin_path') and self.npm_bin_path:
            tool_path = os.path.join(self.npm_bin_path, tool_name)
            if os.path.isfile(tool_path) or os.path.isfile(tool_path + '.cmd'):
                return True
        
        return False

    def _get_tool_path(self, tool_name: str) -> str:
        """Get the full path to a tool executable."""
        # First check regular PATH
        path = shutil.which(tool_name)
        if path:
            return path
        
        # Then check in npm global bin directory
        if hasattr(self, 'npm_global_bin_path') and self.npm_global_bin_path:
            tool_path = os.path.join(self.npm_global_bin_path, tool_name)
            cmd_path = tool_path + '.cmd'  # Windows uses .cmd files
            if os.path.isfile(tool_path):
                return tool_path
            elif os.path.isfile(cmd_path):
                return cmd_path
        
        # Then check in npm local bin directory
        if hasattr(self, 'npm_bin_path') and self.npm_bin_path:
            tool_path = os.path.join(self.npm_bin_path, tool_name)
            cmd_path = tool_path + '.cmd'
            if os.path.isfile(tool_path):
                return tool_path
            elif os.path.isfile(cmd_path):
                return cmd_path
        
        # Return just the tool name as a fallback
        return tool_name
    
    def _install_tool(self, tool_name: str):
        """Try to install a missing tool."""
        try:
            # Map tool names to npm package names if different
            tool_to_package = {
                "cr": "complexity-report",
                "eslint": "eslint",
                "jshint": "jshint",
                "flow": "flow-bin",  # Use flow-bin package for flow
                # Add more mappings as needed
            }
            
            package_name = tool_to_package.get(tool_name, tool_name)
            
            # Check if npm is available
            npm_exists = bool(shutil.which("npm"))
            if not npm_exists:
                print(f"Warning: Cannot install {tool_name}. npm not found in PATH. JavaScript analysis may be limited.")
                return
            
            # For Windows, try local installation first as it's more reliable
            is_windows = os.name == 'nt'
            if is_windows:
                # Create a local node_modules directory if needed
                cwd = os.getcwd()
                node_modules_path = os.path.join(cwd, "node_modules")
                if not os.path.exists(node_modules_path):
                    os.makedirs(node_modules_path, exist_ok=True)
                
                # Try local installation first
                install_cmd = ["npm", "install", package_name]
                
                print(f"Installing {package_name} locally...")
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=True
                )
                
                if result.returncode == 0:
                    print(f"Successfully installed {package_name} locally")
                    # Update npm bin path and check tool again
                    npm_bin_result = subprocess.run(
                        ["npm", "bin"],
                        capture_output=True,
                        text=True,
                        check=False,
                        shell=True
                    )
                    if npm_bin_result.returncode == 0:
                        self.npm_bin_path = npm_bin_result.stdout.strip()
                        if self._check_tool(tool_name):
                            self.tools[tool_name] = True
                            return
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    print(f"Failed to install {package_name} locally: {error_msg}")
                
                    # Try global installation as a fallback
                    install_cmd = ["npm", "install", "-g", package_name]
                    print(f"Attempting global installation of {package_name}...")
                    result = subprocess.run(
                        install_cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                        shell=True
                    )
                    
                    if result.returncode == 0:
                        print(f"Successfully installed {package_name} globally")
                        # Update global npm bin path and check tool again
                        npm_prefix_result = subprocess.run(
                            ["npm", "prefix", "-g"],
                            capture_output=True,
                            text=True,
                            check=False,
                            shell=True
                        )
                        if npm_prefix_result.returncode == 0:
                            prefix = npm_prefix_result.stdout.strip()
                            self.npm_global_bin_path = os.path.join(prefix, "node_modules", ".bin")
                            if self._check_tool(tool_name):
                                self.tools[tool_name] = True
                    else:
                        error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                        print(f"Failed to install {package_name} globally: {error_msg}")
            else:
                # For non-Windows systems, try global installation first
                install_cmd = ["npm", "install", "-g", package_name]
                
                print(f"Installing {package_name} globally...")
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode != 0:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    print(f"Failed to install {package_name} globally: {error_msg}")
                    # Try local installation if global fails
                    print(f"Attempting local installation of {package_name}...")
                    install_cmd = ["npm", "install", package_name]
                    result = subprocess.run(
                        install_cmd,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode == 0:
                        print(f"Successfully installed {package_name} locally")
                        # Update npm bin path and check tool again
                        npm_bin_result = subprocess.run(
                            ["npm", "bin"],
                            capture_output=True,
                            text=True,
                            check=False
                        )
                        if npm_bin_result.returncode == 0:
                            self.npm_bin_path = npm_bin_result.stdout.strip()
                            if self._check_tool(tool_name):
                                self.tools[tool_name] = True
                    else:
                        error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                        print(f"Failed to install {package_name} locally: {error_msg}")
                else:
                    print(f"Successfully installed {package_name} globally")
                    # Update global npm bin path and check tool again
                    npm_bin_result = subprocess.run(
                        ["npm", "bin", "-g"],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    if npm_bin_result.returncode == 0:
                        self.npm_global_bin_path = npm_bin_result.stdout.strip()
                        if self._check_tool(tool_name):
                            self.tools[tool_name] = True
                
        except Exception as e:
            print(f"Failed to install {tool_name}: {str(e)}")
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """
        Perform comprehensive analysis on a JavaScript file.
        
        Args:
            file_path: Path to the JavaScript file to analyze
            
        Returns:
            AnalysisResult object containing all findings
        """
        # Skip non-JavaScript files
        if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            return AnalysisResult(
                findings=[],
                summary={"skipped": 1},
                errors=[f"Skipped non-JavaScript file: {file_path}"]
            )
        
        # Check if file exists
        if not os.path.exists(file_path):
            return AnalysisResult(
                findings=[],
                summary={"error": 1},
                errors=[f"File not found: {file_path}"]
            )
        
        findings = []
        errors = []
        
        # Try to run each type of analysis, continuing even if some fail
        try:
            findings.extend(self._syntax_analysis(file_path))
        except Exception as e:
            errors.append(f"Syntax analysis failed: {str(e)}")
        
        try:
            findings.extend(self._data_flow_analysis(file_path))
        except Exception as e:
            errors.append(f"Data flow analysis failed: {str(e)}")
        
        try:
            findings.extend(self._control_flow_analysis(file_path))
        except Exception as e:
            errors.append(f"Control flow analysis failed: {str(e)}")
        
        try:
            findings.extend(self._metrics_analysis(file_path))
        except Exception as e:
            errors.append(f"Metrics analysis failed: {str(e)}")
        
        try:
            findings.extend(self._rule_based_analysis(file_path))
        except Exception as e:
            errors.append(f"Rule-based analysis failed: {str(e)}")
        
        try:
            findings.extend(self._pattern_analysis(file_path))
        except Exception as e:
            errors.append(f"Pattern analysis failed: {str(e)}")
        
        try:
            findings.extend(self._symbolic_analysis(file_path))
        except Exception as e:
            errors.append(f"Symbolic analysis failed: {str(e)}")
        
        try:
            findings.extend(self._taint_analysis(file_path))
        except Exception as e:
            errors.append(f"Taint analysis failed: {str(e)}")
        
        try:
            findings.extend(self._lexical_analysis(file_path))
        except Exception as e:
            errors.append(f"Lexical analysis failed: {str(e)}")
        
        try:
            findings.extend(self._memory_analysis(file_path))
        except Exception as e:
            errors.append(f"Memory analysis failed: {str(e)}")
        
        # Create summary by severity and type
        summary = {}
        for finding in findings:
            # Count by severity
            severity = finding.severity.value
            summary[severity] = summary.get(severity, 0) + 1
            
            # Count by type
            analysis_type = finding.type.value
            summary[analysis_type] = summary.get(analysis_type, 0) + 1
        
        # Add error count to summary if there were errors
        if errors:
            summary["errors"] = len(errors)
        
        return AnalysisResult(
            findings=findings,
            summary=summary,
            errors=errors
        )
    
    def _syntax_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform syntax analysis using ESLint."""
        findings = []
        
        if self.tools["eslint"]:
            eslint_path = self._get_tool_path("eslint")
            cmd = [eslint_path, "--format=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for file_result in data:
                        for message in file_result.get("messages", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYNTAX,
                                severity=self._map_severity(message.get("severity", 1)),
                                message=message.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("column", 1)
                                ),
                                rule_id=message.get("ruleId"),
                                fix_suggestions=[message.get("fix", {}).get("text", "")]
                            ))
            except Exception as e:
                print(f"ESLint analysis failed: {str(e)}")
        
        return findings
    
    def _data_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform data flow analysis using Flow."""
        findings = []
        
        if self.tools["flow"]:
            flow_path = self._get_tool_path("flow")
            cmd = [flow_path, "check", "--json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for error in data.get("errors", []):
                        for message in error.get("message", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.DATA_FLOW,
                                severity=SeverityLevel.MEDIUM,
                                message=message.get("descr", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("start", 1),
                                    column_end=message.get("end", 1)
                                )
                            ))
            except Exception as e:
                print(f"Flow analysis failed: {str(e)}")
        
        return findings
    
    def _control_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform control flow analysis using ESLint rules."""
        findings = []
        
        if self.tools["eslint"]:
            eslint_path = self._get_tool_path("eslint")
            # Use ESLint rules specific to control flow
            cmd = [eslint_path, "--format=json", "--rule", "no-unreachable:error", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for file_result in data:
                        for message in file_result.get("messages", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.CONTROL_FLOW,
                                severity=SeverityLevel.HIGH,
                                message=message.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("column", 1)
                                ),
                                rule_id=message.get("ruleId")
                            ))
            except Exception as e:
                print(f"Control flow analysis failed: {str(e)}")
        
        return findings
    
    def _metrics_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform metrics-based analysis using complexity-report."""
        findings = []
        
        if self.tools["complexity-report"]:
            cr_path = self._get_tool_path("cr")
            cmd = [cr_path, "--format=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for func in data.get("functions", []):
                        if func.get("cyclomatic", 0) > 10:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.METRICS,
                                severity=SeverityLevel.MEDIUM,
                                message=f"High cyclomatic complexity ({func['cyclomatic']}) in function {func.get('name', 'anonymous')}",
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=func.get("line", 1)
                                ),
                                fix_suggestions=[
                                    "Break down the function into smaller functions",
                                    "Reduce nested conditionals",
                                    "Use early returns"
                                ]
                            ))
            except Exception as e:
                print(f"Metrics analysis failed: {str(e)}")
        
        return findings
    
    def _rule_based_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform rule-based analysis using JSHint."""
        findings = []
        
        if self.tools["jshint"]:
            jshint_path = self._get_tool_path("jshint")
            cmd = [jshint_path, "--reporter=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for error in data:
                        findings.append(AnalysisFinding(
                            type=AnalysisType.RULE_BASED,
                            severity=self._map_severity(error.get("code", "")),
                            message=error.get("reason", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=error.get("line", 1),
                                column_start=error.get("character", 1)
                            ),
                            rule_id=error.get("code")
                        ))
            except Exception as e:
                print(f"JSHint analysis failed: {str(e)}")
        
        return findings
    
    def _pattern_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform pattern-based analysis using ESLint rules."""
        findings = []
        
        if self.tools["eslint"]:
            eslint_path = self._get_tool_path("eslint")
            # Use ESLint rules for common patterns
            pattern_rules = {
                "no-with": "error",
                "no-eval": "error",
                "no-implied-eval": "error",
                "no-param-reassign": "error"
            }
            
            cmd = [eslint_path, "--format=json"]
            for rule, level in pattern_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for file_result in data:
                        for message in file_result.get("messages", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.PATTERN,
                                severity=SeverityLevel.HIGH,
                                message=message.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("column", 1)
                                ),
                                rule_id=message.get("ruleId")
                            ))
            except Exception as e:
                print(f"Pattern analysis failed: {str(e)}")
        
        return findings
    
    def _symbolic_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform symbolic analysis using ESLint rules."""
        findings = []
        
        if self.tools["eslint"]:
            eslint_path = self._get_tool_path("eslint")
            # Use ESLint rules for potential runtime errors
            symbolic_rules = {
                "no-unsafe-negation": "error",
                "no-unsafe-optional-chaining": "error",
                "no-unsafe-finally": "error",
                "no-self-compare": "error"
            }
            
            cmd = [eslint_path, "--format=json"]
            for rule, level in symbolic_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for file_result in data:
                        for message in file_result.get("messages", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYMBOLIC,
                                severity=SeverityLevel.HIGH,
                                message=message.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("column", 1)
                                ),
                                rule_id=message.get("ruleId")
                            ))
            except Exception as e:
                print(f"Symbolic analysis failed: {str(e)}")
        
        return findings
    
    def _taint_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform taint analysis for security vulnerabilities."""
        findings = []
        
        if self.tools["eslint"]:
            eslint_path = self._get_tool_path("eslint")
            # Use ESLint security rules
            security_rules = {
                "no-eval": "error",
                "no-implied-eval": "error",
                "security/detect-non-literal-regexp": "error",
                "security/detect-unsafe-regex": "error",
                "security/detect-buffer-noassert": "error",
                "security/detect-child-process": "error",
                "security/detect-disable-mustache-escape": "error",
                "security/detect-eval-with-expression": "error",
                "security/detect-no-csrf-before-method-override": "error",
                "security/detect-non-literal-fs-filename": "error",
                "security/detect-pseudoRandomBytes": "error",
                "security/detect-possible-timing-attacks": "error"
            }
            
            cmd = [eslint_path, "--format=json"]
            for rule, level in security_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for file_result in data:
                        for message in file_result.get("messages", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.TAINT,
                                severity=SeverityLevel.CRITICAL,
                                message=message.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("column", 1)
                                ),
                                rule_id=message.get("ruleId")
                            ))
            except Exception as e:
                print(f"Taint analysis failed: {str(e)}")
        
        return findings
    
    def _lexical_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform lexical analysis using JSHint."""
        findings = []
        
        if self.tools["jshint"]:
            jshint_path = self._get_tool_path("jshint")
            # Focus on lexical issues
            lexical_rules = {
                "asi": False,  # Enforce semicolons
                "curly": True,  # Require curly braces for loops and conditionals
                "eqeqeq": True,  # Require === and !==
                "forin": True,  # Require hasOwnProperty checks in for-in loops
                "noarg": True,  # Prohibit use of arguments.caller and arguments.callee
                "noempty": True,  # Prohibit empty blocks
                "nonew": True,  # Prohibit use of constructors for side-effects
                "undef": True,  # Require variables to be declared
                "unused": True  # Warn about unused variables
            }
            
            # Convert Python booleans to JSON booleans
            json_rules = {}
            for key, value in lexical_rules.items():
                if value is True:
                    json_rules[key] = "true"
                elif value is False:
                    json_rules[key] = "false"
                else:
                    json_rules[key] = value
            
            # Create a temporary .jshintrc file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                json.dump(json_rules, tmp)
                tmp_path = tmp.name
            
            try:
                cmd = [jshint_path, "--config", tmp_path, "--reporter=json", file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for error in data:
                        findings.append(AnalysisFinding(
                            type=AnalysisType.LEXICAL,
                            severity=self._map_severity(error.get("code", "")),
                            message=error.get("reason", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=error.get("line", 1),
                                column_start=error.get("character", 1)
                            ),
                            rule_id=error.get("code")
                        ))
            except Exception as e:
                print(f"Lexical analysis failed: {str(e)}")
            finally:
                # Clean up the temporary file
                os.unlink(tmp_path)
        
        return findings
    
    def _memory_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform memory usage analysis using ESLint rules."""
        findings = []
        
        if self.tools["eslint"]:
            eslint_path = self._get_tool_path("eslint")
            # Rules related to memory leaks and usage
            memory_rules = {
                "no-global-assign": "error",
                "no-extend-native": "error",
                "no-extra-bind": "error",
                "no-implicit-globals": "error",
                "no-this-before-super": "error",
                "no-unused-vars": "error",
                "no-use-before-define": "error",
                "no-useless-call": "error",
                "no-useless-concat": "error"
            }
            
            cmd = [eslint_path, "--format=json"]
            for rule, level in memory_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=(os.name == 'nt'))
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for file_result in data:
                        for message in file_result.get("messages", []):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.MEMORY,
                                severity=SeverityLevel.MEDIUM,
                                message=message.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=message.get("line", 1),
                                    column_start=message.get("column", 1)
                                ),
                                rule_id=message.get("ruleId")
                            ))
            except Exception as e:
                print(f"Memory analysis failed: {str(e)}")
        
        return findings
    
    def _map_severity(self, severity: Union[str, int]) -> SeverityLevel:
        """Map tool-specific severity levels to our standardized levels."""
        if isinstance(severity, str):
            severity = severity.lower()
            if severity in ('critical', 'high', 'error'):
                return SeverityLevel.HIGH
            elif severity in ('medium', 'moderate', 'warning'):
                return SeverityLevel.MEDIUM
            elif severity in ('low', 'minor', 'info'):
                return SeverityLevel.LOW
            else:
                return SeverityLevel.INFO
        else:
            # ESLint uses 2 for error, 1 for warning
            if severity == 2:
                return SeverityLevel.HIGH
            elif severity == 1:
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW
    
    def analyze_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, AnalysisResult]:
        """Analyze all JavaScript files in a directory."""
        if not os.path.isdir(directory_path):
            return {"error": AnalysisResult(errors=[f"Directory not found: {directory_path}"])}
        
        results = {}
        pattern = '**/*.{js,jsx,ts,tsx}' if recursive else '*.{js,jsx,ts,tsx}'
        
        for file_path in Path(directory_path).glob(pattern):
            if any(p in str(file_path) for p in self.config.ignore_patterns):
                continue
            results[str(file_path)] = self.analyze_file(str(file_path))
        
        return results


if __name__ == "__main__":
    # Simple CLI for testing
    if len(sys.argv) < 2:
        print("Usage: python javascript_analyzer.py <file_or_directory_path>")
        sys.exit(1)
    
    path = sys.argv[1]
    analyzer = JavaScriptAnalyzer()
    
    if os.path.isfile(path):
        results = analyzer.analyze_file(path)
    elif os.path.isdir(path):
        results = analyzer.analyze_directory(path)
    else:
        print(f"Error: {path} is not a valid file or directory")
        sys.exit(1)
    
    print(json.dumps(results, indent=2)) 