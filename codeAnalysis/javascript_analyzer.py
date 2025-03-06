import os
import sys
import json
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
        """Check if a tool is available in PATH."""
        return bool(shutil.which(tool_name))
    
    def _install_tool(self, tool_name: str):
        """Attempt to install a missing tool."""
        try:
            subprocess.run(
                ["npm", "install", "-g", tool_name],
                check=True,
                capture_output=True
            )
            self.tools[tool_name] = True
        except Exception as e:
            print(f"Failed to install {tool_name}: {str(e)}")
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single JavaScript file using all available analysis types."""
        if not os.path.exists(file_path):
            return AnalysisResult(errors=[f"File not found: {file_path}"])
        
        if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            return AnalysisResult(errors=[f"Not a JavaScript/TypeScript file: {file_path}"])
        
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
        """Perform syntax analysis using ESLint."""
        findings = []
        
        if self.tools["eslint"]:
            cmd = ["eslint", "--format=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            cmd = ["flow", "check", "--json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            # Use ESLint rules specific to control flow
            cmd = ["eslint", "--format=json", "--rule", "no-unreachable:error", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            cmd = ["cr", "--format=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            cmd = ["jshint", "--reporter=json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            # Use ESLint rules for common patterns
            pattern_rules = {
                "no-with": "error",
                "no-eval": "error",
                "no-implied-eval": "error",
                "no-param-reassign": "error"
            }
            
            cmd = ["eslint", "--format=json"]
            for rule, level in pattern_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            # Use ESLint rules for potential runtime errors
            symbolic_rules = {
                "no-unsafe-negation": "error",
                "no-unsafe-optional-chaining": "error",
                "no-unsafe-finally": "error",
                "no-self-compare": "error"
            }
            
            cmd = ["eslint", "--format=json"]
            for rule, level in symbolic_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            # Use ESLint security rules
            security_rules = {
                "no-eval": "error",
                "no-implied-eval": "error",
                "security/detect-non-literal-regexp": "error",
                "security/detect-unsafe-regex": "error",
                "security/detect-buffer-noassert": "error"
            }
            
            cmd = ["eslint", "--format=json"]
            for rule, level in security_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
                            rule_id=message.get("ruleId"),
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
        """Perform lexical analysis using ESLint style rules."""
        findings = []
        
        if self.tools["eslint"]:
            # Use ESLint style rules
            style_rules = {
                "indent": ["error", 2],
                "linebreak-style": ["error", "unix"],
                "quotes": ["error", "single"],
                "semi": ["error", "always"],
                "max-len": ["error", {"code": 80}]
            }
            
            cmd = ["eslint", "--format=json"]
            for rule, config in style_rules.items():
                cmd.extend(["--rule", f"{rule}:{json.dumps(config)}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for file_result in data:
                    for message in file_result.get("messages", []):
                        findings.append(AnalysisFinding(
                            type=AnalysisType.LEXICAL,
                            severity=SeverityLevel.LOW,
                            message=message.get("message", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=message.get("line", 1),
                                column_start=message.get("column", 1)
                            ),
                            rule_id=message.get("ruleId")
                        ))
            except Exception as e:
                print(f"Lexical analysis failed: {str(e)}")
        
        return findings
    
    def _memory_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform memory leak analysis."""
        findings = []
        
        if self.tools["eslint"]:
            # Use ESLint rules for memory leaks
            memory_rules = {
                "no-unused-vars": "error",
                "no-undef": "error",
                "no-global-assign": "error",
                "no-shadow": "error"
            }
            
            cmd = ["eslint", "--format=json"]
            for rule, level in memory_rules.items():
                cmd.extend(["--rule", f"{rule}:{level}"])
            cmd.append(file_path)
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
                            rule_id=message.get("ruleId"),
                            fix_suggestions=[
                                "Clean up unused variables",
                                "Use proper variable scoping",
                                "Avoid memory leaks in closures"
                            ]
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