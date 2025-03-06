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

class CppAnalyzer:
    """
    Enhanced C++ code analyzer that performs comprehensive code analysis
    including syntax, data flow, control flow, and other advanced analyses.
    """
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize all required analysis tools."""
        self.tools = {
            "cppcheck": self._check_tool("cppcheck"),
            "clang-tidy": self._check_tool("clang-tidy"),
            "clang-analyzer": self._check_tool("clang-analyzer"),
            "flawfinder": self._check_tool("flawfinder"),
            "vera++": self._check_tool("vera++")
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
            if tool_name == "cppcheck":
                subprocess.run(
                    ["apt-get", "install", "-y", "cppcheck"],
                    check=True,
                    capture_output=True
                )
                self.tools[tool_name] = True
            elif tool_name == "clang-tidy":
                subprocess.run(
                    ["apt-get", "install", "-y", "clang-tidy"],
                    check=True,
                    capture_output=True
                )
                self.tools[tool_name] = True
        except Exception as e:
            print(f"Failed to install {tool_name}: {str(e)}")
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single C++ file using all available analysis types."""
        if not os.path.exists(file_path):
            return AnalysisResult(errors=[f"File not found: {file_path}"])
        
        if not file_path.endswith(('.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp', '.hxx', '.h++')):
            return AnalysisResult(errors=[f"Not a C++ file: {file_path}"])
        
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
        """Perform syntax analysis using clang-tidy."""
        findings = []
        
        if self.tools["clang-tidy"]:
            cmd = ["clang-tidy", "-checks=*", "-export-fixes=/dev/stdout", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse clang-tidy output
                for line in result.stdout.splitlines():
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYNTAX,
                                severity=self._map_severity(parts[3].strip()),
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1]),
                                    column_start=int(parts[2])
                                )
                            ))
            except Exception as e:
                print(f"Clang-tidy analysis failed: {str(e)}")
        
        return findings
    
    def _data_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform data flow analysis using clang-analyzer."""
        findings = []
        
        if self.tools["clang-analyzer"]:
            cmd = ["clang", "--analyze", "-Xanalyzer", "-analyzer-output=text", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if "warning:" in line:
                        parts = line.split(":")
                        if len(parts) >= 3:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.DATA_FLOW,
                                severity=SeverityLevel.MEDIUM,
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1])
                                )
                            ))
            except Exception as e:
                print(f"Clang analyzer failed: {str(e)}")
        
        return findings
    
    def _control_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform control flow analysis using cppcheck."""
        findings = []
        
        if self.tools["cppcheck"]:
            cmd = ["cppcheck", "--enable=all", "--xml", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse cppcheck XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stderr)
                
                for error in root.findall(".//error"):
                    if error.get("severity") in ["error", "warning"]:
                        location = error.find("location")
                        if location is not None:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.CONTROL_FLOW,
                                severity=self._map_severity(error.get("severity", "warning")),
                                message=error.get("msg", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(location.get("line", "1")),
                                    column_start=int(location.get("column", "1"))
                                ),
                                rule_id=error.get("id")
                            ))
            except Exception as e:
                print(f"Control flow analysis failed: {str(e)}")
        
        return findings
    
    def _metrics_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform metrics-based analysis using clang-tidy metrics checks."""
        findings = []
        
        if self.tools["clang-tidy"]:
            cmd = ["clang-tidy", "-checks=readability-*,clang-analyzer-*", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.METRICS,
                                severity=self._map_severity(parts[3].strip()),
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1]),
                                    column_start=int(parts[2])
                                ),
                                fix_suggestions=[
                                    "Break down complex functions",
                                    "Reduce cyclomatic complexity",
                                    "Improve code readability"
                                ]
                            ))
            except Exception as e:
                print(f"Metrics analysis failed: {str(e)}")
        
        return findings
    
    def _rule_based_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform rule-based analysis using vera++."""
        findings = []
        
        if self.tools["vera++"]:
            cmd = ["vera++", "--show-rule", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.RULE_BASED,
                                severity=SeverityLevel.MEDIUM,
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1])
                                ),
                                rule_id=parts[3].strip()
                            ))
            except Exception as e:
                print(f"Rule-based analysis failed: {str(e)}")
        
        return findings
    
    def _pattern_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform pattern-based analysis using clang-tidy pattern checks."""
        findings = []
        
        if self.tools["clang-tidy"]:
            cmd = ["clang-tidy", "-checks=modernize-*,performance-*", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.PATTERN,
                                severity=self._map_severity(parts[3].strip()),
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1]),
                                    column_start=int(parts[2])
                                )
                            ))
            except Exception as e:
                print(f"Pattern analysis failed: {str(e)}")
        
        return findings
    
    def _symbolic_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform symbolic analysis using clang static analyzer."""
        findings = []
        
        if self.tools["clang-analyzer"]:
            cmd = ["clang", "--analyze", "-Xanalyzer", "-analyzer-checker=core", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if "warning:" in line:
                        parts = line.split(":")
                        if len(parts) >= 3:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYMBOLIC,
                                severity=SeverityLevel.HIGH,
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1])
                                )
                            ))
            except Exception as e:
                print(f"Symbolic analysis failed: {str(e)}")
        
        return findings
    
    def _taint_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform taint analysis using flawfinder."""
        findings = []
        
        if self.tools["flawfinder"]:
            cmd = ["flawfinder", "--dataonly", "--quiet", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                for line in result.stdout.splitlines():
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.TAINT,
                                severity=SeverityLevel.CRITICAL,
                                message=parts[-1].strip(),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[1])
                                ),
                                fix_suggestions=[
                                    "Validate input data",
                                    "Use secure functions",
                                    "Implement proper bounds checking"
                                ]
                            ))
            except Exception as e:
                print(f"Taint analysis failed: {str(e)}")
        
        return findings
    
    def _lexical_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform lexical analysis using clang-format."""
        findings = []
        
        cmd = ["clang-format", "-style=file", "-output-replacements-xml", file_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            # Parse clang-format XML output
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result.stdout)
            
            for replacement in root.findall(".//replacement"):
                offset = int(replacement.get("offset", "0"))
                length = int(replacement.get("length", "0"))
                
                # Convert offset to line number (approximate)
                with open(file_path, 'r') as f:
                    content = f.read()
                    line_number = content.count('\n', 0, offset) + 1
                
                findings.append(AnalysisFinding(
                    type=AnalysisType.LEXICAL,
                    severity=SeverityLevel.LOW,
                    message="Style issue detected",
                    location=CodeLocation(
                        file=file_path,
                        line_start=line_number
                    ),
                    fix_suggestions=["Run clang-format to fix style issues"]
                ))
        except Exception as e:
            print(f"Lexical analysis failed: {str(e)}")
        
        return findings
    
    def _memory_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform memory leak analysis using cppcheck memory checks."""
        findings = []
        
        if self.tools["cppcheck"]:
            cmd = ["cppcheck", "--enable=memory,leak", "--xml", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse cppcheck XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stderr)
                
                for error in root.findall(".//error"):
                    if error.get("severity") in ["error", "warning"]:
                        location = error.find("location")
                        if location is not None:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.MEMORY,
                                severity=SeverityLevel.HIGH,
                                message=error.get("msg", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(location.get("line", "1")),
                                    column_start=int(location.get("column", "1"))
                                ),
                                rule_id=error.get("id"),
                                fix_suggestions=[
                                    "Use smart pointers",
                                    "Properly deallocate memory",
                                    "Fix memory leaks"
                                ]
                            ))
            except Exception as e:
                print(f"Memory analysis failed: {str(e)}")
        
        return findings
    
    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map tool-specific severity levels to our standardized levels."""
        severity = severity.lower()
        if severity in ('critical', 'high', 'error'):
            return SeverityLevel.HIGH
        elif severity in ('medium', 'moderate', 'warning'):
            return SeverityLevel.MEDIUM
        elif severity in ('low', 'minor', 'style', 'information'):
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def analyze_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, AnalysisResult]:
        """Analyze all C++ files in a directory."""
        if not os.path.isdir(directory_path):
            return {"error": AnalysisResult(errors=[f"Directory not found: {directory_path}"])}
        
        results = {}
        extensions = ('.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp', '.hxx', '.h++')
        pattern = '**/*[!.]*' if recursive else '*[!.]*'
        
        for file_path in Path(directory_path).glob(pattern):
            if file_path.suffix in extensions and not any(p in str(file_path) for p in self.config.ignore_patterns):
                results[str(file_path)] = self.analyze_file(str(file_path))
        
        return results


if __name__ == "__main__":
    # Simple CLI for testing
    if len(sys.argv) < 2:
        print("Usage: python cpp_analyzer.py <file_or_directory_path> [compilation_db_path] [config_path]")
        sys.exit(1)
    
    path = sys.argv[1]
    compilation_db_path = sys.argv[2] if len(sys.argv) > 2 else None
    config_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    analyzer = CppAnalyzer(config_path)
    
    if os.path.isfile(path):
        results = analyzer.analyze_file(path)
    elif os.path.isdir(path):
        results = analyzer.analyze_directory(path, True)
    else:
        print(f"Error: {path} is not a valid file or directory")
        sys.exit(1)
    
    print(json.dumps(results, indent=2)) 