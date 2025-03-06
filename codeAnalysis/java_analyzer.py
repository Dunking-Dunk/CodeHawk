import os
import sys
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Union, Set
from pathlib import Path
import shutil

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

class JavaAnalyzer:
    """
    Enhanced Java code analyzer that performs comprehensive code analysis
    including syntax, data flow, control flow, and other advanced analyses.
    """
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize all required analysis tools."""
        self.tools = {
            "pmd": self._check_tool("pmd"),
            "spotbugs": self._check_tool("spotbugs"),
            "checkstyle": self._check_tool("checkstyle"),
            "findbugs": self._check_tool("findbugs"),
            "sonar-scanner": self._check_tool("sonar-scanner")
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
            if tool_name == "pmd":
                subprocess.run(
                    ["wget", "https://github.com/pmd/pmd/releases/download/pmd_releases/6.55.0/pmd-bin-6.55.0.zip"],
                    check=True,
                    capture_output=True
                )
                subprocess.run(["unzip", "pmd-bin-6.55.0.zip"], check=True)
                self.tools[tool_name] = True
            elif tool_name == "spotbugs":
                subprocess.run(
                    ["wget", "https://github.com/spotbugs/spotbugs/releases/download/4.7.3/spotbugs-4.7.3.zip"],
                    check=True,
                    capture_output=True
                )
                subprocess.run(["unzip", "spotbugs-4.7.3.zip"], check=True)
                self.tools[tool_name] = True
        except Exception as e:
            print(f"Failed to install {tool_name}: {str(e)}")
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single Java file using all available analysis types."""
        if not os.path.exists(file_path):
            return AnalysisResult(errors=[f"File not found: {file_path}"])
        
        if not file_path.endswith('.java'):
            return AnalysisResult(errors=[f"Not a Java file: {file_path}"])
        
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
        """Perform syntax analysis using PMD."""
        findings = []
        
        if self.tools["pmd"]:
            cmd = ["pmd", "check", "-f", "json", "-R", "rulesets/java/quickstart.xml", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for violation in data.get("files", []):
                    for issue in violation.get("violations", []):
                        findings.append(AnalysisFinding(
                            type=AnalysisType.SYNTAX,
                            severity=self._map_severity(issue.get("priority", 3)),
                            message=issue.get("description", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=issue.get("beginline", 1),
                                line_end=issue.get("endline", 1)
                            ),
                            rule_id=issue.get("rule")
                        ))
            except Exception as e:
                print(f"PMD analysis failed: {str(e)}")
        
        return findings
    
    def _data_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform data flow analysis using SpotBugs."""
        findings = []
        
        if self.tools["spotbugs"]:
            cmd = ["spotbugs", "-textui", "-xml:withMessages", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse SpotBugs XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                for bug in root.findall(".//BugInstance"):
                    source_line = bug.find(".//SourceLine")
                    if source_line is not None:
                        findings.append(AnalysisFinding(
                            type=AnalysisType.DATA_FLOW,
                            severity=self._map_severity(bug.get("priority", "3")),
                            message=bug.find("LongMessage").text,
                            location=CodeLocation(
                                file=file_path,
                                line_start=int(source_line.get("start", "1")),
                                line_end=int(source_line.get("end", "1"))
                            ),
                            rule_id=bug.get("type")
                        ))
            except Exception as e:
                print(f"SpotBugs analysis failed: {str(e)}")
        
        return findings
    
    def _control_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform control flow analysis using PMD control flow rules."""
        findings = []
        
        if self.tools["pmd"]:
            cmd = ["pmd", "check", "-f", "json", "-R", "rulesets/java/design.xml", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for violation in data.get("files", []):
                    for issue in violation.get("violations", []):
                        if "ControlFlow" in issue.get("rule", ""):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.CONTROL_FLOW,
                                severity=self._map_severity(issue.get("priority", 3)),
                                message=issue.get("description", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=issue.get("beginline", 1),
                                    line_end=issue.get("endline", 1)
                                ),
                                rule_id=issue.get("rule")
                            ))
            except Exception as e:
                print(f"Control flow analysis failed: {str(e)}")
        
        return findings
    
    def _metrics_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform metrics-based analysis using PMD metrics rules."""
        findings = []
        
        if self.tools["pmd"]:
            cmd = ["pmd", "check", "-f", "json", "-R", "rulesets/java/metrics.xml", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for violation in data.get("files", []):
                    for issue in violation.get("violations", []):
                        findings.append(AnalysisFinding(
                            type=AnalysisType.METRICS,
                            severity=self._map_severity(issue.get("priority", 3)),
                            message=issue.get("description", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=issue.get("beginline", 1),
                                line_end=issue.get("endline", 1)
                            ),
                            rule_id=issue.get("rule"),
                            fix_suggestions=[
                                "Break down complex methods into smaller ones",
                                "Reduce cyclomatic complexity",
                                "Improve code organization"
                            ]
                        ))
            except Exception as e:
                print(f"Metrics analysis failed: {str(e)}")
        
        return findings
    
    def _rule_based_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform rule-based analysis using Checkstyle."""
        findings = []
        
        if self.tools["checkstyle"]:
            cmd = ["checkstyle", "-f", "json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for file_result in data:
                    for error in file_result.get("errors", []):
                        findings.append(AnalysisFinding(
                            type=AnalysisType.RULE_BASED,
                            severity=self._map_severity(error.get("severity", "error")),
                            message=error.get("message", ""),
                            location=CodeLocation(
                                file=file_path,
                                line_start=error.get("line", 1),
                                column_start=error.get("column", 1)
                            ),
                            rule_id=error.get("source")
                        ))
            except Exception as e:
                print(f"Checkstyle analysis failed: {str(e)}")
        
        return findings
    
    def _pattern_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform pattern-based analysis using FindBugs patterns."""
        findings = []
        
        if self.tools["findbugs"]:
            cmd = ["findbugs", "-textui", "-xml", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse FindBugs XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                for bug in root.findall(".//BugInstance"):
                    if "Pattern" in bug.get("category", ""):
                        source_line = bug.find(".//SourceLine")
                        if source_line is not None:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.PATTERN,
                                severity=self._map_severity(bug.get("priority", "3")),
                                message=bug.find("LongMessage").text,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(source_line.get("start", "1")),
                                    line_end=int(source_line.get("end", "1"))
                                ),
                                rule_id=bug.get("type")
                            ))
            except Exception as e:
                print(f"Pattern analysis failed: {str(e)}")
        
        return findings
    
    def _symbolic_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform symbolic analysis using SpotBugs."""
        findings = []
        
        if self.tools["spotbugs"]:
            cmd = ["spotbugs", "-textui", "-xml:withMessages", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse SpotBugs XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                for bug in root.findall(".//BugInstance"):
                    if "CORRECTNESS" in bug.get("category", ""):
                        source_line = bug.find(".//SourceLine")
                        if source_line is not None:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYMBOLIC,
                                severity=self._map_severity(bug.get("priority", "3")),
                                message=bug.find("LongMessage").text,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(source_line.get("start", "1")),
                                    line_end=int(source_line.get("end", "1"))
                                ),
                                rule_id=bug.get("type")
                            ))
            except Exception as e:
                print(f"Symbolic analysis failed: {str(e)}")
        
        return findings
    
    def _taint_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform taint analysis using FindSecBugs."""
        findings = []
        
        if self.tools["spotbugs"]:
            cmd = ["spotbugs", "-textui", "-xml:withMessages", "-pluginList", "findsecbugs-plugin", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse FindSecBugs XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                for bug in root.findall(".//BugInstance"):
                    if "SECURITY" in bug.get("category", ""):
                        source_line = bug.find(".//SourceLine")
                        if source_line is not None:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.TAINT,
                                severity=SeverityLevel.CRITICAL,
                                message=bug.find("LongMessage").text,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(source_line.get("start", "1")),
                                    line_end=int(source_line.get("end", "1"))
                                ),
                                rule_id=bug.get("type"),
                                fix_suggestions=[
                                    "Sanitize input data",
                                    "Use parameterized queries",
                                    "Implement proper input validation"
                                ]
                            ))
            except Exception as e:
                print(f"Taint analysis failed: {str(e)}")
        
        return findings
    
    def _lexical_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform lexical analysis using Checkstyle."""
        findings = []
        
        if self.tools["checkstyle"]:
            cmd = ["checkstyle", "-f", "json", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                
                for file_result in data:
                    for error in file_result.get("errors", []):
                        if "Style" in error.get("source", ""):
                            findings.append(AnalysisFinding(
                                type=AnalysisType.LEXICAL,
                                severity=SeverityLevel.LOW,
                                message=error.get("message", ""),
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=error.get("line", 1),
                                    column_start=error.get("column", 1)
                                ),
                                rule_id=error.get("source")
                            ))
            except Exception as e:
                print(f"Lexical analysis failed: {str(e)}")
        
        return findings
    
    def _memory_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform memory leak analysis using SpotBugs."""
        findings = []
        
        if self.tools["spotbugs"]:
            cmd = ["spotbugs", "-textui", "-xml:withMessages", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Parse SpotBugs XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                for bug in root.findall(".//BugInstance"):
                    if "MEMORY" in bug.get("category", ""):
                        source_line = bug.find(".//SourceLine")
                        if source_line is not None:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.MEMORY,
                                severity=self._map_severity(bug.get("priority", "3")),
                                message=bug.find("LongMessage").text,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(source_line.get("start", "1")),
                                    line_end=int(source_line.get("end", "1"))
                                ),
                                rule_id=bug.get("type"),
                                fix_suggestions=[
                                    "Close resources in finally blocks",
                                    "Use try-with-resources",
                                    "Fix memory leaks"
                                ]
                            ))
            except Exception as e:
                print(f"Memory analysis failed: {str(e)}")
        
        return findings
    
    def _map_severity(self, severity: Union[str, int]) -> SeverityLevel:
        """Map tool-specific severity levels to our standardized levels."""
        if isinstance(severity, str):
            severity = severity.lower()
            if severity in ('critical', 'high', 'error', '1'):
                return SeverityLevel.HIGH
            elif severity in ('medium', 'moderate', 'warning', '2'):
                return SeverityLevel.MEDIUM
            elif severity in ('low', 'minor', 'info', '3'):
                return SeverityLevel.LOW
            else:
                return SeverityLevel.INFO
        else:
            # PMD uses 1 for highest priority
            if severity <= 1:
                return SeverityLevel.HIGH
            elif severity == 2:
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW
    
    def analyze_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, AnalysisResult]:
        """Analyze all Java files in a directory."""
        if not os.path.isdir(directory_path):
            return {"error": AnalysisResult(errors=[f"Directory not found: {directory_path}"])}
        
        results = {}
        pattern = '**/*.java' if recursive else '*.java'
        
        for file_path in Path(directory_path).glob(pattern):
            if any(p in str(file_path) for p in self.config.ignore_patterns):
                continue
            results[str(file_path)] = self.analyze_file(str(file_path))
        
        return results


if __name__ == "__main__":
    # Simple CLI for testing
    if len(sys.argv) < 2:
        print("Usage: python java_analyzer.py <file_or_directory_path> [pmd_path] [spotbugs_path]")
        sys.exit(1)
    
    path = sys.argv[1]
    pmd_path = sys.argv[2] if len(sys.argv) > 2 else None
    spotbugs_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    analyzer = JavaAnalyzer(pmd_path, spotbugs_path)
    
    if os.path.isfile(path):
        results = analyzer.analyze_file(path)
    elif os.path.isdir(path):
        results = analyzer.analyze_directory(path)
    else:
        print(f"Error: {path} is not a valid file or directory")
        sys.exit(1)
    
    print(json.dumps(results, indent=2)) 