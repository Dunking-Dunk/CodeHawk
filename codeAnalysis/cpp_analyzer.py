import os
import json
import re
import subprocess
import tempfile
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass

# pycparser imports
PYCPARSER_AVAILABLE = False
try:
    from pycparser import c_parser, c_ast
    from pycparser.plyparser import ParseError
    from pycparser import parse_file
    PYCPARSER_AVAILABLE = True
except ImportError:
    pass

# Import analysis models
try:
    # Try package import first
    from codeAnalysis.models import (
        AnalysisType, SeverityLevel, CodeLocation, 
        AnalysisFinding
    )
except ImportError:
    # Fall back to direct import
    from models import (
        AnalysisType, SeverityLevel, CodeLocation, 
        AnalysisFinding
    )


@dataclass
class AnalysisResult:
    """
    Class to represent the result of a code analysis.
    """
    findings: List[AnalysisFinding] = None
    errors: List[str] = None
    summary: Dict[str, int] = None
    
    def __post_init__(self):
        self.findings = self.findings or []
        self.errors = self.errors or []
        self.summary = self.summary or {}


class CppAnalyzer:
    """
    A static analyzer for C and C++ code.
    Uses multiple analysis techniques to identify bugs, vulnerabilities, and code quality issues.
    """
    
    def __init__(self, config_path: str = None):
        """
        Initialize the C++ static analyzer.
        
        Args:
            config_path: Path to the configuration file. If None, default configuration will be used.
        """
        self.config = CppAnalyzerConfig()
        if config_path:
            self.config.load_from_file(config_path)
        
        self.pycparser_available = PYCPARSER_AVAILABLE
        
        # Make sure required tools are installed
        self._check_tools_availability()
    
    def _check_tools_availability(self):
        """
        Check if all required tools are available and install them if necessary.
        """
        self.tools = {
            "cppcheck": self._check_tool("cppcheck"),
            "clang-tidy": self._check_tool("clang-tidy")
        }
    
    def _check_tool(self, tool_name: str) -> bool:
        """
        Check if a tool is available in PATH.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            bool: True if tool is available, False otherwise
        """
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['where', tool_name], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       check=False)
            else:  # Unix/Linux/MacOS
                result = subprocess.run(['which', tool_name], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       check=False)
                
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_tool_path(self, tool_name: str) -> str:
        """Get the full path to a tool executable."""
        # If we have a custom path for this tool, use it
        if tool_name in self.tool_paths:
            return self.tool_paths[tool_name]
        
        # Otherwise use the tool name directly and let subprocess find it
        return tool_name
    
    def _install_tool(self, tool_name: str):
        """Attempt to install a missing tool."""
        try:
            if self.is_windows:
                # For Windows, we'll instruct the user on how to install the tools
                if tool_name == "cppcheck":
                    print(f"To install cppcheck on Windows, download from: https://cppcheck.sourceforge.io/")
                    print("After installation, add the installation directory to your PATH or run the analyzer again.")
                    
                    # Try to use winget if available
                    if shutil.which("winget"):
                        try:
                            print("Attempting to install cppcheck using winget...")
                            result = subprocess.run(
                                ["winget", "install", "--id", "Cppcheck.Cppcheck"],
                                capture_output=True,
                                text=True,
                                check=False,
                                shell=True
                            )
                            if result.returncode == 0:
                                print("Successfully installed cppcheck via winget!")
                                # Try to find the tool again
                                self.tools[tool_name] = self._check_tool(tool_name)
                            else:
                                print(f"Failed to install cppcheck via winget: {result.stderr}")
                        except Exception as e:
                            print(f"Error using winget: {str(e)}")
                    
                elif tool_name == "clang-tidy":
                    print(f"To install clang-tidy on Windows, download LLVM from: https://releases.llvm.org/download.html")
                    print("After installation, add the LLVM bin directory to your PATH or run the analyzer again.")
                    
                    # Try to use winget if available
                    if shutil.which("winget"):
                        try:
                            print("Attempting to install LLVM (which includes clang-tidy) using winget...")
                            result = subprocess.run(
                                ["winget", "install", "--id", "LLVM.LLVM"],
                                capture_output=True,
                                text=True,
                                check=False,
                                shell=True
                            )
                            if result.returncode == 0:
                                print("Successfully installed LLVM via winget!")
                                # Try to find the tool again
                                self.tools[tool_name] = self._check_tool(tool_name)
                            else:
                                print(f"Failed to install LLVM via winget: {result.stderr}")
                        except Exception as e:
                            print(f"Error using winget: {str(e)}")
                    
            else:
                # For Linux systems
                if shutil.which("apt-get"):
                    # Debian/Ubuntu
                    if tool_name == "cppcheck":
                        subprocess.run(
                            ["apt-get", "install", "-y", "cppcheck"],
                            check=True,
                            capture_output=True
                        )
                        self.tools[tool_name] = self._check_tool(tool_name)
                    elif tool_name == "clang-tidy":
                        subprocess.run(
                            ["apt-get", "install", "-y", "clang-tidy"],
                            check=True,
                            capture_output=True
                        )
                        self.tools[tool_name] = self._check_tool(tool_name)
                elif shutil.which("dnf"):
                    # Fedora/RHEL
                    if tool_name == "cppcheck":
                        subprocess.run(
                            ["dnf", "install", "-y", "cppcheck"],
                            check=True,
                            capture_output=True
                        )
                        self.tools[tool_name] = self._check_tool(tool_name)
                    elif tool_name == "clang-tidy":
                        subprocess.run(
                            ["dnf", "install", "-y", "clang-tools-extra"],
                            check=True,
                            capture_output=True
                        )
                        self.tools[tool_name] = self._check_tool(tool_name)
                elif shutil.which("pacman"):
                    # Arch Linux
                    if tool_name == "cppcheck":
                        subprocess.run(
                            ["pacman", "-S", "--noconfirm", "cppcheck"],
                            check=True,
                            capture_output=True
                        )
                        self.tools[tool_name] = self._check_tool(tool_name)
                    elif tool_name == "clang-tidy":
                        subprocess.run(
                            ["pacman", "-S", "--noconfirm", "clang"],
                            check=True,
                            capture_output=True
                        )
                        self.tools[tool_name] = self._check_tool(tool_name)
                    
        except Exception as e:
            print(f"Failed to install {tool_name}: {str(e)}")
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """
        Perform static analysis on a C/C++ file.
        Uses multiple analysis techniques:
        - Syntax analysis (clang-tidy)
        - Memory analysis (valgrind-like checks)
        - Data flow analysis
        - Rule-based analysis (cppcheck)
        - Metrics analysis (complexity)
        - AST-based analysis (pycparser for C files)
        
        Args:
            file_path: Path to the C/C++ file to analyze
            
        Returns:
            AnalysisResult containing findings and summary information
        """
        findings = []
        errors = []
        summary = {}
        
        # Skip if file doesn't exist
        if not os.path.exists(file_path):
            error_msg = f"File not found: {file_path}"
            print(error_msg)
            return AnalysisResult(errors=[error_msg])
        
        # Check if file has a valid C/C++ extension
        valid_extensions = ('.cpp', '.c', '.cc', '.cxx', '.hpp', '.h')
        if not any(file_path.endswith(ext) for ext in valid_extensions):
            error_msg = f"Skipping non-C/C++ file: {file_path}"
            print(error_msg)
            return AnalysisResult(errors=[error_msg])
            
        # Determine file type (C or C++)
        is_c_file = file_path.endswith('.c')
        file_type = "C" if is_c_file else "C++"
            
        # Special handling for C files using pycparser
        if is_c_file and PYCPARSER_AVAILABLE:
            try:
                pycparser_findings = self._pycparser_analysis(file_path)
                findings.extend(pycparser_findings)
                summary["pycparser"] = len(pycparser_findings)
            except Exception as e:
                error_msg = f"Error in pycparser analysis: {str(e)}"
                errors.append(error_msg)
                print(error_msg)
        
        # Run all enabled analyzers for this file
        for analyzer_type, enabled in self.config.enabled_analyzers.items():
            if not enabled:
                continue
            
            # Skip Syntax Analysis for header files as clang-tidy struggles with them
            if analyzer_type == AnalysisType.SYNTAX and file_path.endswith(('.h', '.hpp')):
                continue
                
            try:
                analyzer_findings = []
                
                if analyzer_type == AnalysisType.SYNTAX:
                    analyzer_findings = self._syntax_analysis(file_path)
                elif analyzer_type == AnalysisType.MEMORY:
                    analyzer_findings = self._memory_analysis(file_path)
                elif analyzer_type == AnalysisType.SYMBOLIC:
                    analyzer_findings = self._symbolic_analysis(file_path)
                elif analyzer_type == AnalysisType.METRICS:
                    analyzer_findings = self._metrics_analysis(file_path)
                elif analyzer_type == AnalysisType.DATA_FLOW:
                    analyzer_findings = self._data_flow_analysis(file_path)
                elif analyzer_type == AnalysisType.TAINT:
                    analyzer_findings = self._taint_analysis(file_path)
                elif analyzer_type == AnalysisType.RULE_BASED:
                    analyzer_findings = self._rule_based_analysis(file_path)
                    
                findings.extend(analyzer_findings)
                summary[analyzer_type.value] = len(analyzer_findings)
            except Exception as e:
                error_msg = f"Error in {analyzer_type} analysis: {str(e)}"
                errors.append(error_msg)
                print(error_msg)
        
        # Update summary with severity counts
        for finding in findings:
            severity_key = f"{finding.type.value}_{finding.severity.value}"
            summary[severity_key] = summary.get(severity_key, 0) + 1
        
        # Add language info to summary
        summary["language"] = file_type
        
        return AnalysisResult(findings=findings, errors=errors, summary=summary)
    
    def _parse_clang_tidy_output(self, line: str, file_path: str) -> tuple:
        """
        Parse a line of clang-tidy output and extract relevant information.
        Returns a tuple of (line_number, column_number, severity, message).
        Returns None if parsing fails.
        """
        try:
            # Windows paths contain drive letters with colons (C:) which break normal splitting
            if self.is_windows and ":" in line:
                # Try to find the file path pattern in the line
                if file_path in line:
                    # Split only after the file path
                    line_after_path = line[line.find(file_path) + len(file_path):]
                    if line_after_path.startswith(":"):
                        # Remove leading colon and split the rest
                        parts = line_after_path[1:].split(":")
                        if len(parts) >= 3:  # We need at least line, column, and some message
                            line_num = int(parts[0])
                            col_num = int(parts[1])
                            severity = parts[2].strip() if len(parts) > 2 else "warning"
                            message = parts[-1].strip() if len(parts) > 3 else "Unknown issue"
                            return (line_num, col_num, severity, message)
            else:
                # Standard parsing for non-Windows or when the file path isn't found
                parts = line.split(":")
                if len(parts) >= 4:
                    try:
                        line_num = int(parts[1])
                        col_num = int(parts[2])
                        severity = parts[3].strip()
                        message = parts[-1].strip()
                        return (line_num, col_num, severity, message)
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        
        return None
    
    def _syntax_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform syntax analysis using clang-tidy."""
        findings = []
        
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            # Adjust checks based on file type
            is_c_file = file_path.lower().endswith('.c')
            
            # Use different checks for C vs C++ files
            if is_c_file:
                # Use C-specific checks, avoiding C++ specific ones
                cmd = [clang_tidy_path, "-checks=*,-clang-analyzer-cplusplus*,-modernize*"]
            else:
                # Use all checks for C++ files
                cmd = [clang_tidy_path, "-checks=*"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running syntax analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout and not result.stderr:
                    print("No output from clang-tidy syntax analysis")
                elif result.returncode != 0:
                    print(f"clang-tidy syntax analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYNTAX,
                                severity=self._map_severity(severity),
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                )
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Clang-tidy analysis failed: {str(e)}")
            
            # Clean up the compilation database
            if compile_commands_path and os.path.exists(compile_commands_path):
                try:
                    os.remove(compile_commands_path)
                except Exception:
                    pass
        
        return findings
    
    def _data_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform data flow analysis using clang-tidy."""
        findings = []
        
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            is_c_file = file_path.lower().endswith('.c')
            
            # Use different checks for C vs C++ files
            if is_c_file:
                cmd = [clang_tidy_path, "-checks=clang-analyzer-core.uninitialized*,-clang-analyzer-cplusplus*"]
            else:
                cmd = [clang_tidy_path, "-checks=clang-analyzer-core.uninitialized*,clang-analyzer-cplusplus.Move"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running data flow analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout and not result.stderr:
                    print("No output from clang-tidy data flow analysis")
                elif result.returncode != 0:
                    print(f"clang-tidy data flow analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.DATA_FLOW,
                                severity=SeverityLevel.MEDIUM,
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                )
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Data flow analysis failed: {str(e)}")
            
            # Clean up the compilation database
            if compile_commands_path and os.path.exists(compile_commands_path):
                try:
                    os.remove(compile_commands_path)
                except Exception:
                    pass
        
        return findings
    
    def _control_flow_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform control flow analysis using cppcheck."""
        findings = []
        
        if self.tools["cppcheck"]:
            cppcheck_path = self._get_tool_path("cppcheck")
            
            # Use a template that will work better with Windows paths
            template = "{{file}}@LINE@{{line}}@COL@{{column}}@SEV@{{severity}}@MSG@{{message}}"
            
            # Use appropriate language standard based on file extension
            is_c_file = file_path.lower().endswith('.c')
            if is_c_file:
                cmd = [cppcheck_path, "--enable=all", "--std=c99", "--language=c", f"--template={template}", file_path]
            else:
                cmd = [cppcheck_path, "--enable=all", "--std=c++17", "--language=c++", f"--template={template}", file_path]
            
            # Print diagnostic info
            print(f"Running control flow analysis with cppcheck: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stderr and not result.stdout:
                    print("No output from cppcheck control flow analysis")
                else:
                    print(f"Got {len(result.stderr.splitlines())} lines of stderr output from cppcheck")
                    if len(result.stderr.splitlines()) > 0:
                        print(f"First line: {result.stderr.splitlines()[0]}")
                
                for line in result.stderr.splitlines():
                    if "@LINE@" in line and "@COL@" in line and "@SEV@" in line and "@MSG@" in line:
                        try:
                            # Split by custom markers instead of colons
                            parts = line.split("@LINE@")
                            if len(parts) >= 2:
                                file_part = parts[0]
                                rest = parts[1]
                                
                                line_col_parts = rest.split("@COL@")
                                if len(line_col_parts) >= 2:
                                    line_num = int(line_col_parts[0])
                                    rest = line_col_parts[1]
                                    
                                    col_sev_parts = rest.split("@SEV@")
                                    if len(col_sev_parts) >= 2:
                                        col_num = int(col_sev_parts[0])
                                        rest = col_sev_parts[1]
                                        
                                        sev_msg_parts = rest.split("@MSG@")
                                        if len(sev_msg_parts) >= 2:
                                            severity = sev_msg_parts[0]
                                            message = sev_msg_parts[1]
                                            
                                            findings.append(AnalysisFinding(
                                                type=AnalysisType.CONTROL_FLOW,
                                                severity=self._map_severity(severity),
                                                message=message,
                                                location=CodeLocation(
                                                    file=file_path,
                                                    line_start=line_num,
                                                    column_start=col_num
                                                )
                                            ))
                        except (ValueError, IndexError) as e:
                            # Print out the error for debugging
                            print(f"Error parsing cppcheck output: {str(e)}")
                            # Skip malformed output lines
                            continue
            except Exception as e:
                print(f"Control flow analysis failed: {str(e)}")
        
        return findings
    
    def _metrics_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform metrics-based analysis using clang-tidy metrics checks."""
        findings = []
        
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            # Determine if this is a C or C++ file
            is_c_file = file_path.lower().endswith('.c')
            
            if is_c_file:
                # For C files, skip C++ specific checks
                cmd = [clang_tidy_path, "-checks=readability-*,-readability-isolate-declaration,-readability-qualified-auto,clang-analyzer-*,-clang-analyzer-cplusplus*"]
            else:
                # Use all checks for C++ files
                cmd = [clang_tidy_path, "-checks=readability-*,clang-analyzer-*"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running metrics analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout and not result.stderr:
                    print("No output from clang-tidy metrics analysis")
                elif result.returncode != 0:
                    print(f"clang-tidy metrics analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.METRICS,
                                severity=self._map_severity(severity),
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                ),
                                fix_suggestions=[
                                    "Break down complex functions",
                                    "Reduce cyclomatic complexity",
                                    "Improve code readability"
                                ]
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Metrics analysis failed: {str(e)}")
            
            # Clean up the compilation database
            if compile_commands_path and os.path.exists(compile_commands_path):
                try:
                    os.remove(compile_commands_path)
                except Exception:
                    pass
        
        # Use cppcheck for complexity metrics
        if self.tools["cppcheck"]:
            cppcheck_path = self._get_tool_path("cppcheck")
            # Use a template that will work better with Windows paths
            template = "{{file}}@LINE@{{line}}@COL@{{column}}@SEV@{{severity}}@MSG@{{message}}"
            
            # Use appropriate language standard based on file extension
            is_c_file = file_path.lower().endswith('.c')
            if is_c_file:
                cmd = [cppcheck_path, "--enable=all", "--std=c99", "--language=c", f"--template={template}", file_path]
            else:
                cmd = [cppcheck_path, "--enable=all", "--std=c++17", "--language=c++", f"--template={template}", file_path]
            
            # Print diagnostic info
            print(f"Running cppcheck metrics analysis with: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stderr and not result.stdout:
                    print("No output from cppcheck metrics analysis")
                elif result.returncode != 0:
                    print(f"cppcheck metrics analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stderr.splitlines():
                    if "@LINE@" in line and "@COL@" in line and "@SEV@" in line and "@MSG@" in line:
                        if "complexity" in line.lower():
                            try:
                                # Split by custom markers instead of colons
                                parts = line.split("@LINE@")
                                if len(parts) >= 2:
                                    file_part = parts[0]
                                    rest = parts[1]
                                    
                                    line_col_parts = rest.split("@COL@")
                                    if len(line_col_parts) >= 2:
                                        line_num = int(line_col_parts[0])
                                        rest = line_col_parts[1]
                                        
                                        col_sev_parts = rest.split("@SEV@")
                                        if len(col_sev_parts) >= 2:
                                            col_num = int(col_sev_parts[0])
                                            rest = col_sev_parts[1]
                                            
                                            sev_msg_parts = rest.split("@MSG@")
                                            if len(sev_msg_parts) >= 2:
                                                severity = sev_msg_parts[0]
                                                message = sev_msg_parts[1]
                                                
                                                findings.append(AnalysisFinding(
                                                    type=AnalysisType.METRICS,
                                                    severity=self._map_severity(severity),
                                                    message=message,
                                                    location=CodeLocation(
                                                        file=file_path,
                                                        line_start=line_num,
                                                        column_start=col_num
                                                    )
                                                ))
                            except (ValueError, IndexError):
                                # Skip malformed output lines
                                continue
            except Exception as e:
                print(f"CPPCheck metrics analysis failed: {str(e)}")
        
        return findings
    
    def _rule_based_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform rule-based analysis using cppcheck."""
        findings = []
        
        if self.tools["cppcheck"]:
            cppcheck_path = self._get_tool_path("cppcheck")
            # Use a template that will work better with Windows paths
            template = "{{file}}@LINE@{{line}}@COL@{{column}}@SEV@{{severity}}@MSG@{{message}}"
            
            # Use appropriate language standard based on file extension
            is_c_file = file_path.lower().endswith('.c')
            
            rule_file_path = None
            if is_c_file:
                rule_file_path = os.path.join(os.path.dirname(__file__), "config", "cppcheck_rules_c.xml")
                if os.path.exists(rule_file_path):
                    cmd = [cppcheck_path, f"--rule-file={rule_file_path}", 
                           "--std=c99", "--language=c", f"--template={template}", file_path]
                else:
                    cmd = [cppcheck_path, "--enable=warning", "--std=c99", "--language=c", 
                           f"--template={template}", file_path]
            else:
                rule_file_path = os.path.join(os.path.dirname(__file__), "config", "cppcheck_rules_cpp.xml")
                if os.path.exists(rule_file_path):
                    cmd = [cppcheck_path, f"--rule-file={rule_file_path}",
                           "--std=c++17", "--language=c++", f"--template={template}", file_path]
                else:
                    cmd = [cppcheck_path, "--enable=warning", "--std=c++17", "--language=c++",
                           f"--template={template}", file_path]
            
            # Print diagnostic info
            print(f"Running rule-based analysis with cppcheck: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stderr:
                    print("No stderr output from cppcheck rule-based analysis")
                else:
                    print(f"Got {len(result.stderr.splitlines())} lines of stderr output from cppcheck")
                    warning_count = 0
                    for line in result.stderr.splitlines():
                        if "warning" in line.lower():
                            warning_count += 1
                    print(f"Found {warning_count} warning lines")
                
                for line in result.stderr.splitlines():
                    if "@LINE@" in line and "@COL@" in line and "@SEV@" in line and "@MSG@" in line:
                        try:
                            # Split by custom markers instead of colons
                            parts = line.split("@LINE@")
                            if len(parts) >= 2:
                                file_part = parts[0]
                                rest = parts[1]
                                
                                line_col_parts = rest.split("@COL@")
                                if len(line_col_parts) >= 2:
                                    line_num = int(line_col_parts[0])
                                    rest = line_col_parts[1]
                                    
                                    col_sev_parts = rest.split("@SEV@")
                                    if len(col_sev_parts) >= 2:
                                        col_num = int(col_sev_parts[0])
                                        rest = col_sev_parts[1]
                                        
                                        sev_msg_parts = rest.split("@MSG@")
                                        if len(sev_msg_parts) >= 2:
                                            severity = sev_msg_parts[0]
                                            message = sev_msg_parts[1]
                                            
                                            # Extract rule ID if available (usually in square brackets)
                                            rule_id = None
                                            if '[' in message and ']' in message:
                                                start = message.find('[')
                                                end = message.find(']', start)
                                                if start >= 0 and end > start:
                                                    rule_id = message[start+1:end]
                                            
                                            findings.append(AnalysisFinding(
                                                type=AnalysisType.RULE_BASED,
                                                severity=self._map_severity(severity),
                                                message=message,
                                                location=CodeLocation(
                                                    file=file_path,
                                                    line_start=line_num,
                                                    column_start=col_num
                                                ),
                                                rule_id=rule_id
                                            ))
                        except (ValueError, IndexError) as e:
                            # Print diagnostic info
                            print(f"Error parsing cppcheck output: {str(e)} - Line: {line}")
                            # Skip malformed output lines
                            continue
            except Exception as e:
                print(f"Rule-based analysis (cppcheck) failed: {str(e)}")
        
        return findings
    
    def _pattern_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform pattern-based analysis using flawfinder."""
        findings = []
        
        if self.tools["flawfinder"]:
            flawfinder_path = self._get_tool_path("flawfinder")
            cmd = [flawfinder_path, "--csv", file_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                for line in result.stdout.splitlines()[1:]:  # Skip header
                    if "," in line:
                        parts = line.split(",")
                        if len(parts) >= 5:
                            findings.append(AnalysisFinding(
                                type=AnalysisType.PATTERN,
                                severity=self._map_severity(parts[1]),
                                message=parts[4],
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=int(parts[0])
                                ),
                                rule_id=parts[2]
                            ))
            except Exception as e:
                print(f"Pattern analysis failed: {str(e)}")
        
        return findings
    
    def _symbolic_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform symbolic analysis using clang-tidy symbolic checks."""
        findings = []
        
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            # Determine if this is a C or C++ file
            is_c_file = file_path.lower().endswith('.c')
            
            if is_c_file:
                # Use core checks common to both C and C++
                cmd = [clang_tidy_path, "-checks=clang-analyzer-core*,-clang-analyzer-cplusplus*"]
            else:
                # Include C++ specific checks for C++ files
                cmd = [clang_tidy_path, "-checks=clang-analyzer-core*"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running symbolic analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout and not result.stderr:
                    print("No output from clang-tidy symbolic analysis")
                elif result.returncode != 0:
                    print(f"clang-tidy symbolic analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.SYMBOLIC,
                                severity=SeverityLevel.HIGH,
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                )
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Symbolic analysis failed: {str(e)}")
            
            # Clean up the compilation database
            if compile_commands_path and os.path.exists(compile_commands_path):
                try:
                    os.remove(compile_commands_path)
                except Exception:
                    pass
        
        return findings
    
    def _taint_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform taint analysis using clang-tidy security checks."""
        findings = []
        
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            # Determine if this is a C or C++ file
            is_c_file = file_path.lower().endswith('.c')
            
            if is_c_file:
                # For C files, include relevant security checks
                cmd = [clang_tidy_path, "-checks=clang-analyzer-security*,-clang-analyzer-cplusplus*"]
            else:
                # Include C++ specific checks for C++ files
                cmd = [clang_tidy_path, "-checks=clang-analyzer-security*"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running taint analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout and not result.stderr:
                    print("No output from clang-tidy taint analysis")
                elif result.returncode != 0:
                    print(f"clang-tidy taint analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.TAINT,
                                severity=SeverityLevel.CRITICAL,
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                )
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Taint analysis failed: {str(e)}")
        
        return findings
    
    def _lexical_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform lexical analysis."""
        findings = []
        
        # Use cppcheck for lexical analysis when available
        if self.tools["cppcheck"]:
            cppcheck_path = self._get_tool_path("cppcheck")
            # Use a template that will work better with Windows paths
            template = "{{file}}@LINE@{{line}}@COL@{{column}}@SEV@{{severity}}@MSG@{{message}}"
            
            # Use appropriate language standard based on file extension
            is_c_file = file_path.lower().endswith('.c')
            if is_c_file:
                cmd = [cppcheck_path, "--enable=style", "--std=c99", "--language=c", f"--template={template}", file_path]
            else:
                cmd = [cppcheck_path, "--enable=style", "--std=c++17", "--language=c++", f"--template={template}", file_path]
            
            # Print diagnostic info
            print(f"Running lexical analysis with cppcheck: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stderr:
                    print("No stderr output from cppcheck lexical analysis")
                else:
                    print(f"Got {len(result.stderr.splitlines())} lines of stderr output from cppcheck")
                    style_count = 0
                    for line in result.stderr.splitlines():
                        if "style" in line.lower():
                            style_count += 1
                    print(f"Found {style_count} lines containing 'style'")
                
                for line in result.stderr.splitlines():
                    if "@LINE@" in line and "@COL@" in line and "@SEV@" in line and "@MSG@" in line:
                        try:
                            # Split by custom markers instead of colons
                            parts = line.split("@LINE@")
                            if len(parts) >= 2:
                                file_part = parts[0]
                                rest = parts[1]
                                
                                line_col_parts = rest.split("@COL@")
                                if len(line_col_parts) >= 2:
                                    line_num = int(line_col_parts[0])
                                    rest = line_col_parts[1]
                                    
                                    col_sev_parts = rest.split("@SEV@")
                                    if len(col_sev_parts) >= 2:
                                        col_num = int(col_sev_parts[0])
                                        rest = col_sev_parts[1]
                                        
                                        sev_msg_parts = rest.split("@MSG@")
                                        if len(sev_msg_parts) >= 2:
                                            severity = sev_msg_parts[0]
                                            message = sev_msg_parts[1]
                                            
                                            # Accept both 'style' and 'warning' for lexical findings as cppcheck may use either
                                            if severity.lower() in ['style', 'warning', 'information', 'portability']:
                                                findings.append(AnalysisFinding(
                                                    type=AnalysisType.LEXICAL,
                                                    severity=SeverityLevel.LOW,
                                                    message=message,
                                                    location=CodeLocation(
                                                        file=file_path,
                                                        line_start=line_num,
                                                        column_start=col_num
                                                    )
                                                ))
                        except (ValueError, IndexError) as e:
                            # Print diagnostic info
                            print(f"Error parsing cppcheck output: {str(e)} - Line: {line}")
                            # Skip malformed output lines
                            continue
            except Exception as e:
                print(f"Lexical analysis (cppcheck) failed: {str(e)}")
        
        # Add clang-tidy lexical analysis as well
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            # Use appropriate checks based on file type
            is_c_file = file_path.lower().endswith('.c')
            if is_c_file:
                # For C files, use C-appropriate readability checks
                cmd = [clang_tidy_path, "-checks=readability-braces-around-statements,readability-misleading-indentation,readability-non-const-parameter,-readability-isolate-declaration"]
            else:
                # For C++ files, include C++ specific checks
                cmd = [clang_tidy_path, "-checks=readability-braces-around-statements,readability-misleading-indentation,readability-const-return-type"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running lexical analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout:
                    print("No stdout output from clang-tidy lexical analysis")
                else:
                    print(f"Got {len(result.stdout.splitlines())} lines of stdout output from clang-tidy")
                    warning_count = 0
                    for line in result.stdout.splitlines():
                        if "warning:" in line or "error:" in line:
                            warning_count += 1
                    print(f"Found {warning_count} warning/error lines")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.LEXICAL,
                                severity=SeverityLevel.LOW,
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                )
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Lexical analysis (clang-tidy) failed: {str(e)}")
            
            # Clean up the compilation database
            if compile_commands_path and os.path.exists(compile_commands_path):
                try:
                    os.remove(compile_commands_path)
                except Exception:
                    pass
        
        return findings
    
    def _memory_analysis(self, file_path: str) -> List[AnalysisFinding]:
        """Perform memory analysis using cppcheck."""
        findings = []
        
        if self.tools["cppcheck"]:
            cppcheck_path = self._get_tool_path("cppcheck")
            # Use a template that will work better with Windows paths
            template = "{{file}}@LINE@{{line}}@COL@{{column}}@SEV@{{severity}}@MSG@{{message}}"
            
            # Use appropriate language standard based on file extension
            is_c_file = file_path.lower().endswith('.c')
            if is_c_file:
                cmd = [cppcheck_path, "--enable=memory", "--std=c99", "--language=c", f"--template={template}", file_path]
            else:
                cmd = [cppcheck_path, "--enable=memory", "--std=c++17", "--language=c++", f"--template={template}", file_path]
            
            # Print diagnostic info
            print(f"Running memory analysis with cppcheck: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stderr and not result.stdout:
                    print("No output from cppcheck memory analysis")
                else:
                    print(f"Got {len(result.stderr.splitlines())} lines of stderr output from cppcheck")
                    if len(result.stderr.splitlines()) > 0:
                        print(f"First line: {result.stderr.splitlines()[0]}")
                
                for line in result.stderr.splitlines():
                    if "@LINE@" in line and "@COL@" in line and "@SEV@" in line and "@MSG@" in line:
                        try:
                            # Split by custom markers instead of colons
                            parts = line.split("@LINE@")
                            if len(parts) >= 2:
                                file_part = parts[0]
                                rest = parts[1]
                                
                                line_col_parts = rest.split("@COL@")
                                if len(line_col_parts) >= 2:
                                    line_num = int(line_col_parts[0])
                                    rest = line_col_parts[1]
                                    
                                    col_sev_parts = rest.split("@SEV@")
                                    if len(col_sev_parts) >= 2:
                                        col_num = int(col_sev_parts[0])
                                        rest = col_sev_parts[1]
                                        
                                        sev_msg_parts = rest.split("@MSG@")
                                        if len(sev_msg_parts) >= 2:
                                            severity = sev_msg_parts[0]
                                            message = sev_msg_parts[1]
                                            
                                            findings.append(AnalysisFinding(
                                                type=AnalysisType.MEMORY,
                                                severity=SeverityLevel.HIGH,
                                                message=message,
                                                location=CodeLocation(
                                                    file=file_path,
                                                    line_start=line_num,
                                                    column_start=col_num
                                                )
                                            ))
                        except (ValueError, IndexError) as e:
                            # Print out the error for debugging
                            print(f"Error parsing cppcheck output: {str(e)}")
                            # Skip malformed output lines
                            continue
            except Exception as e:
                print(f"Memory analysis (cppcheck) failed: {str(e)}")
        
        # Add clang-tidy memory checks
        if self.tools["clang-tidy"]:
            clang_tidy_path = self._get_tool_path("clang-tidy")
            
            # Generate compilation database for clang-tidy
            compile_commands_path = self._generate_compile_commands(file_path)
            
            # Determine if this is a C or C++ file
            is_c_file = file_path.lower().endswith('.c')
            
            if is_c_file:
                # For C files, skip C++ specific checks and use C memory checks
                cmd = [clang_tidy_path, "-checks=clang-analyzer-core.StackAddressEscape,clang-analyzer-unix.Malloc,clang-analyzer-unix.MallocSizeof,clang-analyzer-unix.cstring.NullArg"]
            else:
                # For C++ files, include C++ specific checks
                cmd = [clang_tidy_path, "-checks=clang-analyzer-cplusplus.Move,clang-analyzer-cplusplus.NewDelete"]
            
            # Add path to compilation database if we created one
            if compile_commands_path:
                cmd.extend(["-p", os.path.dirname(compile_commands_path)])
            
            # Add the file to analyze
            cmd.append(file_path)
            
            # Print diagnostic info
            print(f"Running memory analysis with clang-tidy: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=self.is_windows)
                
                # Print diagnostic info
                if not result.stdout and not result.stderr:
                    print("No output from clang-tidy memory analysis")
                elif result.returncode != 0:
                    print(f"clang-tidy memory analysis failed with code {result.returncode}")
                    if result.stderr:
                        print(f"Error: {result.stderr}")
                
                for line in result.stdout.splitlines():
                    if "warning:" in line or "error:" in line:
                        parsed = self._parse_clang_tidy_output(line, file_path)
                        if parsed:
                            line_num, col_num, severity, message = parsed
                            findings.append(AnalysisFinding(
                                type=AnalysisType.MEMORY,
                                severity=SeverityLevel.HIGH,
                                message=message,
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    column_start=col_num
                                )
                            ))
                        else:
                            print(f"Failed to parse clang-tidy output line: {line}")
            except Exception as e:
                print(f"Memory analysis (clang-tidy) failed: {str(e)}")
            
            # Clean up the compilation database
            if compile_commands_path and os.path.exists(compile_commands_path):
                try:
                    os.remove(compile_commands_path)
                except Exception:
                    pass
        
        return findings
    
    def _generate_compile_commands(self, file_path: str):
        """Generate a temporary compilation database for clang-tidy."""
        # Determine if it's a C or C++ file
        is_c_file = file_path.lower().endswith('.c')
        
        # Create a temporary compile_commands.json file
        compile_commands_dir = os.path.dirname(file_path)
        absolute_file_path = os.path.abspath(file_path)
        
        compile_commands = [{
            "directory": os.path.abspath(compile_commands_dir),
            "command": f"{'gcc' if is_c_file else 'g++'} -c {absolute_file_path}",
            "file": absolute_file_path
        }]
        
        compile_commands_path = os.path.join(compile_commands_dir, "compile_commands.json")
        
        try:
            with open(compile_commands_path, 'w') as f:
                json.dump(compile_commands, f, indent=2)
            return compile_commands_path
        except Exception as e:
            print(f"Error creating compilation database: {str(e)}")
            return None
    
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
        """Analyze all C/C++ files in a directory."""
        if not os.path.isdir(directory_path):
            return {"error": AnalysisResult(errors=[f"Directory not found: {directory_path}"])}
        
        results = {}
        c_extensions = ('.c', '.h')
        cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp', '.hxx', '.h++')
        valid_extensions = c_extensions + cpp_extensions
        
        pattern = '**/*' if recursive else '*'
        
        for file_path in Path(directory_path).glob(pattern):
            # Check if the file suffix is in our list of valid extensions
            if file_path.suffix.lower() in valid_extensions and not any(p in str(file_path) for p in self.config.ignore_patterns):
                results[str(file_path)] = self.analyze_file(str(file_path))
        
        return results

    def _pycparser_analysis(self, file_path: str) -> list:
        """
        Perform analysis using pycparser on C files.
        """
        findings = []
        
        # Only analyze files with a .c extension
        if not file_path.endswith('.c'):
            return findings
            
        try:
            if not PYCPARSER_AVAILABLE:
                return findings
                
            # Create temp file for preprocessed code
            preprocessed_file = f"{file_path}.preprocessed.c"
            
            try:
                # Try to preprocess the file with GCC
                cpp_path = 'gcc'
                cpp_args = ['-E', file_path]
                
                # Try to parse the file using CParser directly first
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Create a visitor to analyze the AST
                if os.path.exists(file_path):
                    try:
                        # Try to parse directly first
                        ast = parse_file(file_path, use_cpp=False)
                        visitor = CodeAnalysisVisitor(file_path)
                        visitor.visit(ast)
                        findings.extend(visitor.findings)
                    except Exception as direct_parse_error:
                        try:
                            # If direct parsing fails, try with preprocessing
                            ast = parse_file(file_path, use_cpp=True, cpp_path=cpp_path, cpp_args=cpp_args)
                            visitor = CodeAnalysisVisitor(file_path)
                            visitor.visit(ast)
                            findings.extend(visitor.findings)
                        except Exception as preprocess_error:
                            # If both approaches fail, try parsing from raw content
                            try:
                                parser = c_parser.CParser()
                                ast = parser.parse(content)
                                visitor = CodeAnalysisVisitor(file_path)
                                visitor.visit(ast)
                                findings.extend(visitor.findings)
                            except Exception as raw_parse_error:
                                # Try to capture the line number from the error message
                                error_msg = str(raw_parse_error)
                                line_match = re.search(r':(\d+):', error_msg)
                                line_num = int(line_match.group(1)) if line_match else 1
                                
                                findings.append(AnalysisFinding(
                                    type=AnalysisType.LEXICAL,
                                    severity=SeverityLevel.HIGH,
                                    message=f"Failed to parse C file: {error_msg}",
                                    location=CodeLocation(
                                        file=file_path,
                                        line_start=line_num,
                                        column_start=1
                                    )
                                ))
            except Exception as e:
                findings.append(AnalysisFinding(
                    type=AnalysisType.LEXICAL,
                    severity=SeverityLevel.HIGH,
                    message=f"Error during pycparser analysis: {str(e)}",
                    location=CodeLocation(
                        file=file_path,
                        line_start=1,
                        column_start=1
                    )
                ))
            finally:
                # Clean up temporary file if it exists
                if os.path.exists(preprocessed_file):
                    try:
                        os.remove(preprocessed_file)
                    except:
                        pass
        except Exception as outer_e:
            findings.append(AnalysisFinding(
                type=AnalysisType.LEXICAL,
                severity=SeverityLevel.HIGH,
                message=f"Unexpected error in pycparser analysis: {str(outer_e)}",
                location=CodeLocation(
                    file=file_path,
                    line_start=1,
                    column_start=1
                )
            ))
            
        return findings


class CodeAnalysisVisitor(c_ast.NodeVisitor):
    """
    A visitor class that traverses the pycparser AST and identifies potential issues.
    """
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.variables = {}  # Dictionary to track variable declarations and usage
        self.functions = {}  # Dictionary to track function declarations and calls
        self.current_function = None  # Keep track of current function
        
    def visit_FuncDef(self, node):
        """Visit function definitions and check for issues."""
        # Store current function for context
        prev_function = self.current_function
        self.current_function = node.decl.name
        
        # Check for function name style (should be snake_case or camelCase)
        if not self._is_snake_or_camel_case(node.decl.name):
            self.findings.append(AnalysisFinding(
                type=AnalysisType.LEXICAL,
                severity=SeverityLevel.LOW,
                message=f"Function name '{node.decl.name}' doesn't follow snake_case or camelCase convention",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.decl.coord.line,
                    column_start=node.decl.coord.column
                )
            ))
        
        # Store function definition
        self.functions[node.decl.name] = {
            'params': self._get_params(node.decl),
            'returns': self._get_return_type(node.decl),
            'line': node.decl.coord.line,
            'column': node.decl.coord.column
        }
        
        # Check function body
        self.generic_visit(node)
        
        # Restore previous function context
        self.current_function = prev_function
    
    def visit_Decl(self, node):
        """Visit variable declarations and check for issues."""
        if hasattr(node, 'name') and node.name:
            # Check variable name style (should be snake_case or camelCase)
            if not self._is_snake_or_camel_case(node.name) and len(node.name) > 1:
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.LEXICAL,
                    severity=SeverityLevel.LOW,
                    message=f"Variable name '{node.name}' doesn't follow snake_case or camelCase convention",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
            
            # Check for uninitialized variables (if no init value provided)
            if not hasattr(node, 'init') or node.init is None:
                # Only flag uninitialized local variables in functions (not params or globals)
                if self.current_function and not isinstance(node.type, c_ast.FuncDecl):
                    # Don't flag function parameters
                    self.findings.append(AnalysisFinding(
                        type=AnalysisType.DATA_FLOW,
                        severity=SeverityLevel.MEDIUM,
                        message=f"Variable '{node.name}' may be used uninitialized",
                        location=CodeLocation(
                            file=self.file_path,
                            line_start=node.coord.line,
                            column_start=node.coord.column
                        )
                    ))
            
            # Track variable declarations
            var_type = self._get_type_name(node.type)
            self.variables[node.name] = {
                'type': var_type,
                'line': node.coord.line,
                'column': node.coord.column,
                'initialized': hasattr(node, 'init') and node.init is not None
            }
        
        self.generic_visit(node)
    
    def visit_Assignment(self, node):
        """Visit assignments and check for issues."""
        # Check for assignments in conditions (common mistake)
        if hasattr(node, 'parent') and isinstance(node.parent, (c_ast.If, c_ast.While, c_ast.DoWhile)):
            self.findings.append(AnalysisFinding(
                type=AnalysisType.CONTROL_FLOW,
                severity=SeverityLevel.MEDIUM,
                message=f"Assignment in condition may be a bug (did you mean '==' instead of '='?)",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.coord.line,
                    column_start=node.coord.column
                )
            ))
        
        self.generic_visit(node)
    
    def visit_If(self, node):
        """Visit if statements and check for issues."""
        # Check for empty if bodies
        if not node.iftrue or (isinstance(node.iftrue, c_ast.Compound) and not node.iftrue.block_items):
            self.findings.append(AnalysisFinding(
                type=AnalysisType.CONTROL_FLOW,
                severity=SeverityLevel.LOW,
                message=f"Empty if statement body",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.coord.line,
                    column_start=node.coord.column
                )
            ))
        
        # Check for constant conditions
        if isinstance(node.cond, c_ast.Constant):
            self.findings.append(AnalysisFinding(
                type=AnalysisType.CONTROL_FLOW,
                severity=SeverityLevel.MEDIUM,
                message=f"If condition is a constant value ({node.cond.value})",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.coord.line,
                    column_start=node.coord.column
                )
            ))
        
        self.generic_visit(node)
    
    def visit_While(self, node):
        """Visit while loops and check for issues."""
        # Check for empty while bodies
        if not node.stmt or (isinstance(node.stmt, c_ast.Compound) and not node.stmt.block_items):
            self.findings.append(AnalysisFinding(
                type=AnalysisType.CONTROL_FLOW,
                severity=SeverityLevel.LOW,
                message=f"Empty while loop body",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.coord.line,
                    column_start=node.coord.column
                )
            ))
        
        # Check for constant conditions
        if isinstance(node.cond, c_ast.Constant):
            if node.cond.value != '0':  # Not while(0)
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.CONTROL_FLOW,
                    severity=SeverityLevel.MEDIUM,
                    message=f"While loop condition is a constant value ({node.cond.value})",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
        
        self.generic_visit(node)
    
    def visit_For(self, node):
        """Visit for loops and check for issues."""
        # Check for empty for bodies
        if not node.stmt or (isinstance(node.stmt, c_ast.Compound) and not node.stmt.block_items):
            self.findings.append(AnalysisFinding(
                type=AnalysisType.CONTROL_FLOW,
                severity=SeverityLevel.LOW,
                message=f"Empty for loop body",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.coord.line,
                    column_start=node.coord.column
                )
            ))
        
        self.generic_visit(node)
    
    def visit_Return(self, node):
        """Visit return statements and check for issues."""
        if self.current_function and self.current_function in self.functions:
            # Check if return type matches function return type
            func_info = self.functions[self.current_function]
            return_type = func_info.get('returns', '')
            
            # If function returns void but return has a value
            if return_type == 'void' and node.expr is not None:
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.DATA_FLOW,
                    severity=SeverityLevel.HIGH,
                    message=f"Function '{self.current_function}' returns a value but is declared void",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
            
            # If function doesn't return void but return has no value
            if return_type != 'void' and node.expr is None:
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.DATA_FLOW,
                    severity=SeverityLevel.HIGH,
                    message=f"Function '{self.current_function}' doesn't return a value but should return {return_type}",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
        
        self.generic_visit(node)
    
    def visit_FuncCall(self, node):
        """Visit function calls and check for issues."""
        func_name = self._get_func_name(node)
        
        # Check for potentially dangerous functions
        dangerous_funcs = {
            'strcpy': 'unsafe, use strncpy instead',
            'strcat': 'unsafe, use strncat instead',
            'gets': 'unsafe, use fgets instead',
            'sprintf': 'unsafe, use snprintf instead'
        }
        
        if func_name in dangerous_funcs:
            self.findings.append(AnalysisFinding(
                type=AnalysisType.SECURITY,
                severity=SeverityLevel.HIGH,
                message=f"Function '{func_name}' is {dangerous_funcs[func_name]}",
                location=CodeLocation(
                    file=self.file_path,
                    line_start=node.coord.line,
                    column_start=node.coord.column
                )
            ))
        
        self.generic_visit(node)
    
    def visit_BinaryOp(self, node):
        """Visit binary operations and check for issues."""
        # Check for potential null pointer dereference
        if node.op == '==' or node.op == '!=':
            if (isinstance(node.left, c_ast.Constant) and node.left.value == '0' and 
                isinstance(node.right, c_ast.ID)):
                # Found something like: 0 == ptr or 0 != ptr
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.MEMORY,
                    severity=SeverityLevel.MEDIUM,
                    message=f"Consider using NULL instead of 0 for pointer comparison",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
            elif (isinstance(node.right, c_ast.Constant) and node.right.value == '0' and 
                  isinstance(node.left, c_ast.ID)):
                # Found something like: ptr == 0 or ptr != 0
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.MEMORY,
                    severity=SeverityLevel.MEDIUM,
                    message=f"Consider using NULL instead of 0 for pointer comparison",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
        
        # Check for potential division by zero
        if node.op == '/' or node.op == '%':
            if isinstance(node.right, c_ast.Constant) and node.right.value == '0':
                self.findings.append(AnalysisFinding(
                    type=AnalysisType.DATA_FLOW,
                    severity=SeverityLevel.HIGH,
                    message=f"Division by zero detected",
                    location=CodeLocation(
                        file=self.file_path,
                        line_start=node.coord.line,
                        column_start=node.coord.column
                    )
                ))
        
        self.generic_visit(node)
    
    def _is_snake_or_camel_case(self, name: str) -> bool:
        """Check if a name follows snake_case or camelCase convention."""
        # Allow single letter names
        if len(name) <= 1:
            return True
            
        # Allow names with underscores (snake_case)
        if '_' in name:
            parts = name.split('_')
            return all(part.islower() or part == '' for part in parts)
            
        # Check for camelCase (first letter lowercase, no underscores)
        return name[0].islower() and '_' not in name
    
    def _get_type_name(self, type_node) -> str:
        """Extract type name from a type node."""
        if isinstance(type_node, c_ast.TypeDecl):
            return self._get_type_name(type_node.type)
        elif isinstance(type_node, c_ast.IdentifierType):
            return ' '.join(type_node.names)
        elif isinstance(type_node, c_ast.PtrDecl):
            return self._get_type_name(type_node.type) + '*'
        elif isinstance(type_node, c_ast.ArrayDecl):
            return self._get_type_name(type_node.type) + '[]'
        elif isinstance(type_node, c_ast.FuncDecl):
            return 'function'
        else:
            return 'unknown'
    
    def _get_params(self, func_decl) -> List[str]:
        """Extract parameter names from a function declaration."""
        if not hasattr(func_decl, 'type') or not isinstance(func_decl.type, c_ast.FuncDecl):
            return []
            
        params = func_decl.type.args
        if not params:
            return []
            
        result = []
        for param in params.params:
            if hasattr(param, 'name'):
                result.append(param.name)
        
        return result
    
    def _get_return_type(self, func_decl) -> str:
        """Extract return type from a function declaration."""
        if not hasattr(func_decl, 'type') or not isinstance(func_decl.type, c_ast.FuncDecl):
            return 'unknown'
            
        return self._get_type_name(func_decl.type.type)
    
    def _get_func_name(self, func_call) -> str:
        """Extract function name from a function call node."""
        if isinstance(func_call.name, c_ast.ID):
            return func_call.name.name
        return "unknown"


class CppAnalyzerConfig:
    """
    Configuration for the C++ static analyzer.
    """
    
    def __init__(self):
        """Initialize with default configuration."""
        # By default, enable all analyzers
        self.enabled_analyzers = {analysis_type: True for analysis_type in AnalysisType}
        
        # Specific analyzer settings
        self.clang_tidy_checks = [
            "bugprone-*",
            "cert-*",
            "clang-analyzer-*",
            "cppcoreguidelines-*",
            "misc-*",
            "performance-*",
            "portability-*",
            "readability-*",
            "-readability-magic-numbers",
            "-readability-braces-around-statements",
            "-readability-identifier-length"
        ]
        
        self.cppcheck_checks = [
            "all",
            "--enable=warning,style,performance,portability,information"
        ]
        
        # Other configuration options
        self.max_findings_per_file = 100
        self.severity_filter = SeverityLevel.INFO  # Include findings at this level and above
        
    def load_from_file(self, config_path: str):
        """
        Load configuration from a JSON file.
        
        Args:
            config_path: Path to the JSON configuration file
        """
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                
            # Update enabled analyzers
            if 'enabled_analyzers' in config_data:
                for analyzer, enabled in config_data['enabled_analyzers'].items():
                    try:
                        analyzer_type = AnalysisType(analyzer)
                        self.enabled_analyzers[analyzer_type] = enabled
                    except ValueError:
                        print(f"Warning: Unknown analyzer type '{analyzer}' in config")
            
            # Update other settings if present
            if 'clang_tidy_checks' in config_data:
                self.clang_tidy_checks = config_data['clang_tidy_checks']
                
            if 'cppcheck_checks' in config_data:
                self.cppcheck_checks = config_data['cppcheck_checks']
                
            if 'max_findings_per_file' in config_data:
                self.max_findings_per_file = config_data['max_findings_per_file']
                
            if 'severity_filter' in config_data:
                try:
                    self.severity_filter = SeverityLevel(config_data['severity_filter'])
                except ValueError:
                    print(f"Warning: Unknown severity level '{config_data['severity_filter']}' in config")
                    
        except Exception as e:
            print(f"Error loading config from {config_path}: {str(e)}")
            print("Using default configuration instead")
            
    def save_to_file(self, config_path: str):
        """
        Save configuration to a JSON file.
        
        Args:
            config_path: Path to save the JSON configuration file
        """
        try:
            config_data = {
                'enabled_analyzers': {analysis_type.value: enabled for analysis_type, enabled in self.enabled_analyzers.items()},
                'clang_tidy_checks': self.clang_tidy_checks,
                'cppcheck_checks': self.cppcheck_checks,
                'max_findings_per_file': self.max_findings_per_file,
                'severity_filter': self.severity_filter.value
            }
            
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=4)
                
            print(f"Configuration saved to {config_path}")
        except Exception as e:
            print(f"Error saving config to {config_path}: {str(e)}")


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