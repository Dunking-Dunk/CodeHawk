import os
import sys
import json
import argparse
from typing import Dict, List, Any, Optional
from pathlib import Path

def pydantic_model_to_dict(obj):
    """
    Convert Pydantic models to dictionaries for JSON serialization.
    Works recursively for nested models, lists and dictionaries.
    """
    if hasattr(obj, 'model_dump'):
        # Pydantic v2
        return obj.model_dump()
    elif hasattr(obj, 'dict'):
        # Pydantic v1
        return obj.dict()
    elif isinstance(obj, dict):
        return {k: pydantic_model_to_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [pydantic_model_to_dict(i) for i in obj]
    else:
        return obj

try:
    from .python_analyzer import PythonAnalyzer
except ImportError:
    try:
        from python_analyzer import PythonAnalyzer
    except ImportError:
        print("Warning: Could not import Python analyzer. Python analysis will be disabled.")
        PythonAnalyzer = None

try:
    from .javascript_analyzer import JavaScriptAnalyzer
except ImportError:
    try:
        from javascript_analyzer import JavaScriptAnalyzer
    except ImportError:
        print("Warning: Could not import JavaScript analyzer. JavaScript analysis will be disabled.")
        JavaScriptAnalyzer = None

try:
    from .java_analyzer import JavaAnalyzer
except ImportError:
    try:
        from java_analyzer import JavaAnalyzer
    except ImportError:
        print("Warning: Could not import Java analyzer. Java analysis will be disabled.")
        JavaAnalyzer = None

try:
    from .cpp_analyzer import CppAnalyzer
except ImportError:
    try:
        from cpp_analyzer import CppAnalyzer
    except ImportError:
        print("Warning: Could not import C/C++ analyzer. C/C++ analysis will be disabled.")
        CppAnalyzer = None


class CodeAnalysis:
    """
    Main code analysis tool that integrates analyzers for multiple languages.
    """
    
    def __init__(self, config_paths: Optional[Dict[str, str]] = None):
        """Initialize the code analysis tool with all available analyzers.
        
        Args:
            config_paths: Dictionary mapping language to configuration file paths
        """
        self.analyzers = {}
        self.available_analyzer_classes = {}
        self.initialized_analyzers = set()
        
      
        if config_paths is None:
            config_paths = {}
        self.config_paths = config_paths
        
       
        if PythonAnalyzer:
            self.available_analyzer_classes['python'] = PythonAnalyzer
            
        if JavaScriptAnalyzer:
            self.available_analyzer_classes['javascript'] = JavaScriptAnalyzer
            
        if JavaAnalyzer:
            self.available_analyzer_classes['java'] = JavaAnalyzer
            
        if CppAnalyzer:
            self.available_analyzer_classes['cpp'] = CppAnalyzer
    
    def get_available_analyzers(self) -> List[str]:
        """
        Get a list of available analyzers.
        
        Returns:
            List of language names for which analyzers are available
        """
        return list(self.available_analyzer_classes.keys())
    
    def _initialize_analyzer(self, analyzer_type: str) -> bool:
        """
        Initialize a specific analyzer if it hasn't been initialized yet.
        
        Args:
            analyzer_type: The type of analyzer to initialize (e.g., 'python', 'javascript')
            
        Returns:
            True if initialization successful, False otherwise
        """
        if analyzer_type in self.initialized_analyzers:
            return True
            
        if analyzer_type not in self.available_analyzer_classes:
            return False
            
        try:
            try:
                from models.analysis_models import AnalysisConfig
            except ImportError:
                try:
                    from .models.analysis_models import AnalysisConfig
                except ImportError:

                    from codeAnalysis.models.analysis_models import AnalysisConfig
            
            config = AnalysisConfig()
            
            # Initialize the analyzer with the config object
            self.analyzers[analyzer_type] = self.available_analyzer_classes[analyzer_type](config=config)
                
            self.initialized_analyzers.add(analyzer_type)
            return True
        except Exception as e:
            print(f"Error initializing {analyzer_type} analyzer: {str(e)}")
            return False
    
    def analyze_file(self, file_path: str, selected_analyzers: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze a single file using the appropriate analyzer based on file extension.
        
        Args:
            file_path: Path to the file to analyze
            selected_analyzers: List of analyzers to use (if None, use all available)
            
        Returns:
            Analysis results
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        # Determine the file type based on extension
        extension = os.path.splitext(file_path)[1].lower()
        
        # Map file extensions to analyzers
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.java': 'java',
            '.c': 'cpp',
            '.cc': 'cpp',
            '.cpp': 'cpp',
            '.cxx': 'cpp',
            '.h': 'cpp',
            '.hh': 'cpp',
            '.hpp': 'cpp',
            '.hxx': 'cpp'
        }
        
        file_type = extension_map.get(extension)
        
        if not file_type:
            return {"error": f"Unsupported file type: {extension}"}
        
        # If specific analyzers are selected, check if the file type is included
        if selected_analyzers and file_type not in selected_analyzers:
            return {"error": f"Analyzer for {file_type} not selected"}
        
        # Check if we have an analyzer class for this file type
        if file_type not in self.available_analyzer_classes:
            return {"error": f"No analyzer available for {file_type}"}
            
        # Initialize the analyzer if it hasn't been initialized yet
        if not self._initialize_analyzer(file_type):
            return {"error": f"Failed to initialize {file_type} analyzer"}
        
        # Run the appropriate analyzer
        analyzer = self.analyzers[file_type]
        return {file_type: analyzer.analyze_file(file_path)}
    
    def analyze_directory(self, directory_path: str, recursive: bool = True, selected_analyzers: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze all supported files in a directory.
        
        Args:
            directory_path: Path to the directory to analyze
            recursive: Whether to analyze subdirectories
            selected_analyzers: List of analyzers to use (if None, use all available)
            
        Returns:
            Analysis results grouped by language
        """
        if not os.path.isdir(directory_path):
            return {"error": f"Directory not found: {directory_path}"}
        
        results = {}
        
        # Determine which analyzers to use
        analyzer_types = selected_analyzers if selected_analyzers else self.get_available_analyzers()
        
        # Initialize and run each selected analyzer
        for analyzer_type in analyzer_types:
            if analyzer_type not in self.available_analyzer_classes:
                results[analyzer_type] = {"error": f"No analyzer available for {analyzer_type}"}
                continue
                
            # Initialize the analyzer if it hasn't been initialized yet
            if not self._initialize_analyzer(analyzer_type):
                results[analyzer_type] = {"error": f"Failed to initialize {analyzer_type} analyzer"}
                continue
                
            # Run the analyzer on the directory
            analyzer = self.analyzers[analyzer_type]
            results[analyzer_type] = analyzer.analyze_directory(directory_path, recursive)
        
        return results
    
    def run_analysis(self, code: str, file_path: Optional[str] = None, selected_analyzers: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run analysis on code provided as a string.
        
        Args:
            code: The code to analyze as a string
            file_path: Optional file path to determine the language
            selected_analyzers: List of analyzers to use (if None, use all available)
            
        Returns:
            Analysis results
        """
        # If no file path is provided, we need to guess the language
        if not file_path:
            return {"error": "Cannot determine language without a file path"}
        
        # Create a temporary file with the provided code
        temp_dir = os.path.join(os.getcwd(), "temp_analysis")
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_file = os.path.join(temp_dir, os.path.basename(file_path))
        
        try:
            with open(temp_file, 'w') as f:
                f.write(code)
                
            # Run analysis on the temporary file
            results = self.analyze_file(temp_file, selected_analyzers)
            return results
            
        finally:
            # Clean up
            if os.path.exists(temp_file):
                os.remove(temp_file)


def main():
    """Main function to run the code analysis tool from the command line."""
    parser = argparse.ArgumentParser(description="CodeHawk - Multi-language Static Code Analysis Tool")
    
    # Add arguments
    parser.add_argument("path", help="Path to the file or directory to analyze")
    parser.add_argument("-r", "--recursive", action="store_true", help="Analyze subdirectories recursively")
    parser.add_argument("-a", "--analyzer", nargs="+", help="Specific analyzers to run (e.g., python javascript)", dest="analyzers")
    parser.add_argument("-f", "--format", choices=["text", "json", "html"], default="text", help="Output format")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument("-l", "--list", action="store_true", help="List available analyzers")
    parser.add_argument("-c", "--config", nargs="+", help="Configuration files in the format language:path (e.g., python:/path/to/config.yaml)")
    
    args = parser.parse_args()
    
    # Parse configuration files
    config_paths = {}
    if args.config:
        for config_arg in args.config:
            if ":" in config_arg:
                lang, path = config_arg.split(":", 1)
                config_paths[lang] = path
            else:
                print(f"Warning: Invalid config format: {config_arg}. Expected format is language:path")
    
    # Create the code analysis tool with configurations
    analyzer = CodeAnalysis(config_paths)
    
    # List available analyzers if requested
    if args.list:
        print("Available analyzers:")
        for lang in analyzer.get_available_analyzers():
            print(f"- {lang}")
        return
    
    # Check if the path exists
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}")
        return
    
    # Run analysis on file or directory
    if os.path.isfile(args.path):
        results = analyzer.analyze_file(args.path, args.analyzers)
    else:
        results = analyzer.analyze_directory(args.path, args.recursive, args.analyzers)
    
    # Convert Pydantic models to dictionaries for JSON serialization
    results = pydantic_model_to_dict(results)
    
    # Format the output
    if args.format == "json":
        output = json.dumps(results, indent=2)
    elif args.format == "html":
        # Create a more modern and interactive HTML report
        output = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeHawk Analysis Report</title>
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2c3e50;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #1abc9c;
            --light-color: #ecf0f1;
            --dark-color: #34495e;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f9f9f9;
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background-color: var(--secondary-color);
            color: white;
            padding: 20px;
            border-radius: 5px 5px 0 0;
            margin-bottom: 20px;
        }
        
        h1 {
            margin-bottom: 10px;
            font-weight: 300;
            font-size: 2.5rem;
        }
        
        h2 {
            color: var(--secondary-color);
            margin: 20px 0 10px;
            padding-bottom: 5px;
            border-bottom: 2px solid var(--primary-color);
            font-weight: 400;
        }
        
        .summary {
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .summary-card {
            background-color: var(--light-color);
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        
        .summary-card h3 {
            margin-bottom: 10px;
            font-weight: 500;
        }
        
        .summary-card .count {
            font-size: 2rem;
            font-weight: 300;
            color: var(--primary-color);
        }
        
        .analysis-section {
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.95rem;
        }
        
        th {
            background-color: var(--secondary-color);
            color: white;
            text-align: left;
            padding: 12px 15px;
            position: sticky;
            top: 0;
            cursor: pointer;
        }
        
        th:hover {
            background-color: var(--dark-color);
        }
        
        td {
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        .severity {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-critical {
            background-color: var(--danger-color);
        }
        
        .severity-high {
            background-color: #ff5722;
        }
        
        .severity-medium {
            background-color: var(--warning-color);
        }
        
        .severity-low {
            background-color: #3498db;
        }
        
        .severity-info {
            background-color: var(--info-color);
        }
        
        .code-location {
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
        }
        
        .filters {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .filter-select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: white;
            color: var(--secondary-color);
        }
        
        .filter-button {
            padding: 8px 12px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .search-input {
            flex-grow: 1;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        
        .no-findings {
            padding: 20px;
            text-align: center;
            color: #777;
            font-style: italic;
        }
        
        .expandable-row {
            cursor: pointer;
        }
        
        .expandable-row.expanded {
            background-color: #f0f7ff;
        }
        
        .issue-details {
            display: none;
            padding: 10px 15px 10px 45px;
            background-color: #f0f7ff;
            border-bottom: 1px solid #ddd;
        }
        
        .expanded + .issue-details {
            display: table-row;
        }
        
        .details-title {
            font-weight: 500;
            margin-top: 8px;
            margin-bottom: 4px;
        }
        
        .fix-suggestions {
            margin-top: 4px;
            padding-left: 20px;
        }
        
        .fix-suggestion {
            margin-bottom: 2px;
        }
        
        footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.85rem;
            color: #777;
        }
    </style>
</head>
<body>
    <header>
        <h1>CodeHawk Analysis Report</h1>
        <p>Static code analysis for: ${args.path}</p>
    </header>
    
    <div class="summary">
        <h2>Analysis Summary</h2>
        <div class="summary-grid">"""
        
        # Count total issues by severity
        total_findings = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        total_by_language = {}
        
        # Process results to count findings
        for lang, lang_results in results.items():
            lang_count = 0
            
            # Handle different result formats from different analyzers
            if isinstance(lang_results, dict) and "findings" in lang_results:
                # Standard format with findings list
                findings = lang_results.get("findings", [])
                lang_count = len(findings)
                
                # Count by severity
                for finding in findings:
                    severity = finding.get("severity", "").lower()
                    if severity in total_findings:
                        total_findings[severity] += 1
            
            elif lang == "python" and "messages" in lang_results:
                # Python specific format
                messages = lang_results.get("messages", [])
                lang_count = len(messages)
                
                # Map severity
                for msg in messages:
                    severity = "medium"  # Default
                    if msg.get("type") == "error":
                        severity = "high"
                    elif msg.get("type") == "warning":
                        severity = "medium"
                    
                    if severity in total_findings:
                        total_findings[severity] += 1
            
            elif lang == "javascript" and isinstance(lang_results, list):
                # JavaScript format
                total_issues = sum(len(file_result.get("messages", [])) for file_result in lang_results)
                lang_count = total_issues
                
                # Count by severity
                for file_result in lang_results:
                    for msg in file_result.get("messages", []):
                        severity = "medium"  # Default
                        if msg.get("severity") == 2:
                            severity = "high"
                        elif msg.get("severity") == 1:
                            severity = "medium"
                        
                        if severity in total_findings:
                            total_findings[severity] += 1
            
            # Store language total
            total_by_language[lang] = lang_count
        
        # Add summary cards
        total_issues = sum(total_findings.values())
        output += f"""
            <div class="summary-card">
                <h3>Total Issues</h3>
                <div class="count">{total_issues}</div>
            </div>"""
        
        # Add severity summary cards
        for severity, count in total_findings.items():
            if count > 0:
                output += f"""
            <div class="summary-card">
                <h3>{severity.capitalize()}</h3>
                <div class="count">{count}</div>
            </div>"""
        
        # Add language summary cards
        for lang, count in total_by_language.items():
            if count > 0:
                output += f"""
            <div class="summary-card">
                <h3>{lang.capitalize()}</h3>
                <div class="count">{count}</div>
            </div>"""
        
        output += """
        </div>
    </div>
    """
        
        # Format each language's results
        for lang, lang_results in results.items():
            output += f"""
    <div class="analysis-section">
        <h2>{lang.capitalize()} Analysis</h2>
        <div class="filters">
            <input type="text" class="search-input" placeholder="Search issues..." onkeyup="filterTable('{lang}')">
            <select class="filter-select" id="{lang}-severity-filter" onchange="filterTable('{lang}')">
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
            </select>
            <button class="filter-button" onclick="resetFilters('{lang}')">Reset Filters</button>
        </div>
    """
            
            # Handle different result formats from different analyzers
            if isinstance(lang_results, dict) and "findings" in lang_results:
                # Standard format with findings list
                findings = lang_results.get("findings", [])
                
                output += f"""
        <table id="{lang}-table">
            <thead>
                <tr>
                    <th onclick="sortTable('{lang}-table', 0)">Severity</th>
                    <th onclick="sortTable('{lang}-table', 1)">Message</th>
                    <th onclick="sortTable('{lang}-table', 2)">Location</th>
                    <th onclick="sortTable('{lang}-table', 3)">Rule</th>
                </tr>
            </thead>
            <tbody>
        """
                
                if not findings:
                    output += f"""
                <tr>
                    <td colspan="4" class="no-findings">No issues found for {lang}</td>
                </tr>
            """
                else:
                    for i, finding in enumerate(findings):
                        severity = finding.get("severity", "").lower()
                        message = finding.get("message", "")
                        location = finding.get("location", {})
                        file_path = location.get("file", "")
                        line = location.get("line_start", "")
                        column = location.get("column_start", "")
                        location_text = f"{os.path.basename(file_path)}:{line}"
                        if column:
                            location_text += f":{column}"
                        rule_id = finding.get("rule_id", "")
                        
                        output += f"""
                <tr class="expandable-row" onclick="toggleDetails(this)">
                    <td><span class="severity severity-{severity}">{severity}</span></td>
                    <td>{message}</td>
                    <td><span class="code-location">{location_text}</span></td>
                    <td>{rule_id}</td>
                </tr>
                <tr class="issue-details">
                    <td colspan="4">
                        <div class="details-title">File:</div>
                        <div>{file_path}</div>
                """
                        
                        # Add fix suggestions if available
                        fix_suggestions = finding.get("fix_suggestions", [])
                        if fix_suggestions:
                            output += """
                        <div class="details-title">Fix Suggestions:</div>
                        <ul class="fix-suggestions">
                        """
                            
                            for suggestion in fix_suggestions:
                                output += f"""
                            <li class="fix-suggestion">{suggestion}</li>
                        """
                            
                            output += """
                        </ul>
                        """
                        
                        output += """
                    </td>
                </tr>
                """
            
            elif lang == "python" and "messages" in lang_results:
                # Python specific format
                messages = lang_results.get("messages", [])
                
                output += f"""
        <table id="{lang}-table">
            <thead>
                <tr>
                    <th onclick="sortTable('{lang}-table', 0)">Severity</th>
                    <th onclick="sortTable('{lang}-table', 1)">Message</th>
                    <th onclick="sortTable('{lang}-table', 2)">Location</th>
                    <th onclick="sortTable('{lang}-table', 3)">Source</th>
                </tr>
            </thead>
            <tbody>
        """
                
                if not messages:
                    output += f"""
                <tr>
                    <td colspan="4" class="no-findings">No issues found for {lang}</td>
                </tr>
            """
                else:
                    for msg in messages:
                        severity = "medium"  # Default
                        severity_class = "severity-medium"
                        
                        if msg.get("type") == "error":
                            severity = "high"
                            severity_class = "severity-high"
                        elif msg.get("type") == "warning":
                            severity = "medium"
                            severity_class = "severity-medium"
                        
                        message = msg.get("message", "")
                        source = msg.get("source", "")
                        code = msg.get("code", "")
                        location = msg.get("location", {})
                        file_path = location.get("path", "")
                        line = location.get("line", "")
                        
                        output += f"""
                <tr class="expandable-row" onclick="toggleDetails(this)">
                    <td><span class="severity {severity_class}">{severity}</span></td>
                    <td>{message}</td>
                    <td><span class="code-location">{os.path.basename(file_path)}:{line}</span></td>
                    <td>{source}:{code}</td>
                </tr>
                <tr class="issue-details">
                    <td colspan="4">
                        <div class="details-title">File:</div>
                        <div>{file_path}</div>
                    </td>
                </tr>
                """
            
            elif lang == "javascript" and isinstance(lang_results, list):
                # JavaScript format
                output += f"""
        <table id="{lang}-table">
            <thead>
                <tr>
                    <th onclick="sortTable('{lang}-table', 0)">Severity</th>
                    <th onclick="sortTable('{lang}-table', 1)">Message</th>
                    <th onclick="sortTable('{lang}-table', 2)">Location</th>
                    <th onclick="sortTable('{lang}-table', 3)">Rule</th>
                </tr>
            </thead>
            <tbody>
        """
                
                has_messages = False
                for file_result in lang_results:
                    messages = file_result.get("messages", [])
                    file_path = file_result.get("filePath", "")
                    
                    if messages:
                        has_messages = True
                        
                    for msg in messages:
                        severity = "medium"  # Default
                        severity_class = "severity-medium"
                        
                        if msg.get("severity") == 2:
                            severity = "high"
                            severity_class = "severity-high"
                        elif msg.get("severity") == 1:
                            severity = "medium"
                            severity_class = "severity-medium"
                        
                        message = msg.get("message", "")
                        line = msg.get("line", "")
                        column = msg.get("column", "")
                        rule_id = msg.get("ruleId", "")
                        
                        output += f"""
                <tr class="expandable-row" onclick="toggleDetails(this)">
                    <td><span class="severity {severity_class}">{severity}</span></td>
                    <td>{message}</td>
                    <td><span class="code-location">{os.path.basename(file_path)}:{line}:{column}</span></td>
                    <td>{rule_id}</td>
                </tr>
                <tr class="issue-details">
                    <td colspan="4">
                        <div class="details-title">File:</div>
                        <div>{file_path}</div>
                    </td>
                </tr>
                """
                
                if not has_messages:
                    output += f"""
                <tr>
                    <td colspan="4" class="no-findings">No issues found for {lang}</td>
                </tr>
            """
            else:
                # Generic format for other languages
                output += f"""
        <pre>{json.dumps(lang_results, indent=2)}</pre>
        """
            
            output += """
            </tbody>
        </table>
    </div>
            """
        
        # Add JavaScript for interactivity
        output += """
    <footer>
        Generated by CodeHawk Static Analysis Tool
    </footer>

    <script>
        // Function to toggle details visibility
        function toggleDetails(row) {
            row.classList.toggle('expanded');
        }
        
        // Function to sort table
        function sortTable(tableId, columnIndex) {
            const table = document.getElementById(tableId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr.expandable-row'));
            
            // Get current sort direction
            const currentDir = table.getAttribute('data-sort-dir') || 'asc';
            const newDir = currentDir === 'asc' ? 'desc' : 'asc';
            
            // Update table sort attributes
            table.setAttribute('data-sort-dir', newDir);
            table.setAttribute('data-sort-col', columnIndex);
            
            // Sort the rows
            rows.sort((a, b) => {
                const aValue = a.cells[columnIndex].textContent.trim();
                const bValue = b.cells[columnIndex].textContent.trim();
                
                // For severity column, use custom order
                if (columnIndex === 0) {
                    const severityOrder = {
                        'critical': 0,
                        'high': 1,
                        'medium': 2,
                        'low': 3,
                        'info': 4
                    };
                    
                    const aOrder = severityOrder[aValue.toLowerCase()] || 999;
                    const bOrder = severityOrder[bValue.toLowerCase()] || 999;
                    
                    return newDir === 'asc' ? aOrder - bOrder : bOrder - aOrder;
                }
                
                // Regular string comparison for other columns
                const comparison = aValue.localeCompare(bValue);
                return newDir === 'asc' ? comparison : -comparison;
            });
            
            // Reorder the rows in the DOM
            rows.forEach(row => {
                const detailsRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (detailsRow && detailsRow.classList.contains('issue-details')) {
                    tbody.appendChild(detailsRow);
                }
            });
        }
        
        // Function to filter table
        function filterTable(lang) {
            const tableId = `${lang}-table`;
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tbody tr.expandable-row');
            
            // Get the search input and severity filter for this table's section
            // Use more compatible selector approach instead of :has()
            const sections = document.querySelectorAll('.analysis-section');
            let searchInput, severityFilter;
            
            for (const section of sections) {
                if (section.querySelector(`#${tableId}`)) {
                    searchInput = section.querySelector('.search-input');
                    severityFilter = document.getElementById(`${lang}-severity-filter`);
                    break;
                }
            }
            
            if (!searchInput || !severityFilter) return;
            
            const searchTerm = searchInput.value.toLowerCase();
            const severityValue = severityFilter.value.toLowerCase();
            
            rows.forEach(row => {
                const detailsRow = row.nextElementSibling;
                let shouldShow = true;
                
                // Check search term
                if (searchTerm) {
                    const rowText = row.textContent.toLowerCase();
                    if (!rowText.includes(searchTerm)) {
                        shouldShow = false;
                    }
                }
                
                // Check severity filter
                if (severityValue !== 'all') {
                    const severityCell = row.cells[0].textContent.toLowerCase();
                    if (severityCell !== severityValue) {
                        shouldShow = false;
                    }
                }
                
                // Show/hide rows
                row.style.display = shouldShow ? '' : 'none';
                if (detailsRow) {
                    detailsRow.style.display = 'none'; // Always hide details when filtering
                }
            });
        }
        
        // Function to reset filters
        function resetFilters(lang) {
            const tableId = `${lang}-table`;
            
            // Use more compatible selector approach
            const sections = document.querySelectorAll('.analysis-section');
            let searchInput, severityFilter;
            
            for (const section of sections) {
                if (section.querySelector(`#${tableId}`)) {
                    searchInput = section.querySelector('.search-input');
                    severityFilter = document.getElementById(`${lang}-severity-filter`);
                    break;
                }
            }
            
            if (!searchInput || !severityFilter) return;
            
            searchInput.value = '';
            severityFilter.value = 'all';
            
            filterTable(lang);
        }
    </script>
</body>
</html>"""
    else:  # text format
        output = f"CodeHawk Analysis Report for {args.path}\n"
        output += "=" * 40 + "\n\n"
        
        for lang, lang_results in results.items():
            output += f"{lang.upper()} ANALYSIS\n"
            output += "-" * 20 + "\n"
            output += json.dumps(lang_results, indent=2) + "\n\n"
    
    # Output the results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main() 