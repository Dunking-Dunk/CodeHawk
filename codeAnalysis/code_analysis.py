import os
import sys
import json
import argparse
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import the individual language analyzers
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
        
        # Initialize config paths if not provided
        if config_paths is None:
            config_paths = {}
        self.config_paths = config_paths
        
        # Register available analyzer classes without initializing them
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
            if analyzer_type == 'python':
                self.analyzers[analyzer_type] = self.available_analyzer_classes[analyzer_type](
                    config_path=self.config_paths.get('python')
                )
            elif analyzer_type == 'javascript':
                self.analyzers[analyzer_type] = self.available_analyzer_classes[analyzer_type](
                    config_path=self.config_paths.get('javascript')
                )
            elif analyzer_type == 'java':
                self.analyzers[analyzer_type] = self.available_analyzer_classes[analyzer_type](
                    pmd_path=self.config_paths.get('java_pmd'),
                    spotbugs_path=self.config_paths.get('java_spotbugs')
                )
            elif analyzer_type == 'cpp':
                self.analyzers[analyzer_type] = self.available_analyzer_classes[analyzer_type](
                    config_path=self.config_paths.get('cpp')
                )
            else:
                # Generic initialization for any other analyzers
                self.analyzers[analyzer_type] = self.available_analyzer_classes[analyzer_type]()
                
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
    
    # Format the output
    if args.format == "json":
        output = json.dumps(results, indent=2)
    elif args.format == "html":
        # Create a simple HTML report
        output = "<html><head><title>CodeHawk Analysis Report</title>"
        output += "<style>body{font-family:sans-serif;margin:20px;} h1{color:#333;} "
        output += ".issue{margin-bottom:10px;padding:5px;border-left:3px solid #ccc;} "
        output += ".error{border-color:red;} .warning{border-color:orange;}</style></head>"
        output += f"<body><h1>Analysis Report for {args.path}</h1>"
        
        # Format each language's results
        for lang, lang_results in results.items():
            output += f"<h2>{lang.capitalize()} Analysis</h2>"
            
            # Handle different result formats from different analyzers
            if lang == "python" and "messages" in lang_results:
                output += f"<p>Found {len(lang_results['messages'])} issues</p>"
                for msg in lang_results["messages"]:
                    severity_class = "error" if msg.get("type") == "error" else "warning"
                    output += f"<div class='issue {severity_class}'>"
                    output += f"<strong>{msg.get('source')}:{msg.get('code')}</strong>: "
                    output += f"{msg.get('message')} "
                    location = msg.get("location", {})
                    output += f"({location.get('path')}:{location.get('line')})"
                    output += "</div>"
            elif lang == "javascript" and isinstance(lang_results, list):
                total_issues = sum(len(file_result.get("messages", [])) for file_result in lang_results)
                output += f"<p>Found {total_issues} issues</p>"
                for file_result in lang_results:
                    for msg in file_result.get("messages", []):
                        severity_class = "error" if msg.get("severity") == 2 else "warning"
                        output += f"<div class='issue {severity_class}'>"
                        output += f"<strong>{msg.get('ruleId')}</strong>: "
                        output += f"{msg.get('message')} "
                        output += f"({file_result.get('filePath')}:{msg.get('line')}:{msg.get('column')})"
                        output += "</div>"
            else:
                output += f"<pre>{json.dumps(lang_results, indent=2)}</pre>"
                
        output += "</body></html>"
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