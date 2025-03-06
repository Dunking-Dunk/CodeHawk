#!/usr/bin/env python3
"""
CodeHawk CLI - Command-line interface for the CodeHawk code analysis tool
"""

import sys
import os

# Ensure the current directory is in the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(current_dir))

try:
    # Try importing as a package first
    from codeAnalysis.code_analysis import main
except ImportError:
    try:
        # Try relative import
        from .code_analysis import main
    except ImportError:
        try:
            # Try direct import
            from code_analysis import main
        except ImportError:
            print("Error: Could not import code_analysis module. Make sure it exists in the same directory.")
            sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 