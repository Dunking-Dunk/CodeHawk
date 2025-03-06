#!/usr/bin/env python3
"""
CodeHawk CLI - Command-line interface for the CodeHawk code analysis tool
"""

import sys
import os

# Ensure the current directory is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # First try importing directly
    from code_analysis import main
except ImportError:
    try:
        # Try with relative import
        from .code_analysis import main
    except ImportError:
        print("Error: Could not import code_analysis module. Make sure it exists in the same directory.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 