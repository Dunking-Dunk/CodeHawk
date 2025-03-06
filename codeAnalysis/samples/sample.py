"""
Sample Python file with intentional code quality issues for testing the analyzer.
"""

import os
import sys
import random
import json
import time # Unused import

# Global variable without type annotation
GLOBAL_CONSTANT = 42

# Function with too many arguments
def process_data(data, options, config, logger, cache, timeout, retry_count, verbose):
    """Process the data with various options."""
    # Unused variable
    result_status = "pending"
    
    # Using a variable before assignment
    print(f"Processing with mode: {mode}")
    
    mode = options.get("mode", "default")
    
    # Complex nested conditional (high cyclomatic complexity)
    if data:
        if isinstance(data, dict):
            if "items" in data:
                for item in data["items"]:
                    if isinstance(item, dict) and "value" in item:
                        if item["value"] > 100:
                            if verbose:
                                print(f"High value: {item['value']}")
                                return item["value"] * 2
                            else:
                                return item["value"]
                        else:
                            return item["value"] // 2
    
    # Magic number
    timeout_seconds = 3600
    
    # Potential security issue - shell injection
    if "command" in config:
        os.system(f"echo {config['command']}")
    
    # Inconsistent return types
    if random.choice([True, False]):
        return "Success"
    else:
        return 0


class BadClass:
    """A class with various issues."""
    
    def __init__(self):
        self.data = []
        self.count = 0
        # Missing initialization
        # self.name = None
    
    def add_item(self, item):
        # No type hints
        self.data.append(item)
        self.count += 1
        # No return statement
    
    def get_stats(self):
        """Return statistics about the items."""
        # Accessing potentially undefined attribute
        print(f"Name: {self.name}")
        
        # Returning different types
        if not self.data:
            return None
        
        result = {
            "count": self.count,
            "items": len(self.data)
        }
        
        # Inconsistent return
        return json.dumps(result)


# Unused function
def unused_helper():
    """This function is never used."""
    return "Helper result"


if __name__ == "__main__":
    # Creating global variables in the main block
    debug_mode = True
    
    # Direct instantiation without error handling
    instance = BadClass()
    
    # Calling a function without checking return value
    process_data({}, {}, {}, None, None, 0, 0, False)
    
    # Never closed file handle (resource leak)
    f = open("sample.txt", "w")
    f.write("Sample content")
    # f.close() - missing close 