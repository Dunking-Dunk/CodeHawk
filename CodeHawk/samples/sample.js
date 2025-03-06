// Sample JavaScript file with intentional code quality issues

// Unused variable
const unusedVar = 'never used';

// Global variable
globalVar = 'this is global without declaration';

// Function with too many parameters
function processData(data, options, config, logger, cache, timeout, retryCount, verbose) {
  // Using console.log for debugging
  console.log('Processing data...');
  
  // Using == instead of ===
  if (verbose == true) {
    console.log('Verbose mode enabled');
  }
  
  // Using undefined variable
  console.log(undefinedVar);
  
  // Unreachable code after return
  return data;
  console.log('This will never be executed');
}

// Arrow function with inconsistent return
const calculateValue = (x, y) => {
  if (x > y) {
    return x - y;
  }
  // Missing return statement for some paths
};

// Potential memory leak in event listener
document.addEventListener('click', function() {
  const element = document.createElement('div');
  // Missing cleanup code
});

// Function with high cyclomatic complexity
function complexFunction(data) {
  if (!data) {
    return null;
  }
  
  let result = 0;
  
  if (data.type === 'A') {
    if (data.value > 100) {
      if (data.priority === 'high') {
        result = data.value * 2;
      } else if (data.priority === 'medium') {
        result = data.value * 1.5;
      } else {
        result = data.value;
      }
    } else {
      result = data.value / 2;
    }
  } else if (data.type === 'B') {
    if (data.enabled) {
      result = data.value * 3;
    } else {
      result = 0;
    }
  } else {
    result = -1;
  }
  
  return result;
}

// Unsafe string concatenation (potential XSS)
function displayUserInput(input) {
  const element = document.getElementById('output');
  element.innerHTML = input; // Unsafe
}

// Object with duplicate keys
const config = {
  name: 'Config',
  version: 1,
  name: 'Updated Config' // Duplicate key
};

// Comparison with NaN
function checkValue(value) {
  if (value === NaN) { // Always false
    return 'Invalid';
  }
  return 'Valid';
}

// Export for use in other files
module.exports = {
  processData,
  calculateValue,
  complexFunction,
  displayUserInput,
  checkValue
}; 