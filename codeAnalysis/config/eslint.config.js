// ESLint v9.x configuration file
module.exports = [
  {
    // Global configuration
    ignores: ['node_modules/**', 'dist/**', 'build/**'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        ecmaFeatures: {
          jsx: true
        }
      },
      globals: {
        // Browser globals
        document: 'readonly',
        navigator: 'readonly',
        window: 'readonly',
        console: 'readonly',
        // Node.js globals
        process: 'readonly',
        module: 'readonly',
        require: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly'
      }
    },
    
    // Core rules
    rules: {
      // Error prevention
      'no-undef': 'error',
      'no-unused-vars': 'warn',
      
      // Stylistic rules (reduced)
      'indent': ['error', 2, { 'SwitchCase': 1 }],
      'quotes': ['error', 'single'],
      'semi': ['error', 'always'],
      
      // Security related
      'no-eval': 'error',
      'no-implied-eval': 'error'
    }
  },
  
  // TypeScript specific configuration
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: '@typescript-eslint/parser'
    },
    plugins: {
      '@typescript-eslint': '@typescript-eslint/eslint-plugin'
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/explicit-module-boundary-types': 'off'
    }
  },
  
  // React specific configuration
  {
    files: ['**/*.jsx', '**/*.tsx'],
    plugins: {
      'react': 'eslint-plugin-react'
    },
    rules: {
      'react/prop-types': 'off',
      'react/react-in-jsx-scope': 'off'
    },
    settings: {
      react: {
        version: 'detect'
      }
    }
  }
]; 