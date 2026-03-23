## EnvWatch - Environment Secret Scanner

A Go utility that scans your system for exposed secrets in environment variables and `.env` files.

## Overview

EnvWatch is a security-focused tool that helps identify potential secrets and sensitive credentials that may be exposed in your system's environment variables and `.env` configuration files. It performs comprehensive scans and generates detailed JSON reports of findings.

## Features

- **Environment Variable Scanning**: Detects secrets in active environment variables
- **File System Scanning**: Recursively searches the system for `.env` files
- **Secret Detection**: Identifies variables containing sensitive keywords:
  - `PASSWORD`
  - `PASS`
  - `SECRET`
  - `API_KEY` / `APIKEY`
  - `TOKEN`
  - `AWS_SECRET`
  - `PRIVATE_KEY`
  - `ACCESS_KEY`
  - `DB_PASSWORD`
- **JSON Report Export**: Generates a structured report of all detected secrets

## Requirements

- Go 1.16 or higher

## Usage

Run the scanner:

```bash
go run envwatch.go .
```

The tool will:
1. Scan all environment variables in the current session
2. Search the system for `.env` files
3. Generate a `secret_report.json` file with results

## Output

The tool generates a `secret_report.json` file containing detected secrets with the following structure:

```json
[
  {
    "source": "environment",
    "file": "system",
    "variable": "API_KEY",
    "value": "your-secret-value"
  },
  {
    "source": ".env file",
    "file": "/path/to/.env",
    "variable": "DB_PASSWORD",
    "value": "password123"
  }
]
```

## Security Considerations

⚠️ **WARNING**: This tool outputs actual secret values in plain text to both console and JSON file. Use with caution in shared environments and properly secure the generated reports.

**Best Practices:**
- Run in isolated environments when possible
- Immediately rotate any exposed credentials found
- Secure the `secret_report.json` file containing sensitive data
- Consider this tool for security audits and CI/CD pipelines
- Use appropriate file permissions on generated reports
-