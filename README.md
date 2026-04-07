# EnvWatch - Environment Secret Scanner

EnvWatch is a Go-based security scanner that detects exposed secrets, API keys, passwords, and sensitive credentials across your system. It performs comprehensive scans of environment variables, configuration files, SSH keys, and cloud credentials.

## Features

- **Environment Variable Scanning**: Detects secret-related environment variables on the system
- **Configuration File Scanning**: Searches for sensitive data in:
  - `.env` files
  - `.yml` and `.yaml` configuration files
  - `.pem` and `.key` private key files
- **Common Credential Detection**: Scans standard credential locations:
  - AWS credentials (`~/.aws/credentials` and `~/.aws/config`)
  - Git credentials (`~/.git-credentials`)
  - Docker config (`~/.docker/config.json`)
- **SSH Key Detection**: Identifies private keys in `~/.ssh/` directory
- **JSON Report Export**: Generates detailed `secret_report.json` with all findings

## Secret Detection Keywords

EnvWatch identifies variables containing these keywords:
- `PASSWORD`, `PASS`
- `SECRET`
- `API_KEY`, `APIKEY`
- `TOKEN`
- `AWS_SECRET`
- `PRIVATE_KEY`
- `ACCESS_KEY`
- `DB_PASSWORD`

## Installation

### Prerequisites
- Go 1.16 or later

## Usage

### Basic Execution
```bash
go run envwatch.go
```

The scanner will:
1. Scan all environment variables
2. Recursively scan your home directory for sensitive files
3. Check common credential file locations
4. Scan your SSH directory for private keys
5. Export results to `secret_report.json`

### Output

**Console Output:**
- Real-time detection messages for found secrets
- File scanning progress updates
- Completion confirmation with report location

**JSON Report** (`secret_report.json`):
```json
{
  "source": "environment|.env file|yaml file|key file|aws file|ssh key",
  "file": "path/to/file",
  "variable": "variable_name",
  "value": "secret_value or [REDACTED]"
}
```

## Example Output

```
EnvSecretScanner - Full System Scan
-----------------------------------
Scanning environment variables...

Secret detected (ENV): AWS_SECRET_ACCESS_KEY
Secret detected (ENV): DATABASE_PASSWORD

Scanning system for sensitive files...

Found file: /home/user/.env
Secret detected (.env): API_KEY (file: /home/user/.env)

Scanning common credential locations...

Scanning AWS file: /home/user/.aws/credentials
Secret detected (AWS): [profile]: aws_secret_access_key

Scanning SSH directory...

Private key detected: /home/user/.ssh/id_rsa

JSON report saved to secret_report.json
```

## Security Considerations

**Important**: This tool can expose sensitive information. Use responsibly:
- Run with appropriate permissions
- Secure the generated `secret_report.json` file
- Review results before sharing
- Consider running in isolated environments during testing
- The tool stores actual values for non-environment secrets by default

## Use Cases

- **Security Audits**: Identify exposed secrets in your infrastructure
- **DevSecOps**: Automated secret detection in CI/CD pipelines
- **Configuration Review**: Validate that sensitive data isn't hardcoded
- **Compliance Checks**: Ensure credentials aren't stored insecurely
- **Incident Response**: Locate compromise surfaces during security incidents

## Output Files

- `secret_report.json` - Comprehensive JSON report of all detected secrets

## Performance

EnvWatch optimizes performance by:
- Limiting file system scans to user home directory (safer and faster than root)
- Skipping system directories (`/proc`, `/sys`, `/dev`, `/run`)
- Stopping directory traversal when entering these directories
- Using efficient string matching for keyword detection