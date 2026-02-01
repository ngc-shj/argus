# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Argus, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Send an email to the maintainer with details of the vulnerability
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- Acknowledgment of your report within 48 hours
- Regular updates on the progress of fixing the vulnerability
- Credit in the security advisory (unless you prefer to remain anonymous)

### Scope

This security policy applies to:
- The Argus core codebase
- Official documentation
- CI/CD configurations

### Out of Scope

- Third-party dependencies (please report to the respective maintainers)
- Vulnerabilities in user-deployed instances due to misconfiguration

## Security Best Practices

When using Argus:

1. **API Keys**: Never commit API keys to version control. Use environment variables or `.env` files (which are gitignored)
2. **Network Scanning**: Only scan targets you have permission to scan
3. **Rate Limiting**: Respect rate limits to avoid being blocked or causing service disruption
4. **Data Handling**: Scan results may contain sensitive information. Handle them appropriately

## Responsible Disclosure

We follow responsible disclosure principles:
- Security issues will be fixed as soon as possible
- A security advisory will be published after the fix is released
- Credit will be given to reporters unless anonymity is requested
