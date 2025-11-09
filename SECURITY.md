# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly. **Do not create a public GitHub issue** for security vulnerabilities.

### How to Report

Please send a detailed report to:
- Create a **GitHub Security Advisory** (Private)
- Or email: security@[your-domain.com] (if available)

### What to Include

When reporting a vulnerability, please provide:

1. **Description**: Clear explanation of the vulnerability
2. **Affected Version(s)**: Which version(s) are vulnerable
3. **Reproduction Steps**: How to reproduce the issue
4. **Proof of Concept**: Example code or screenshots (if applicable)
5. **Impact**: Severity and potential impact
6. **Suggested Fix**: If you have one

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix Development**: Within 2 weeks (or timeline negotiated)
- **Patch Release**: ASAP after fix verification
- **Public Disclosure**: After patch is released (coordinated disclosure)

## Security Features

### Encryption

- **At Rest**: All project files are encrypted using AES-256-GCM
- **Key Derivation**: PBKDF2 with 200,000 iterations and SHA-256
- **Authentication**: GCM provides authenticated encryption
- **Random IVs and Salts**: Generated for each encryption

### Data Protection

- **100% Offline**: No data is sent to external servers
- **Local Storage Only**: All data stored in `./data/` directory
- **Project Isolation**: Each project has separate encrypted state

### Code Security

- **Input Validation**: All user inputs validated
- **No Eval**: No dynamic code execution
- **OWASP Compliance**: Follows OWASP Secure Coding Practices
- **Dependency Management**: Regular updates and vulnerability scanning

## Known Security Considerations

### Password Security

- Project passwords are NOT recoverable if lost
- Users should use strong, unique passwords
- No password reset mechanism by design (offline-first)

### File Permissions

- Ensure `data/` directory has restricted permissions (0700)
- Do not share encrypted files without the password
- Backup files should be stored securely

### Docker Security

When using Docker:

```dockerfile
# Run with restricted permissions
docker run --read-only --cap-drop=ALL app
```

## Security Best Practices

### For Users

1. **Use Strong Passwords**: Min 12 characters, mix of upper/lower/numbers/symbols
2. **Secure Storage**: Keep backups in encrypted storage
3. **Regular Updates**: Keep the application updated
4. **Access Control**: Restrict access to your assessment machine
5. **Audit Logs**: Monitor `logs/` directory for suspicious activity

### For Developers

1. **Code Review**: All PRs require security-focused review
2. **Dependency Audit**: Run `npm audit` before deploying
3. **SAST Scanning**: Use SonarQube/Checkmarx for code analysis
4. **Testing**: All security features must have test coverage
5. **Documentation**: Document all security-related changes

## Compliance

This project aims to support:

- **OWASP Top 10**: Secure coding practices
- **ASVS**: Application Security Verification Standard
- **ISC License**: Open source with clear terms
- **Data Privacy**: No personal data collection

## Security Headers (for HTTPS deployments)

When deploying with HTTPS:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

## Container Security

Dockerfile best practices applied:

- ✓ Non-root user execution
- ✓ Read-only root filesystem option
- ✓ Health checks implemented
- ✓ Minimal base image (Alpine)
- ✓ No hardcoded secrets

## Third-Party Dependencies

Security monitoring:

```bash
# Check for vulnerabilities
npm audit

# Generate SBOM
npx cyclonedx-npm

# Update dependencies
npm update
```

## Responsible Disclosure Timeline

We follow the **90-day responsible disclosure policy**:

1. **Day 1**: Vulnerability reported
2. **Days 1-30**: Assessment and fix development
3. **Days 31-60**: Patch testing and preparation
4. **Day 61-90**: Public disclosure and CVE assignment
5. **Day 90+**: Public announcement allowed

## Contact

- **Project Lead**: [GitHub Issues](https://github.com/GhostN3xus/Owasp_Checklist_testing/issues)
- **Security**: [GitHub Security Advisories](https://github.com/GhostN3xus/Owasp_Checklist_testing/security/advisories)
- **License**: ISC

---

**Last Updated**: 2024
**Version**: 1.1.0

For the latest security updates, watch the repository and subscribe to security advisories.
