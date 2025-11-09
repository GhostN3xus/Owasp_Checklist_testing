# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-11-09

### 🎉 Major Features

#### Project Management with Encryption
- **Encrypted Projects**: AES-256-GCM encryption with PBKDF2 key derivation (200k iterations)
- **Project Isolation**: Each project has separate encrypted state with unique passwords
- **Persistent Storage**: Projects saved in `data/<projectId>/` with encrypted `state.json`
- **Migration Tool**: Script to migrate existing plaintext projects to encrypted format (`scripts/migrate-plaintext-to-encrypted.mjs`)

#### Standards Mapping
- **ASVS v4.0**: 30+ security verification items with detailed descriptions
- **MASVS v2.0**: 20+ mobile security items for Android & iOS
- **OWASP API Security 2023**: 20+ API security checks including GraphQL, REST, OAuth, JWT
- **WSTG v4.2**: 45+ web security testing items
- **Standards Loader**: CSV-based standard import with search functionality

#### Evidence & Findings Management
- **Evidence Tracking**: Attach files, images, and notes to each check
- **CVSS v3.1**: Full CVSS score calculator with base/temporal/environmental metrics
- **CWE/MITRE Mapping**: Link checks to CWE IDs and MITRE ATT&CK techniques
- **Check States**: Track status (passed/failed/na/not-tested) and severity

#### Export Functionality
- **PDF Reports**: Complete assessment reports with metrics, findings, and evidence
- **CSV Export**: Checks, findings, and summary data in standard CSV format
- **JSON Export**: Full project data dump in machine-readable format
- **Report Templates**: Professional HTML/CSS templates with branding

### 🔒 Security Improvements

- **Encrypted Storage**: All project data encrypted at rest using military-grade AES-256-GCM
- **Key Derivation**: PBKDF2 with SHA-256 hash and 200,000 iterations
- **No External Dependencies**: 100% offline operation - zero data transmission
- **Secure Defaults**: Read-only filesystem option, restricted permissions in Docker
- **Input Validation**: All user inputs validated before processing

### 🐳 DevOps & Deployment

#### Docker Support
- **Dockerfile**: Multi-stage build with Alpine base
- **docker-compose.yml**: Single command deployment with volumes for data and logs
- **Health Checks**: Built-in health status monitoring
- **Environment Configuration**: Configurable port and log levels

#### GitHub Actions CI/CD
- **Automated Testing**: Unit tests (Vitest) + E2E tests (Playwright)
- **Code Quality**: ESLint and Prettier on every push
- **Security Scanning**: Dependency vulnerability check, secret scanning
- **Build Artifacts**: Automated build and upload to artifacts
- **CodeQL Analysis**: Advanced code security analysis

### 🧪 Testing

#### Unit Tests
- **Crypto Module**: AES-GCM encryption/decryption tests
- **CVSS Calculator**: Vector parsing and score calculation
- **CSV Loader**: Standard import and search functionality
- **Project Manager**: State management and persistence

#### E2E Tests
- **Project Workflow**: Create, encrypt, reopen with password
- **Evidence Management**: Add/remove evidence, track findings
- **Export Validation**: PDF/CSV/JSON export verification
- **Standards Integration**: Search and filter standards

### 📝 Documentation

#### New Files
- **SECURITY.md**: Security policy and vulnerability disclosure
- **CONTRIBUTING.md**: Developer guidelines and contribution workflow
- **CODE_OF_CONDUCT.md**: Community standards and expectations
- **CHANGELOG.md**: Version history and release notes
- **Issue Templates**: Bug report and feature request templates

#### Technical Guides (content/guides/)
- **Auth/OAuth/OIDC**: Authentication flows and implementation
- **CORS & WebSockets**: Modern web communication security
- **SSRF & Cloud Security**: Cloud-specific vulnerabilities
- **Kubernetes & IaC**: Container orchestration security
- **Secrets Management**: Secret detection and rotation
- **Supply Chain Security**: SBOM, SLSA, and dependency management
- **Fuzzing & Testing**: Advanced testing methodologies
- **Privacy & LGPD**: Data protection regulations
- **LLM AppSec**: AI/ML security considerations

### 🛠️ Development Tools

#### Scripts
- `npm run dev`: Development server (no build)
- `npm run test:unit`: Unit tests only
- `npm run test:e2e`: E2E tests only
- `npm run lint`: ESLint code style check
- `npm run format`: Prettier auto-format
- `npm run migrate:encrypt`: Migrate plaintext to encrypted projects

#### Configuration Files
- **.eslintrc**: JavaScript linting rules
- **.prettierrc**: Code formatting configuration
- **.editorconfig**: Cross-editor consistency
- **playwright.config.js**: E2E testing framework
- **.github/workflows/ci.yml**: GitHub Actions pipeline

### 📦 Dependencies Added

#### Production
- (Using existing: express, lowdb, multer)

#### Development
- **@playwright/test**: E2E testing framework
- **eslint**: Code linting
- **prettier**: Code formatting

### 🔄 API Changes

#### New Routes
- `POST /api/projects/create`: Create encrypted project
- `POST /api/projects/:id/unlock`: Unlock with password
- `GET /api/projects/list`: List available projects
- `POST /api/projects/:id/save`: Save project state
- `GET /api/standards`: Load all standards
- `GET /api/standards/search?q=query`: Search standards
- `POST /api/export/pdf`: Export project to PDF
- `POST /api/export/csv`: Export to CSV
- `POST /api/export/json`: Export to JSON

### 🎯 Breaking Changes

None - fully backward compatible with v1.0.0

### 🐛 Bug Fixes

- Fixed CVSS calculation edge cases
- Improved error handling in CSV parsing
- Better validation of project state

### ⚠️ Deprecations

None

### 🔮 Future Roadmap

- **Batch Import**: Import multiple projects
- **Team Collaboration**: Share projects with encryption key sharing
- **Webhooks**: Integration with security tools
- **Custom Standards**: User-defined checklist creation
- **Analytics Dashboard**: Advanced metrics and trends
- **Mobile App**: Native iOS/Android applications
- **Cloud Sync**: Optional encrypted cloud backup
- **AI Assistant**: GPT-powered remediation suggestions

---

## [1.0.0] - 2024-09-15

### Initial Release

- **13 Security Modules**: OWASP Web, API, Mobile, Cloud, DevSecOps, etc.
- **300+ Checklist Items**: Comprehensive coverage of security domains
- **Dark Theme UI**: Professional interface with responsive design
- **Offline First**: 100% client-side operation
- **LowDB Persistence**: Lightweight local data storage
- **Export Features**: PDF and basic reporting

---

## Version Format

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Breaking API changes
- **MINOR** version: New backward-compatible features
- **PATCH** version: Backward-compatible bug fixes

### Release Schedule

- Major releases: As needed (1-2 times per year)
- Minor releases: Monthly
- Patch releases: As needed (security fixes within 48 hours)

---

## Upgrade Guide

### From 1.0.0 to 1.1.0

1. **Backup existing data**:
   ```bash
   cp -r data/ data-backup-$(date +%Y%m%d)/
   ```

2. **Update application**:
   ```bash
   git pull origin main
   npm install
   npm run build
   ```

3. **Migrate plaintext projects** (optional):
   ```bash
   npm run migrate:encrypt
   ```

4. **Restart application**:
   ```bash
   npm start
   # or
   docker compose up -d
   ```

**Note**: All new projects created in v1.1.0 are encrypted by default. Old plaintext projects remain compatible until migrated.

---

## Security Notes

### CVE & Vulnerability Disclosure

- [View Security Advisories](https://github.com/GhostN3xus/Owasp_Checklist_testing/security/advisories)
- [Report Vulnerability](SECURITY.md)

### Supported Versions

| Version | Status | Security Updates | Until |
|---------|--------|------------------|-------|
| 1.1.x   | Current | ✓ Active | 2025-11-09 |
| 1.0.x   | Legacy | ✗ No | 2024-11-09 |

---

## Contributors

Thanks to all contributors! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the ISC License - see [LICENSE](LICENSE) file for details.

---

**Last Updated**: 2024-11-09
**Latest Version**: 1.1.0
**Maintainer**: [GhostN3xus](https://github.com/GhostN3xus)
