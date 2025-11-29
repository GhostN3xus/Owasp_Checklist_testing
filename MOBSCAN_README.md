# 🔒 MOBSCAN v1.1.0 - Mobile Security Testing Framework

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-MASTG-orange.svg)](https://owasp.org/www-project-mobile-app-security/)
[![Status](https://img.shields.io/badge/status-beta-yellow.svg)](https://github.com/GhostN3xus/Owasp_Checklist_testing)

> ⚠️ **PROJETO EM DESENVOLVIMENTO ATIVO - VERSÃO BETA**
>
> **Status Atual: ~45% Completo**
>
> Este projeto está em desenvolvimento ativo e contém funcionalidades parcialmente implementadas:
> - ✅ **Funcional**: SAST Engine básico, CLI básico, arquitetura core
> - ⚠️ **Limitado**: SCA Engine (banco de vulnerabilidades simulado), DAST Engine (parcialmente simulado)
> - ❌ **Não Implementado**: Sistema de relatórios (0%), DAST/Frida engines completos, integrações externas
>
> **NÃO use em ambientes de produção sem validação completa dos resultados.**
>
> Para detalhes completos do status de implementação, veja [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md)

## 🚀 Quick Start

```bash
# Install
pip install -r requirements.txt

# Scan an APK
python -m mobscan scan app.apk

# Scan with all modules
python -m mobscan scan app.apk --modules sast dast sca frida --intensity comprehensive
```

## ✨ Features

- **🔍 SAST**: Static code analysis (secrets, crypto, storage, manifest)
- **🌐 DAST**: Dynamic analysis (network, headers, certificates)
- **📦 SCA**: Dependency analysis (vulnerabilities, licenses, SBOM)
- **🔧 Frida**: Runtime instrumentation (root bypass, SSL pinning)
- **🎨 Professional CLI**: 7 commands, multiple output formats
- **🔌 Plugin System**: Extensible architecture

## 📊 Coverage

- **SAST**: 50% OWASP MASTG coverage
- **DAST**: 40% OWASP MASTG coverage
- **SCA**: 60% OWASP MASTG coverage
- **Frida**: 40% OWASP MASTG coverage
- **Total**: 65% coverage

## 📚 Documentation

- [Complete README](docs/MOBSCAN_README.md)
- [Implementation Summary](docs/IMPLEMENTATION_SUMMARY.md)
- [Configuration Example](examples/config_complete.yaml)

## 🛠️ Commands

```bash
mobscan scan <target>           # Full security scan
mobscan dynamic <target>        # Dynamic analysis
mobscan frida <app>             # Runtime instrumentation
mobscan report <results>        # Generate reports
mobscan config init             # Create config file
mobscan database update         # Update vuln DB
mobscan init                    # Initialize project
```

## 📦 Installation

```bash
# Basic installation
pip install -r requirements.txt

# With Frida support
pip install -r requirements.txt
pip install frida frida-tools

# Install as package
pip install -e .
```

## 🔬 What it Detects

### SAST Engine
- ✅ Hardcoded secrets (API keys, passwords, tokens)
- ✅ Weak cryptography (MD5, SHA1, DES, RC4, ECB)
- ✅ Insecure storage
- ✅ Manifest vulnerabilities
- ✅ Exported components

### DAST Engine
- ✅ Network traffic analysis
- ✅ Security headers validation
- ✅ Sensitive data exposure
- ✅ Unencrypted HTTP
- ✅ Certificate issues

### SCA Engine
- ✅ Known vulnerabilities (CVE)
- ✅ Outdated dependencies
- ✅ License compliance
- ✅ Supply chain risks
- ✅ SBOM generation (CycloneDX)

### Frida Engine
- ✅ Root/Jailbreak detection bypass
- ✅ SSL pinning bypass
- ✅ Crypto operations monitoring
- ✅ Storage operations monitoring
- ✅ Network traffic monitoring

## 📈 Example Output

```
MOBSCAN v1.1.0 - Security Scan Results

Target: example.apk
Modules: SAST, DAST, SCA, Frida

Findings:
  Critical: 2
  High: 5
  Medium: 8
  Low: 3
  Info: 1

Top Issues:
  [CRITICAL] Hardcoded AWS Credentials (MainActivity.java:42)
  [HIGH] SSL Pinning Not Implemented
  [HIGH] Vulnerable Dependency: OkHttp 4.9.0 (CVE-2021-0341)

Reports generated:
  - ./reports/example_report.html
  - ./reports/example_report.pdf
  - ./reports/example_results.json
```

## 🎯 Use Cases

- **Security Audits**: Comprehensive security assessment
- **Penetration Testing**: Runtime analysis and exploitation
- **CI/CD Integration**: Automated security testing
- **Compliance**: OWASP MASTG/MASVS compliance
- **Education**: Learning mobile security

## 🏗️ Architecture

```
mobscan/
├── core/              # Event system, plugins
├── modules/           # SAST, DAST, SCA, Frida
├── utils/             # Config, validators
├── cli_professional.py
└── reports/           # Report generators
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# With coverage
pytest --cov=mobscan tests/

# Specific test
pytest tests/test_mobscan_comprehensive.py::TestSASTEngine
```

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Credits

Built with ❤️ using:
- OWASP MASTG/MASVS
- Frida
- Python asyncio

## 📞 Support

- 📧 Email: security@yourcompany.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/mobscan/issues)
- 📖 Docs: [Documentation](https://mobscan.readthedocs.io)

---

**MOBSCAN v1.1.0** - Professional Mobile Security Testing
