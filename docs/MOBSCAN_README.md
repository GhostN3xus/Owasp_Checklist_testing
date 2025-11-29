# MOBSCAN v1.1.0 - Mobile Application Security Testing Framework

![MOBSCAN Logo](https://via.placeholder.com/800x200/0066cc/ffffff?text=MOBSCAN)

## 🚀 Visão Geral

MOBSCAN é um framework profissional e completo para automação de testes de segurança em aplicações mobile (Android e iOS). Oferece análise estática (SAST), análise dinâmica (DAST), análise de composição de software (SCA) e instrumentação em runtime (Frida).

### ✨ Características Principais

- **🔍 SAST Engine**: Análise estática de código
  - Detecção de secrets hardcoded
  - Identificação de criptografia fraca
  - Análise de armazenamento inseguro
  - Validação de manifest/Info.plist
  - Análise de permissões

- **🌐 DAST Engine**: Análise dinâmica
  - Interceptação de tráfego de rede
  - Validação de headers de segurança
  - Detecção de dados sensíveis
  - Verificação de certificados SSL/TLS
  - Exportação HAR

- **📦 SCA Engine**: Análise de dependências
  - Extração de dependências (Gradle, Maven, CocoaPods, SPM)
  - Verificação de vulnerabilidades conhecidas
  - Análise de licenças
  - Detecção de versões desatualizadas
  - Geração de SBOM (CycloneDX)

- **🔧 Frida Engine**: Instrumentação em runtime
  - Bypass de detecção de root/jailbreak
  - Bypass de SSL pinning
  - Monitoramento de operações criptográficas
  - Monitoramento de armazenamento
  - Monitoramento de rede

- **🎨 CLI Profissional**: Interface de linha de comando completa
  - 7 comandos principais
  - Múltiplos formatos de saída
  - Interface colorida e intuitiva

- **🔌 Sistema de Plugins**: Arquitetura extensível
  - Plugins de análise customizada
  - Plugins de relatório
  - Hooks de execução

## 📋 Requisitos

- Python 3.8+
- pip
- Android SDK (para análise de APK)
- Xcode Command Line Tools (para análise de IPA, somente macOS)
- Frida (opcional, para instrumentação)

## 🛠️ Instalação

### Instalação Básica

```bash
# Clone o repositório
git clone https://github.com/your-org/mobscan.git
cd mobscan

# Instale as dependências
pip install -r requirements.txt

# Verifique a instalação
python -m mobscan.cli_professional --help
```

### Instalação com Frida

```bash
# Instale Frida
pip install frida frida-tools

# Verifique a instalação
frida --version
```

### Docker (Alternativa)

```bash
# Build da imagem
docker build -t mobscan:1.1.0 .

# Execute
docker run -it mobscan:1.1.0 scan /path/to/app.apk
```

## 🎯 Uso Rápido

### Scan Básico

```bash
# Scan simples de um APK
python -m mobscan.cli_professional scan app.apk

# Scan de um IPA
python -m mobscan.cli_professional scan app.ipa
```

### Scan Completo

```bash
# Scan com todos os módulos
python -m mobscan.cli_professional scan app.apk \
  --modules sast dast sca frida \
  --intensity comprehensive \
  --report html pdf json
```

### Análise Dinâmica

```bash
# Inicia análise DAST
python -m mobscan.cli_professional dynamic app.apk \
  --proxy localhost:8080 \
  --duration 300 \
  --export-har
```

### Instrumentação Frida

```bash
# Anexa ao app com hooks
python -m mobscan.cli_professional frida com.example.app \
  --device usb \
  --hooks root_bypass ssl_bypass crypto_monitor
```

### Geração de Relatórios

```bash
# Gera relatórios a partir de resultados
python -m mobscan.cli_professional report results.json \
  --format html pdf markdown \
  --output ./reports
```

## 📚 Comandos Disponíveis

### `scan`
Executa scan de segurança completo.

```bash
mobscan scan <target> [options]

Options:
  --modules        Módulos a executar (sast, dast, sca, frida)
  --intensity      Intensidade (quick, normal, comprehensive)
  --output, -o     Diretório de saída
  --report         Formatos de relatório
  --config, -c     Arquivo de configuração
  --verbose, -v    Modo verboso
```

### `dynamic`
Executa análise dinâmica (DAST).

```bash
mobscan dynamic <target> [options]

Options:
  --proxy          Endereço do proxy (host:port)
  --duration       Duração em segundos
  --output, -o     Diretório de saída
  --export-har     Exporta tráfego como HAR
```

### `frida`
Executa instrumentação Frida.

```bash
mobscan frida <target> [options]

Options:
  --device         ID do dispositivo
  --script         Script customizado
  --hooks          Hooks a carregar
  --output, -o     Arquivo de saída
```

### `report`
Gera relatórios.

```bash
mobscan report <input> [options]

Options:
  --format         Formatos (html, pdf, json, markdown, docx)
  --output, -o     Diretório de saída
  --template       Template customizado
```

### `config`
Gerencia configuração.

```bash
mobscan config <action>

Actions:
  init             Cria arquivo de configuração
  show             Mostra configuração atual
  validate <file>  Valida arquivo de configuração
```

### `database`
Gerencia banco de dados de vulnerabilidades.

```bash
mobscan database <action>

Actions:
  update           Atualiza banco de dados
  stats            Mostra estatísticas
```

### `init`
Inicializa projeto MOBSCAN.

```bash
mobscan init [options]

Options:
  --directory, -d  Diretório do projeto
```

## ⚙️ Configuração

### Arquivo de Configuração

Crie um arquivo `mobscan_config.yaml`:

```yaml
scan:
  modules: [sast, sca, dast]
  intensity: comprehensive

sast:
  enabled: true
  min_severity: medium

sca:
  enabled: true
  check_vulnerabilities: true
  generate_sbom: true

report:
  formats: [html, pdf, json]
  output_dir: ./reports
```

Use com:

```bash
mobscan scan app.apk --config mobscan_config.yaml
```

Veja `examples/config_complete.yaml` para todas as opções disponíveis.

## 📊 Formatos de Saída

### JSON
```json
{
  "app": "example.apk",
  "findings": [
    {
      "severity": "high",
      "category": "Hardcoded Secrets",
      "title": "API Key Detected",
      "description": "...",
      "file": "MainActivity.java",
      "line": 42
    }
  ],
  "stats": {
    "total": 15,
    "critical": 2,
    "high": 5,
    "medium": 8
  }
}
```

### HTML
Relatório interativo com:
- Executive Summary
- Findings por severidade
- Gráficos e estatísticas
- Code snippets
- Recomendações

### PDF
Relatório profissional para apresentação a stakeholders.

### Markdown
Formato compatível com documentação e wikis.

## 🔌 Sistema de Plugins

### Criar um Plugin

```python
from mobscan.core.plugin_system import AnalyzerPlugin, PluginMetadata, PluginType

class MyCustomAnalyzer(AnalyzerPlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="my_analyzer",
            version="1.0.0",
            author="Your Name",
            description="Custom analyzer",
            plugin_type=PluginType.ANALYZER
        )

    async def initialize(self, config):
        return True

    async def analyze(self, target, context):
        # Sua análise customizada
        return {"findings": []}

    async def cleanup(self):
        pass
```

### Usar Plugin

```bash
# Coloque em ./plugins/plugin_my_analyzer.py
mobscan scan app.apk --config config.yaml
```

## 🧪 Testes

Execute a suite de testes:

```bash
# Todos os testes
pytest tests/

# Com coverage
pytest --cov=mobscan tests/

# Testes específicos
pytest tests/test_mobscan_comprehensive.py::TestSASTEngine
```

## 📈 Cobertura

| Módulo | Cobertura |
|--------|-----------|
| SAST   | 50%       |
| DAST   | 40%       |
| SCA    | 60%       |
| Frida  | 40%       |
| **Total** | **65%** |

Baseado no OWASP MASTG/MASVS.

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

MIT License - veja LICENSE para detalhes.

## 🙏 Agradecimentos

- OWASP Mobile Security Testing Guide (MASTG)
- OWASP Mobile Application Security Verification Standard (MASVS)
- Frida Project
- Comunidade de segurança mobile

## 📞 Suporte

- Issues: https://github.com/your-org/mobscan/issues
- Docs: https://mobscan.readthedocs.io
- Email: security@yourcompany.com

## 🗺️ Roadmap

### v1.2.0
- [ ] Análise de código nativo (C/C++)
- [ ] Integração com CI/CD
- [ ] API REST
- [ ] Dashboard web

### v1.3.0
- [ ] Machine Learning para detecção de anomalias
- [ ] Suporte para Flutter/React Native
- [ ] Análise de backend mobile
- [ ] Fuzzing automático

## 📖 Documentação Adicional

- [Installation Guide](./INSTALLATION.md)
- [User Guide](./USER_GUIDE.md)
- [Developer Guide](./DEVELOPER_GUIDE.md)
- [API Reference](./API_REFERENCE.md)
- [Plugin Development](./PLUGIN_DEVELOPMENT.md)

---

**MOBSCAN v1.1.0** - Professional Mobile Application Security Testing Framework
