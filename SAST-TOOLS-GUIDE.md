# 🔍 Guia Completo de SAST - Static Application Security Testing

## 📋 Índice

1. [O que é SAST](#o-que-é-sast)
2. [Pontos de Validação Críticos](#pontos-de-validação-críticos)
3. [Ferramentas SAST por Linguagem](#ferramentas-sast-por-linguagem)
4. [Integração em CI/CD](#integração-em-cicd)
5. [Análise de Resultados](#análise-de-resultados)
6. [Checklist de Implementação](#checklist-de-implementação)

---

## O que é SAST?

**SAST (Static Application Security Testing)** é uma análise de segurança que:
- ✅ Examina código-fonte sem executá-lo
- ✅ Detecta vulnerabilidades conhecidas
- ✅ Identifica padrões de código inseguro
- ✅ Fornece relatórios automatizados
- ✅ Integra-se em pipelines CI/CD

### Diferenças:
| Tipo | Como Funciona | Quando Usar |
|------|---------------|-----------|
| **SAST** | Analisa código-fonte | Desenvolvimento, CI/CD |
| **DAST** | Testa aplicação rodando | Pré-produção, QA |
| **IAST** | Testa durante execução | Testes de integração |
| **SCA** | Analisa dependências | Gerenciamento de risco |

---

## Pontos de Validação Críticos

### 1. Injeção SQL

**O que procurar:**
```
❌ String interpolation em queries
❌ Concatenação de strings
❌ Sem prepared statements
```

**Como verificar com SAST:**
```bash
# Pattern perigoso
SELECT * FROM users WHERE id = '$id'

# Padrão seguro
SELECT * FROM users WHERE id = ?
```

### 2. XSS (Cross-Site Scripting)

**O que procurar:**
```
❌ Output sem escape
❌ innerHTML com user input
❌ eval() de dados
```

**Como verificar:**
```javascript
// ❌ Perigoso
document.getElementById('output').innerHTML = userInput;

// ✅ Seguro
document.getElementById('output').textContent = userInput;
```

### 3. Injeção de Comando

**O que procurar:**
```
❌ exec(), system(), shell_exec()
❌ Sem validação de entrada
❌ Pipe de comandos
```

**Como verificar:**
```python
# ❌ Perigoso
os.system(f"ls {user_directory}")

# ✅ Seguro
os.listdir(validated_directory)
```

### 4. Acesso a Arquivo Inseguro

**O que procurar:**
```
❌ Path traversal
❌ Sem validação de caminho
❌ Diretório writable
```

**Como verificar:**
```php
// ❌ Perigoso
file_get_contents($_GET['file'])

// ✅ Seguro
file_get_contents(realpath($safe_dir . '/' . basename($file)))
```

### 5. Criptografia Fraca

**O que procurar:**
```
❌ MD5, SHA1 para senhas
❌ Chaves hardcoded
❌ Modo ECB
```

**Como verificar:**
```python
# ❌ Perigoso
import hashlib
password_hash = hashlib.md5(password).hexdigest()

# ✅ Seguro
import bcrypt
password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
```

### 6. Variáveis Sensíveis Hardcoded

**O que procurar:**
```
❌ Senhas em código
❌ API keys
❌ Tokens
❌ Secrets
```

**Como verificar:**
```bash
# Padrão perigoso
API_KEY = "sk-1234567890"
password = "admin123"
```

---

## Ferramentas SAST por Linguagem

### JavaScript/TypeScript

#### 1. **Semgrep**
```bash
npm install -g semgrep

# Executar
semgrep --config=p/owasp-top-ten . --json
```

**Detecta:**
- ❌ SQL Injection
- ❌ XSS
- ❌ Weak cryptography
- ❌ Hardcoded secrets

#### 2. **ESLint com Plugins de Segurança**
```bash
npm install --save-dev eslint eslint-plugin-security

# .eslintrc.json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}

npm run lint
```

#### 3. **SonarQube Community Edition**
```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community

# Via CLI
sonar-scanner \
  -Dsonar.projectKey=myapp \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000
```

### Python

#### 1. **Bandit**
```bash
pip install bandit

# Executar
bandit -r . -f json -o bandit-report.json

# Excluir testes
bandit -r src/ --skip B101,B601
```

**Detecta:**
- ❌ Hard-coded passwords
- ❌ SQL Injection
- ❌ Insecure deserialization
- ❌ Weak cryptography

#### 2. **Semgrep para Python**
```bash
semgrep --config=p/security-audit src/
```

#### 3. **Pylint com Plugin de Segurança**
```bash
pip install pylint

pylint --load-plugins=pylint.extensions.security src/
```

#### 4. **Ruff**
```bash
pip install ruff

ruff check . --select S  # Security rules
```

### PHP

#### 1. **PHPStan**
```bash
composer require --dev phpstan/phpstan

./vendor/bin/phpstan analyse src/
```

#### 2. **Psalm**
```bash
composer require --dev vimeo/psalm

./vendor/bin/psalm src/
```

#### 3. **SonarQube**
```bash
# Com SonarScanner
sonar-scanner -Dsonar.sources=src
```

### Java

#### 1. **SpotBugs**
```bash
# Maven
mvn spotbugs:check

# Gradle
gradle spotbugsMain
```

#### 2. **OWASP Dependency-Check**
```bash
# Maven
mvn org.owasp:dependency-check-maven:check

# Gradle
gradle dependencyCheckAnalyze
```

#### 3. **SonarQube**
```bash
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=my-app \
  -Dsonar.host.url=http://localhost:9000
```

### C#/.NET

#### 1. **Roslyn Analyzers**
```xml
<!-- .csproj -->
<ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" Version="7.0.0" />
    <PackageReference Include="SecurityCodeScan.VS2019" Version="5.6.0" />
</ItemGroup>
```

```bash
dotnet build
```

#### 2. **SonarQube**
```bash
dotnet sonarscanner begin \
  /k:"myapp" \
  /d:sonar.host.url="http://localhost:9000"

dotnet build

dotnet sonarscanner end
```

---

## Integração em CI/CD

### GitHub Actions

```yaml
# .github/workflows/sast.yml
name: SAST Security Scanning

on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/cwe-top-25
            p/security-audit

  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: python-actions/python-versions@v4
      - run: pip install bandit
      - run: bandit -r src/ -f json -o bandit-report.json
      - uses: actions/upload-artifact@v3
        with:
          name: bandit-report
          path: bandit-report.json

  sonarcloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### GitLab CI

```yaml
# .gitlab-ci.yml
sast-semgrep:
  image: returntocorp/semgrep
  script:
    - semgrep --config=p/owasp-top-ten . --json -o sast-report.json
  artifacts:
    reports:
      sast: sast-report.json

sast-bandit:
  image: python:3.10
  script:
    - pip install bandit
    - bandit -r src/ -f json -o bandit-report.json
  artifacts:
    reports:
      sast: bandit-report.json
```

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('SAST - Semgrep') {
            steps {
                sh '''
                    docker run --rm -v $(pwd):/src returntocorp/semgrep \
                    semgrep --config=p/owasp-top-ten /src --json -o sast-report.json
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh '''
                    pip install bandit
                    bandit -r src/ -f json -o bandit-report.json
                '''
            }
        }

        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: '*-report.json'
                junit 'sast-report.json'
            }
        }
    }
}
```

---

## Análise de Resultados

### Interpretar Severidade

| Nível | Impacto | Ação |
|-------|---------|------|
| **CRITICAL** | Exploração fácil, alto impacto | Corrigir IMEDIATAMENTE |
| **HIGH** | Exploração possível | Corrigir antes do deploy |
| **MEDIUM** | Requer contexto específico | Planejar correção |
| **LOW** | Mitigação necessária | Documentar e acompanhar |
| **INFO** | Informativo | Revisar boas práticas |

### Falsos Positivos

Nem todo alerta é uma vulnerabilidade real!

```javascript
// ❌ SAST pode alertar como XSS
const sanitized = DOMPurify.sanitize(userInput);
document.getElementById('output').innerHTML = sanitized;

// Solução: Adicionar comentário para SAST
// sast-ignore[xss]
document.getElementById('output').innerHTML = sanitized;
```

### Priorizar Correções

1. **CRITICAL + HIGH no código de produção** → Imediato
2. **MEDIUM + dependências críticas** → Sprint atual
3. **LOW + código legado** → Backlog
4. **INFO** → Documentar como política

---

## Checklist de Implementação

### Fase 1: Setup Inicial

- [ ] Escolher ferramenta SAST principal (Semgrep/Bandit/SonarQube)
- [ ] Instalar ferramenta localmente
- [ ] Executar primeiro scan
- [ ] Documentar baseline (vulnerabilidades iniciais)
- [ ] Definir policy de severidade

### Fase 2: CI/CD Integration

- [ ] Integrar SAST no pipeline (GitHub Actions/GitLab/Jenkins)
- [ ] Configurar relatórios automáticos
- [ ] Definir gates (bloquear PRs com CRITICAL)
- [ ] Testar em branch de desenvolvimento
- [ ] Validar atualizações

### Fase 3: Remediation

- [ ] Triagem de todos os alertas
- [ ] Criar issues para vulnerabilidades confirmadas
- [ ] Priorizar por severidade e impacto
- [ ] Corrigir CRITICAL/HIGH imediatamente
- [ ] Documentar falsos positivos

### Fase 4: Governança

- [ ] Estabelecer SLA para correções
- [ ] Auditar código novo regularmente
- [ ] Treinar developers em SAST
- [ ] Revisar politicas mensalmente
- [ ] Manter ferramenta atualizada

---

## Exemplo Prático

### Projeto Node.js

```bash
# 1. Instalar Semgrep
npm install -g semgrep

# 2. Executar scan
semgrep --config=p/owasp-top-ten src/ --json -o sast-report.json

# 3. Revisar resultados
cat sast-report.json | jq '.results[] | select(.severity=="HIGH")'

# 4. Corrigir vulnerabilidades
# ... editar código ...

# 5. Re-scan para verificar
semgrep --config=p/owasp-top-ten src/ --json

# 6. Integrar em package.json
# "scripts": {
#   "sast": "semgrep --config=p/owasp-top-ten src/",
#   "sast-ci": "semgrep --config=p/owasp-top-ten src/ --json -o sast-report.json"
# }
```

### Projeto Python

```bash
# 1. Instalar Bandit
pip install bandit

# 2. Executar scan
bandit -r src/ -f json -o bandit-report.json

# 3. Revisar HIGH/MEDIUM
bandit -r src/ -ll

# 4. Corrigir issues
# ... editar código ...

# 5. Re-scan
bandit -r src/

# 6. Setup pre-commit hook
pip install pre-commit
```

**`.pre-commit-config.yaml`:**
```yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', 'bandit.yaml', '-r', 'src/']
```

---

## Métricas e Reporting

### KPIs para SAST

```
1. Total de vulnerabilidades encontradas
2. Distribuição por severidade (CRITICAL, HIGH, MEDIUM, LOW)
3. Tempo médio para correção
4. Taxa de falsos positivos
5. Cobertura de código analisado
6. Tendência ao longo do tempo
```

### Dashboard Example

```
┌─────────────────────────────────────────┐
│ SAST Security Summary                   │
├─────────────────────────────────────────┤
│ Total Issues:        127                │
│ ├─ CRITICAL:        3  🔴              │
│ ├─ HIGH:           15  🟠              │
│ ├─ MEDIUM:         45  🟡              │
│ └─ LOW:            64  🟢              │
│                                         │
│ Trend:            ↓ 23% (last month)   │
│ Fixed:            85% of issues        │
└─────────────────────────────────────────┘
```

---

## Resumo

**Boas Práticas:**
1. ✅ **Automatizar SAST em CI/CD**
2. ✅ **Bloquear merges com CRITICAL**
3. ✅ **Revisar falsos positivos**
4. ✅ **Treinar developers**
5. ✅ **Manter ferramentas atualizadas**
6. ✅ **Documentar vulnerabilidades**
7. ✅ **Acompanhar tendências**

