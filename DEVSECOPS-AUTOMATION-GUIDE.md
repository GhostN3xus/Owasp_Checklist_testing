# Guia de Automação DevSecOps com OWASP ZAP

A integração de ferramentas de segurança em pipelines de CI/CD é um pilar do DevSecOps. Este guia mostra como automatizar o OWASP ZAP usando o GitHub Actions para escanear uma aplicação web a cada `push` de código.

## 1. O Objetivo da Automação

O objetivo é executar uma varredura de segurança de forma automática, garantindo que novas vulnerabilidades não sejam introduzidas no código. Se uma vulnerabilidade crítica for encontrada, o pipeline deve falhar, impedindo o deploy.

## 2. OWASP ZAP Baseline Scan

Para automação, usaremos o **ZAP Baseline Scan**. É um script pré-configurado que:
- Realiza *spidering* na URL alvo por um tempo definido (ex: 1 minuto).
- Realiza uma análise passiva, sem ataques ativos, para encontrar vulnerabilidades de baixo risco e algumas de médio risco.
- É ideal para CI/CD por ser rápido e não destrutivo.

## 3. Exemplo de Pipeline com GitHub Actions

Este exemplo assume que sua aplicação está sendo implantada em um ambiente de *staging* acessível por uma URL.

Crie um arquivo no seu repositório em `.github/workflows/security-scan.yml`:

```yaml
name: OWASP ZAP Baseline Scan

on:
  push:
    branches: [ main ]

jobs:
  zap_scan:
    runs-on: ubuntu-latest
    name: Scan the web application

    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: ZAP Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          # URL do alvo que será escaneado
          target: 'https://sua-aplicacao-de-staging.com'

          # Regras a serem ignoradas (separadas por vírgula), se necessário
          # Exemplo: 'rules_to_ignore: 10038,10040'

          # Nível de alerta que fará o pipeline falhar (FAIL, WARN ou INFO)
          # WARN: falha em alertas de risco High e Medium
          # FAIL: falha apenas em alertas de risco High
          fail_action: 'WARN'

          # (Opcional) Gere um relatório HTML para análise
          artifact_name: 'zap_scan_report.html'
```

## 4. Entendendo o Workflow

- **`name: OWASP ZAP Baseline Scan`**: Nome do workflow.
- **`on: push: branches: [ main ]`**: Este workflow será acionado sempre que houver um `push` na branch `main`.
- **`jobs: zap_scan:`**: Define o job que fará a varredura.
- **`runs-on: ubuntu-latest`**: O job será executado em um ambiente Ubuntu.
- **`uses: zaproxy/action-baseline@v0.7.0`**: Esta é a "Action" oficial do ZAP para o GitHub. Ela encapsula a complexidade de baixar e rodar o ZAP em um contêiner Docker.

### Parâmetros Chave da Action:

- **`target`**: A URL da sua aplicação. É o único parâmetro obrigatório. **Importante:** A aplicação precisa estar online e acessível para o scanner funcionar.
- **`fail_action: 'WARN'`**: Define o limiar de falha. Com `'WARN'`, o job falhará se o ZAP encontrar qualquer alerta de severidade `High` ou `Medium`. Isso força a equipe a corrigir os problemas antes de continuar.
- **`artifact_name`**: Se definido, a action irá gerar um relatório HTML e salvá-lo como um artefato do workflow. Você pode baixar este relatório na página da execução do workflow no GitHub para ver os detalhes completos da varredura.

## 5. Como Funciona na Prática

1. Um desenvolvedor envia um `push` para a branch `main`.
2. O GitHub Actions inicia o workflow `OWASP ZAP Baseline Scan`.
3. A action do ZAP inicia um contêiner Docker com o ZAP.
4. O ZAP executa o scan de linha de base contra a URL definida em `target`.
5. Se forem encontrados alertas acima do limiar (`WARN`), o job falha, o que pode ser configurado para bloquear um merge ou deploy.
6. O desenvolvedor é notificado da falha e pode baixar o relatório para entender e corrigir a vulnerabilidade.

Este é um primeiro passo poderoso para automatizar a segurança e adotar uma cultura DevSecOps.

## 6. Complementando com SAST: Automatizando o Semgrep

A análise DAST (como o ZAP) testa a aplicação em execução, enquanto a **SAST (Static Application Security Testing)** analisa o código-fonte em busca de vulnerabilidades. Integrar ambos oferece uma cobertura muito mais robusta.

O **Semgrep** é uma ferramenta SAST open-source rápida e ideal para CI/CD.

### Exemplo de Pipeline com Semgrep no GitHub Actions

Adicione um novo job ao seu arquivo `.github/workflows/security-scan.yml` ou crie um novo workflow.

```yaml
jobs:
  semgrep_scan:
    name: Semgrep SAST Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          # Regras padrão para várias linguagens (Python, Go, Java, JS, etc.)
          config: 'p/default'
```

### Entendendo o Workflow do Semgrep

- **`uses: returntocorp/semgrep-action@v1`**: Action oficial do Semgrep.
- **`config: 'p/default'`**: Este é o conjunto de regras padrão mantido pela comunidade do Semgrep. Ele cobre as vulnerabilidades mais comuns do OWASP Top 10 para uma ampla variedade de linguagens.

### Como Funciona

1. O workflow é acionado em um `push`.
2. O código-fonte é baixado (`checkout`).
3. A action do Semgrep executa a varredura no código.
4. Se encontrar vulnerabilidades, o Semgrep exibirá os resultados diretamente nos logs do GitHub Actions e fará o job falhar, bloqueando o pipeline.
5. Os resultados mostram o arquivo, a linha do código vulnerável e uma descrição do problema, facilitando a correção.

A combinação do **OWASP ZAP (DAST)** com o **Semgrep (SAST)** em seu pipeline de CI/CD cria um ciclo de feedback de segurança rápido e eficaz, fundamental para uma estratégia DevSecOps madura.
