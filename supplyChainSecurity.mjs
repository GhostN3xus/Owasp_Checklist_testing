/**
 * Supply Chain Security & Software Composition Analysis (SCA)
 * Gestão segura de dependências, SBOM, verificação de integridade, análise de vulnerabilidades
 */

export const supplyChainSecurityChecklist = {
  id: "supply-chain",
  name: "Supply Chain & SCA",
  description: "Supply Chain Security e SCA (Software Composition Analysis) - Gestão de dependências vulneráveis, SBOM, verificação de integridade, proteção contra ataques à cadeia de suprimentos.",
  sections: [
    {
      id: "sca-dependencies",
      title: "Análise de Dependências e Vulnerabilidades",
      summary: "Identificação e remediação de bibliotecas com CVEs conhecidos.",
      items: [
        {
          id: "sca-dep-1",
          title: "Escanear dependências em busca de vulnerabilidades conhecidas",
          description: "Usar ferramentas SCA para identificar CVEs em packages (npm, pip, Maven, NuGet).",
          guide: {
            overview: "Aplicações modernas usam 100+ dependências. SCA identifica quais possuem vulnerabilidades conhecidas (CVEs).",
            impact: "Exploração de CVEs em Log4j, Spring4Shell, Lodash, etc pode comprometer aplicação inteira.",
            detection: [
              "Executar scan de dependências: npm audit, pip-audit, OWASP Dependency-Check",
              "Identificar packages com CVEs: severity (Critical, High, Medium, Low)",
              "Priorizar remediação por CVSS score e exploitability"
            ],
            tools: [
              "npm audit / yarn audit",
              "pip-audit / safety (Python)",
              "OWASP Dependency-Check",
              "Snyk",
              "GitHub Dependabot",
              "Trivy (containers)",
              "Grype"
            ],
            commands: [
              "# Node.js",
              "npm audit",
              "npm audit --json > audit-report.json",
              "npm audit fix  # Auto-update para versões seguras",
              "",
              "# Python",
              "pip-audit",
              "safety check --json",
              "",
              "# Java (Maven)",
              "mvn org.owasp:dependency-check-maven:check",
              "",
              "# Multi-language (OWASP Dependency-Check)",
              "dependency-check --project MyApp --scan ./src --format JSON",
              "",
              "# Snyk",
              "snyk test",
              "snyk monitor  # Continuous monitoring",
              "",
              "# Container scanning",
              "trivy image myapp:latest",
              "grype myapp:latest"
            ],
            steps: [
              "1. Escolher ferramenta SCA para stack: npm audit, Snyk, Dependency-Check",
              "2. Executar scan inicial: npm audit ou snyk test",
              "3. Analisar output: quantas vulnerabilidades? severity?",
              "4. Priorizar por CVSS >= 7.0 (High/Critical)",
              "5. Verificar se há fix disponível: versão segura do package",
              "6. Atualizar dependências: npm update, pip install --upgrade",
              "7. Testar aplicação após updates (regression testing)",
              "8. Integrar SCA no CI/CD (fail build se Critical vulnerabilities)"
            ],
            mitigation: [
              "Automatizar scans: npm audit no pre-commit hook",
              "Integrar no CI/CD: fail build se vulnerabilidades críticas",
              "Usar Dependabot/Renovate para auto-updates",
              "Estabelecer SLA: Critical CVEs = fix em 24h, High = 7 dias",
              "Manter dependências atualizadas (não usar versões EOL)",
              "Revisar release notes antes de atualizar major versions",
              "Usar lockfiles: package-lock.json, Pipfile.lock (reproducible builds)"
            ],
            evidence: [
              "npm audit output: 45 vulnerabilities (5 critical, 12 high, 28 moderate)",
              "CVE-2024-XXXX em lodash@4.17.15 (CVSS 9.8)",
              "Snyk report mostrando dependency tree afetado",
              "Screenshot do Dependabot PR sugerindo updates"
            ],
            references: [
              "https://owasp.org/www-community/Component_Analysis",
              "https://owasp.org/www-project-dependency-check/",
              "https://snyk.io/learn/open-source-security/",
              "https://github.com/pyupio/safety"
            ]
          }
        },
        {
          id: "sca-dep-2",
          title: "Validar integridade de packages (checksum, signatures)",
          description: "Verificar checksums e assinaturas de packages para detectar tampering.",
          guide: {
            overview: "Packages podem ser comprometidos em registries (typosquatting, account hijacking). Validação de integridade detecta tampering.",
            impact: "Malware em dependencies, backdoors, data exfiltration (ex: event-stream incident).",
            detection: [
              "Verificar lockfiles: package-lock.json contém checksums (integrity field)",
              "Validar signatures: npm verify, pip install --require-hashes",
              "Auditar packages suspeitos: recém-publicados, poucos downloads, nomes similares"
            ],
            tools: ["npm verify", "pip-audit", "Sigstore/cosign", "in-toto"],
            commands: [
              "# npm - Verificar integridade",
              "npm install --ignore-scripts  # Prevenir execução de install scripts maliciosos",
              "npm audit signatures  # Verificar assinaturas de packages",
              "",
              "# Python - Require hashes",
              "pip install --require-hashes -r requirements.txt",
              "# requirements.txt deve conter:",
              "# package==1.0.0 --hash=sha256:abc123...",
              "",
              "# Verificar package manualmente",
              "npm view lodash@4.17.21 dist.integrity",
              "# Compare com package-lock.json",
              "",
              "# Sigstore (assinaturas criptográficas)",
              "cosign verify-blob --certificate package.crt --signature package.sig package.tar.gz"
            ],
            steps: [
              "1. Habilitar validação de integridade: npm ci (usa lockfile)",
              "2. Auditar lockfiles: verificar integrity fields presentes",
              "3. Evitar install sem lockfile: npm ci ao invés de npm install",
              "4. Verificar assinaturas: npm audit signatures",
              "5. Revisar packages suspeitos: typosquatting (lodash vs lodahs)",
              "6. Usar registries privados para packages críticos",
              "7. Implementar policy: apenas packages com X+ downloads/semana"
            ],
            mitigation: [
              "Usar lockfiles SEMPRE (package-lock.json, yarn.lock)",
              "npm ci no CI/CD (valida integrity automaticamente)",
              "Habilitar 2FA em contas de registry (npm, PyPI)",
              "Usar private registry/artifactory para curated packages",
              "Implementar package vetting process: revisar novo package antes de adicionar",
              "Monitorar novos packages: alertas para adições ao projeto",
              "Usar tools: Socket.dev, Snyk Advisor para avaliar trustworthiness"
            ],
            evidence: [
              "package-lock.json sem integrity fields (versão antiga do npm)",
              "Package instalado sem validação de checksum",
              "Typosquatting detectado: 'react-domm' ao invés de 'react-dom'",
              "Malware encontrado em install script de dependency"
            ],
            references: [
              "https://docs.npmjs.com/cli/v9/commands/npm-audit",
              "https://blog.npmjs.org/post/185397814280/plot-to-steal-cryptocurrency-foiled-by-the-npm",
              "https://github.com/sigstore/cosign",
              "https://socket.dev/"
            ]
          }
        }
      ]
    },
    {
      id: "sbom",
      title: "Software Bill of Materials (SBOM)",
      summary: "Geração e gestão de inventário completo de componentes de software.",
      items: [
        {
          id: "sbom-1",
          title: "Gerar SBOM (Software Bill of Materials) completo",
          description: "Criar inventário estruturado de todas dependências (diretas e transitivas) em formato padrão.",
          guide: {
            overview: "SBOM é lista completa de componentes de software, como 'lista de ingredientes'. Essencial para compliance e incident response.",
            impact: "Sem SBOM, impossível saber se aplicação é afetada por novo CVE (ex: Log4Shell). Exigido por regulações (EO 14028).",
            detection: [
              "Gerar SBOM em formato padrão: SPDX, CycloneDX",
              "Incluir: nome do componente, versão, licença, supplier, checksums",
              "Capturar dependências transitivas (não apenas diretas)"
            ],
            tools: [
              "CycloneDX CLI",
              "SPDX Tools",
              "Syft (Anchore)",
              "Tern",
              "npm sbom",
              "cdxgen"
            ],
            commands: [
              "# CycloneDX (multi-language)",
              "npm install -g @cyclonedx/cyclonedx-npm",
              "cyclonedx-npm --output-file sbom.json",
              "",
              "# npm native (Node.js 16+)",
              "npm sbom --sbom-format=cyclonedx > sbom-cyclonedx.json",
              "",
              "# Syft (containers e filesystems)",
              "syft packages dir:. -o cyclonedx-json > sbom.json",
              "syft packages myapp:latest -o spdx-json > sbom-spdx.json",
              "",
              "# cdxgen (universal)",
              "npm install -g @cyclonedx/cdxgen",
              "cdxgen -o sbom.json .",
              "",
              "# Grype (scan SBOM for vulnerabilities)",
              "grype sbom:sbom.json"
            ],
            steps: [
              "1. Escolher formato: CycloneDX (recomendado) ou SPDX",
              "2. Instalar ferramenta: Syft, cdxgen, ou nativa do package manager",
              "3. Gerar SBOM: syft packages dir:. -o cyclonedx-json",
              "4. Validar SBOM: contém todas dependências? versões corretas?",
              "5. Versionar SBOM: commit no repo (sbom.json)",
              "6. Armazenar SBOM em artifact registry (correlacionar com builds)",
              "7. Automatizar: gerar SBOM em cada build de CI/CD",
              "8. Usar SBOM para vulnerability tracking: grype sbom:sbom.json"
            ],
            mitigation: [
              "Gerar SBOM automaticamente em CI/CD pipeline",
              "Armazenar SBOM com cada release (artifact repository)",
              "Usar SBOM para vulnerability management: scan diário",
              "Compartilhar SBOM com clientes (compliance, transparency)",
              "Implementar SBOM diff: alertar quando novos componentes são adicionados",
              "Usar SBOM em incident response: afetados por CVE-XXXX?"
            ],
            evidence: [
              "SBOM gerado em CycloneDX JSON format",
              "145 componentes listados (12 diretos, 133 transitivos)",
              "Validação: todas dependências do package.json presentes",
              "CI/CD configurado para gerar SBOM em cada build"
            ],
            references: [
              "https://cyclonedx.org/",
              "https://spdx.dev/",
              "https://www.cisa.gov/sbom",
              "https://www.ntia.gov/SBOM",
              "https://github.com/anchore/syft"
            ]
          }
        },
        {
          id: "sbom-2",
          title: "Implementar monitoramento contínuo de SBOM contra novos CVEs",
          description: "Automatizar verificação de SBOM contra databases de vulnerabilidades atualizadas diariamente.",
          guide: {
            overview: "Novos CVEs são publicados diariamente. Monitoramento contínuo de SBOM alerta sobre vulnerabilidades emergentes.",
            impact: "Detecção proativa de vulnerabilidades (antes de exploits), resposta rápida a 0-days.",
            detection: [
              "Configurar scan automatizado de SBOM: grype, Snyk, Dependency-Track",
              "Receber alertas quando novo CVE afeta componentes do SBOM",
              "Integrar com issue tracker: criar tickets automaticamente"
            ],
            tools: ["Dependency-Track", "Grype", "Snyk Monitor", "GitHub Dependabot"],
            commands: [
              "# Dependency-Track (self-hosted)",
              "docker run -p 8080:8080 dependencytrack/bundled",
              "# Upload SBOM via API:",
              "curl -X POST 'http://localhost:8080/api/v1/bom' \\",
              "  -H 'X-API-Key: YOUR_KEY' \\",
              "  -F 'project=abc-123' \\",
              "  -F 'bom=@sbom.json'",
              "",
              "# Grype (CLI scan)",
              "grype sbom:sbom.json --only-fixed  # Apenas CVEs com fix disponível",
              "",
              "# Snyk Monitor (continuous monitoring)",
              "snyk monitor --file=package.json --org=my-org",
              "",
              "# Automation: daily scan",
              "crontab -e",
              "0 2 * * * grype sbom:/path/to/sbom.json --output json > /var/log/vuln-scan.json && notify-if-critical.sh"
            ],
            steps: [
              "1. Escolher plataforma: Dependency-Track (open-source), Snyk, ou scripts",
              "2. Fazer upload de SBOM para plataforma",
              "3. Configurar notificações: email, Slack, PagerDuty",
              "4. Estabelecer thresholds: Critical = alerta imediato, High = daily digest",
              "5. Integrar com ticketing: Jira, Linear (criar issues automaticamente)",
              "6. Definir SLAs de remediação por severity",
              "7. Revisar alertas diariamente (vulnerability triage)",
              "8. Medir métricas: MTTR (Mean Time To Remediate)"
            ],
            mitigation: [
              "Dependency-Track para monitoramento centralizado",
              "Alertas em tempo real para Critical vulnerabilities",
              "Integração com CI/CD: bloquear deploy se Critical CVEs",
              "Processo de vulnerability triage: avaliar exploitability",
              "Priorização: internet-facing components > internos",
              "Manter dashboard de vulnerability status (executivos)"
            ],
            evidence: [
              "Dependency-Track dashboard: 12 vulnerabilities ativas",
              "Alerta recebido 2h após publicação de CVE-2024-XXXX",
              "Ticket Jira criado automaticamente: 'Update lodash to 4.17.22'",
              "Métrica: MTTR = 3.5 dias (target: < 7 dias)"
            ],
            references: [
              "https://dependencytrack.org/",
              "https://github.com/anchore/grype",
              "https://snyk.io/product/open-source-security-management/"
            ]
          }
        }
      ]
    },
    {
      id: "sc-supply-chain-attacks",
      title: "Proteção contra Ataques à Supply Chain",
      summary: "Mitigação de typosquatting, dependency confusion, compromised maintainers.",
      items: [
        {
          id: "sc-attack-1",
          title: "Prevenir dependency confusion attacks",
          description: "Proteger contra pacotes maliciosos com mesmo nome em registries públicos vs privados.",
          guide: {
            overview: "Dependency confusion: atacante publica package 'internal-lib' em registry público. Build system baixa versão maliciosa ao invés da privada.",
            impact: "Execução de código malicioso em build servers, exfiltração de secrets, supply chain compromise.",
            detection: [
              "Identificar packages privados/internos",
              "Verificar se existem homônimos em registries públicos (npm, PyPI)",
              "Testar: npm install dá preferência a qual registry?"
            ],
            tools: ["npm/pip config", "Artifactory", "Nexus", "Azure Artifacts"],
            commands: [
              "# npm - Configurar scoped registry",
              "npm config set @mycompany:registry https://npm.mycompany.com/",
              "",
              "# .npmrc (project-level)",
              "@mycompany:registry=https://npm.mycompany.com/",
              "registry=https://registry.npmjs.org/  # Fallback",
              "",
              "# Python - Configurar index-url",
              "pip config set global.index-url https://pypi.mycompany.com/simple",
              "pip config set global.extra-index-url https://pypi.org/simple",
              "",
              "# Maven - settings.xml",
              "<mirrors>",
              "  <mirror>",
              "    <id>internal</id>",
              "    <url>https://nexus.mycompany.com/</url>",
              "    <mirrorOf>*</mirrorOf>",
              "  </mirror>",
              "</mirrors>"
            ],
            steps: [
              "1. Listar todos packages internos/privados do projeto",
              "2. Verificar se existem em registries públicos (npm search, pypi.org)",
              "3. Se existir: ALERTA! Possível dependency confusion",
              "4. Configurar scoped registries: @company/* usa registry privado",
              "5. Usar namespace/prefix em packages internos: @mycompany/utils",
              "6. Configurar .npmrc / pip.conf para priorizar registry privado",
              "7. Publicar placeholders em registries públicos (claim names)",
              "8. Monitorar: alertas se packages internos aparecem em públicos"
            ],
            mitigation: [
              "Usar scoped packages: @mycompany/package-name (npm)",
              "Configurar registry priority: privado ANTES de público",
              "Usar private registry exclusivo (sem fallback para público)",
              "Publicar placeholders: registrar nomes em públicos (vazios)",
              "Implementar allowlist: apenas packages aprovados podem ser instalados",
              "Usar tools: Socket.dev detecta dependency confusion",
              "Audit de .npmrc, pip.conf em onboarding de devs"
            ],
            evidence: [
              "Package 'internal-auth-lib' encontrado em npmjs.com (malicioso)",
              "Build baixou versão pública ao invés de privada",
              "Código malicioso executado em CI: exfiltração de AWS_SECRET_KEY",
              ".npmrc sem configuração de scoped registry"
            ],
            references: [
              "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
              "https://azure.microsoft.com/en-us/blog/three-ways-to-mitigate-risk-using-private-package-feeds/",
              "https://docs.npmjs.com/cli/v9/using-npm/scope"
            ]
          }
        },
        {
          id: "sc-attack-2",
          title: "Detectar e prevenir typosquatting",
          description: "Identificar packages maliciosos com nomes similares a populares (ex: 'reqeusts' vs 'requests').",
          guide: {
            overview: "Typosquatting: atacante publica 'reqeusts' (typo de 'requests'). Desenvolvedores instalam por engano.",
            impact: "Malware instalado via typo, data exfiltration, backdoors.",
            detection: [
              "Revisar package.json / requirements.txt: typos nos nomes?",
              "Usar linters: detectam packages suspeitos",
              "Verificar download counts: packages legítimos têm milhões de downloads"
            ],
            tools: ["npm-check", "safety", "Socket.dev", "Snyk Advisor"],
            commands: [
              "# Verificar package statistics",
              "npm view lodash",
              "# Verificar: weekly downloads (deve ser milhões para packages populares)",
              "",
              "# Socket.dev CLI (detecta typosquatting)",
              "npx socket-cli audit",
              "",
              "# Comparar nomes (manual)",
              "# Legítimo: 'requests'",
              "# Typosquat: 'reqeusts', 'requ3sts', 'request-python'"
            ],
            steps: [
              "1. Revisar dependencies: verificar nomes corretos",
              "2. Comparar com documentação oficial: site do package",
              "3. Verificar metrics: downloads/week, GitHub stars, idade do package",
              "4. Red flags: <1000 downloads, publicado recentemente, sem repo GitHub",
              "5. Usar Socket.dev ou Snyk para analysis automática",
              "6. Implementar pre-commit hook: validar nomes de packages",
              "7. Educação: treinar devs sobre riscos de typosquatting"
            ],
            mitigation: [
              "Usar autocomplete de IDE (reduz typos)",
              "Code review: revisar mudanças em package.json",
              "Implementar allowlist: apenas packages aprovados",
              "Usar tools: Socket.dev (detecta typosquatting automaticamente)",
              "Pre-commit hook: validar packages contra allowlist",
              "Educação: awareness training sobre supply chain attacks"
            ],
            evidence: [
              "Package 'lodahs' instalado (typo de 'lodash')",
              "0 downloads/week, publicado há 2 dias",
              "Código malicioso encontrado: exfiltração de env vars",
              "Socket.dev alerta: 'Possible typosquatting detected'"
            ],
            references: [
              "https://snyk.io/blog/typosquatting-attacks/",
              "https://socket.dev/blog/typosquatting-campaigns",
              "https://www.usenix.org/conference/usenixsecurity20/presentation/ohm"
            ]
          }
        }
      ]
    },
    {
      id: "sc-license-compliance",
      title: "Compliance de Licenças",
      summary: "Gestão de licenças de open-source, detecção de incompatibilidades, risco legal.",
      items: [
        {
          id: "sc-license-1",
          title: "Auditar licenças de dependências (GPL, MIT, Apache, proprietary)",
          description: "Identificar licenças de todas dependências e verificar compatibilidade com licença do projeto.",
          guide: {
            overview: "Dependências têm licenças (GPL, MIT, Apache). Algumas são incompatíveis ou exigem disclosure de código.",
            impact: "Violação de licenças (processo judicial), obrigação de open-source de código proprietário (GPL).",
            detection: [
              "Scan de licenças: npm-license-crawler, pip-licenses, FOSSA",
              "Identificar GPL, AGPL (copyleft: exigem open-source)",
              "Verificar incompatibilidades: GPL + MIT pode ser problemático"
            ],
            tools: ["npm-license-crawler", "pip-licenses", "FOSSA", "FOSSology", "ScanCode"],
            commands: [
              "# Node.js - License audit",
              "npx license-checker --summary",
              "npx license-checker --json > licenses.json",
              "",
              "# Python",
              "pip install pip-licenses",
              "pip-licenses --format=json > licenses.json",
              "",
              "# Multi-language (ScanCode)",
              "scancode --license --copyright --json-pp licenses.json .",
              "",
              "# FOSSA CLI",
              "fossa analyze",
              "fossa test  # Check compliance"
            ],
            steps: [
              "1. Executar scan de licenças: license-checker, pip-licenses",
              "2. Identificar tipos: MIT, Apache-2.0, GPL, LGPL, proprietary, unknown",
              "3. Flaggar copyleft licenses: GPL, AGPL (exigem disclosure)",
              "4. Verificar incompatibilidades com licença do projeto",
              "5. Identificar 'unknown' licenses: investigar manualmente",
              "6. Consultar jurídico para casos complexos",
              "7. Documentar compliance: manter lista de licenses",
              "8. Integrar no CI: fail build se license não aprovada"
            ],
            mitigation: [
              "Estabelecer license policy: quais são permitidas?",
              "Allowlist: MIT, Apache-2.0, BSD (permissive)",
              "Blocklist: GPL, AGPL (copyleft, incompatível com proprietary)",
              "Revisar licenses em code review",
              "Usar FOSSA ou similar para automation",
              "Manter LICENSE file atualizado (creditar dependências)",
              "Consultar jurídico para dúvidas"
            ],
            evidence: [
              "Scan results: 120 MIT, 15 Apache, 3 GPL, 2 Unknown",
              "Red flag: GPL-3.0 license em 'library-x' (incompatível)",
              "Action: substituir por alternativa MIT-licensed",
              "LICENSE file gerado com créditos a todas dependências"
            ],
            references: [
              "https://fossa.com/",
              "https://www.gnu.org/licenses/license-list.html",
              "https://opensource.org/licenses",
              "https://tldrlegal.com/"
            ]
          }
        }
      ]
    }
  ]
};
