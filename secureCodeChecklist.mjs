export const secureCodeChecklist = {
  id: "secure-code",
  name: "Secure Code & Review",
  description: "Checklist para práticas de desenvolvimento seguro e revisão de código (Code Review).",
  sections: [
    {
      id: "code-review",
      title: "Checklist de Code Review de Segurança",
      summary: "Itens a serem verificados durante a revisão de código para garantir a segurança.",
      items: [
        {
          id: "cr-injection",
          title: "Prevenção de Injeção",
          description: "Verifique se todas as entradas de usuário são tratadas como não confiáveis e são devidamente validadas e sanitizadas.",
          guide: {
            overview: "Inspecione o código em busca de padrões de concatenação de strings em queries (SQL, NoSQL, LDAP) e comandos (OS command injection).",
            impact: "Falhas de injeção podem levar a vazamento de dados, execução remota de código e negação de serviço.",
            detection: ["Procure por `exec`, `eval`, `subprocess` com `shell=True`.", "Verifique o uso de Prepared Statements ou ORMs."],
            tools: ["Semgrep", "ESLint (com plugin de segurança)", "Bandit"],
            commands: ["semgrep --config 'p/injection'"],
            mitigation: ["Use sempre ORMs ou Prepared Statements parametrizados.", "Valide e sanitize todas as entradas externas com base em uma lista de permissões (allow-list)."],
            references: ["OWASP Cheat Sheet: Injection Prevention"]
          }
        },
        {
          id: "cr-auth",
          title: "Autenticação e Gerenciamento de Sessão",
          description: "Confirme se a autenticação é robusta, se o MFA está implementado para funções críticas e se as sessões são invalidadas corretamente.",
          guide: {
            overview: "Revise os fluxos de login, logout e recuperação de senha. Verifique o armazenamento de credenciais e a geração de tokens de sessão.",
            impact: "Falhas na autenticação podem permitir o acesso não autorizado a contas e sistemas.",
            detection: ["Procure por senhas hardcoded.", "Verifique a configuração de bibliotecas de autenticação (ex: Passport, Spring Security)."],
            tools: ["Revisão manual", "Git-secrets"],
            mitigation: ["Armazene senhas usando hashes adaptativos (ex: bcrypt, Argon2).", "Invalide a sessão no servidor durante o logout.", "Implemente proteção contra brute-force."],
            references: ["OWASP Cheat Sheet: Authentication"]
          }
        },
        {
          id: "cr-access-control",
          title: "Controle de Acesso",
          description: "Garanta que o código impõe o controle de acesso no lado do servidor para cada requisição, verificando se o usuário tem permissão para a ação e o recurso.",
          guide: {
            overview: "Procure por falhas de IDOR (Insecure Direct Object References) e verifique se as verificações de permissão são centralizadas e aplicadas em todas as rotas/endpoints.",
            impact: "Controle de acesso falho permite que usuários acessem dados ou funcionalidades que não deveriam.",
            detection: ["Inspecione controllers/rotas para garantir que verificações de permissão são feitas antes da lógica de negócio.", "Verifique se as roles são consultadas a partir de uma fonte confiável (ex: token JWT, sessão do servidor)."],
            tools: ["Revisão Manual"],
            mitigation: ["Implemente verificações de permissão em um middleware ou decorador centralizado.", "Use identificadores de objeto indiretos e aleatórios (UUIDs)."],
            references: ["OWASP Cheat Sheet: Access Control"]
          }
        },
        {
          id: "cr-crypto",
          title: "Criptografia",
          description: "Verifique se dados sensíveis em trânsito e em repouso são criptografados com algoritmos fortes e se o gerenciamento de chaves é seguro.",
          guide: {
            overview: "Procure por algoritmos criptográficos fracos ou obsoletos (ex: MD5, SHA1). Verifique se as chaves de criptografia não estão hardcoded.",
            impact: "Criptografia fraca pode levar à exposição de dados sensíveis.",
            detection: ["Busque por `MD5`, `SHA1`, `DES`, `RC4` no código.", "Verifique a configuração de TLS/SSL nos servidores web."],
            tools: ["Revisão Manual", "SSLyze", "TestSSL.sh"],
            mitigation: ["Use algoritmos fortes como AES-256 para criptografia simétrica e RSA-2048 ou superior para assimétrica.", "Armazene chaves em um cofre de segredos."],
            references: ["OWASP Cheat Sheet: Cryptographic Storage"]
          }
        },
        {
          id: "cr-logging-monitoring",
          title: "Logging e Monitoramento",
          description: "Garanta que eventos de segurança relevantes (logins, falhas de acesso, transações críticas) são registrados para permitir a detecção de incidentes.",
          guide: {
            overview: "Verifique se o código registra informações suficientes para rastrear a atividade de um usuário sem logar dados sensíveis (senhas, tokens).",
            impact: "Logging inadequado dificulta ou impossibilita a detecção e a resposta a incidentes de segurança.",
            detection: ["Inspecione o código em busca de chamadas para bibliotecas de log.", "Verifique se os logs não contêm senhas, chaves de API ou PII."],
            tools: ["Revisão Manual"],
            mitigation: ["Implemente um framework de logging centralizado.", "Defina quais eventos de segurança devem ser registrados e em qual nível de detalhe."],
            references: ["OWASP Cheat Sheet: Logging"]
          }
        },
        {
          id: "cr-error-handling",
          title: "Tratamento de Erros e Exceções",
          description: "Valide se erros são tratados adequadamente sem expor informações sensíveis ou deixar a aplicação em estado inconsistente.",
          guide: {
            overview: "Erros podem revelar detalhes internos (stack traces, versões, paths) ou deixar o sistema vulnerável (transações incompletas).",
            impact: "Tratamento inadequado de erros pode resultar em information disclosure, DOS ou estado corrompido de dados.",
            detection: [
              "Procure por try/catch vazio ou logging de stack traces em frontend.",
              "Verifique se erros diferenciados revelam validação (ex: 'usuário não existe' vs 'senha incorreta').",
              "Teste se erros deixam recursos em lock (arquivos, conexões DB)."
            ],
            tools: ["Revisão Manual", "SAST (Semgrep, Bandit)"],
            commands: ["semgrep --config 'p/error-handling'"],
            mitigation: [
              "Implementar handlers específicos para exceções esperadas.",
              "Registrar detalhes internos em logs, não em respostas.",
              "Fornecer mensagens genéricas ('operação falhou') ao usuário.",
              "Implementar finally blocks para limpeza de recursos."
            ],
            references: ["OWASP Error Handling Cheat Sheet"]
          }
        },
        {
          id: "cr-input-validation",
          title: "Validação de Entrada (Input Validation)",
          description: "Certifique-se que todas as entradas de usuário são validadas contra uma whitelist de padrões esperados.",
          guide: {
            overview: "Validação inadequada permite injeção (SQL, LDAP, OS command), XSS, path traversal e outros ataques.",
            impact: "Falhas de validação são a raiz de 90% das vulnerabilidades críticas.",
            detection: [
              "Identifique todos os pontos de entrada (formulários, APIs, uploads).",
              "Verifique se validação ocorre no servidor (não apenas frontend).",
              "Teste limits (tamanho, comprimento, caracteres especiais)."
            ],
            tools: ["SAST (Semgrep, ESLint security)", "Validação libraries (Zod, Yup, Pydantic)"],
            commands: ["semgrep --config 'p/owasp-top-ten' -f input"],
            mitigation: [
              "Implementar whitelist validation (aceitar apenas padrões conhecidos).",
              "Usar bibliotecas de validação de schema (Zod, Pydantic, Jakarta Validation).",
              "Validar no servidor SEMPRE, não confiando no cliente.",
              "Rejeitar requests fora do padrão esperado (retornar 400)."
            ],
            references: ["OWASP Input Validation Cheat Sheet"]
          }
        },
        {
          id: "cr-output-encoding",
          title: "Codificação de Saída (Output Encoding)",
          description: "Garanta que dados são encoded corretamente para o contexto (HTML, JavaScript, URL) prevenindo XSS.",
          guide: {
            overview: "XSS ocorre quando dados não são encodificados antes de serem renderizados. O encoding é diferente por contexto.",
            impact: "XSS permite roubo de sessões, defacement, redirecionamento e pivot para outros usuários.",
            detection: [
              "Procure por template interpolation sem escaping (ex: {{user_input}} em templates).",
              "Verifique innerHTML, eval, innerText não escapados.",
              "Teste payload XSS: <script>alert(1)</script>"
            ],
            tools: ["SAST (Semgrep, ESLint, Brakeman)", "DAST (OWASP ZAP, Burp)"],
            commands: ["semgrep --config 'p/xss'"],
            mitigation: [
              "Usar template engines que escapam por padrão (Jinja2, EJS, ERB).",
              "Escapar para HTML: & < > \" '.",
              "Escapar para JavaScript: \\ \" '.",
              "Escapar para URL: %XX encoding.",
              "Implementar Content Security Policy (CSP)."
            ],
            references: ["OWASP XSS Prevention Cheat Sheet"]
          }
        }
      ]
    },
    {
      id: "secure-dev-practices",
      title: "Práticas de Desenvolvimento Seguro",
      summary: "Ações e hábitos para integrar a segurança no ciclo de vida de desenvolvimento de software (SDLC).",
      items: [
        {
          id: "sdp-threat-modeling",
          title: "Modelagem de Ameaças",
          description: "Realize sessões de modelagem de ameaças no início do desenvolvimento de novas funcionalidades para identificar e mitigar riscos de design.",
          guide: {
            overview: "Use frameworks como STRIDE para analisar os componentes da aplicação e os fluxos de dados, identificando potenciais ameaças.",
            impact: "A falta de modelagem de ameaças pode levar a falhas de segurança arquiteturais que são difíceis e caras de corrigir mais tarde.",
            tools: ["OWASP Threat Dragon", "Microsoft Threat Modeling Tool"],
            mitigation: ["Integre a modelagem de ameaças ao seu processo de design.", "Documente as ameaças e as mitigações em um backlog de segurança."],
            references: ["OWASP Cheat Sheet: Threat Modeling"]
          }
        },
        {
          id: "sdp-sast-dast",
          title: "Integração de SAST e DAST",
          description: "Integre ferramentas de teste de segurança estático (SAST) e dinâmico (DAST) no pipeline de CI/CD para identificar vulnerabilidades automaticamente.",
          guide: {
            overview: "SAST analisa o código-fonte em busca de falhas, enquanto DAST testa a aplicação em execução. A integração contínua permite a detecção precoce de problemas.",
            impact: "A automação de testes de segurança reduz a janela de exposição de vulnerabilidades.",
            tools: ["SAST: Semgrep, SonarQube, Checkmarx", "DAST: OWASP ZAP, Burp Suite, Invicti"],
            mitigation: ["Configure o pipeline para falhar se vulnerabilidades críticas forem encontradas.", "Treine a equipe para analisar e corrigir os resultados das ferramentas."],
            references: ["OWASP DevSecOps Guideline"]
          }
        },
        {
          id: "sdp-security-champions",
          title: "Programa de Security Champions",
          description: "Crie um programa de Security Champions para disseminar o conhecimento de segurança e escalar a cultura de AppSec na equipe de desenvolvimento.",
          guide: {
            overview: "Security Champions são desenvolvedores com interesse em segurança que atuam como um ponto de contato e multiplicadores de conhecimento dentro de suas equipes.",
            impact: "Aumenta a conscientização sobre segurança e a autonomia das equipes para resolver problemas de segurança.",
            mitigation: ["Forneça treinamento contínuo para os Security Champions.", "Crie um canal de comunicação para que eles possam colaborar e tirar dúvidas."],
            references: ["OWASP Security Champions Playbook"]
          }
        },
        {
          id: "sdp-secure-architecture",
          title: "Design de Arquitetura Segura",
          description: "Integre princípios de segurança no design arquitetônico desde a conceção, não como afterthought.",
          guide: {
            overview: "Arquitetura segura começa com decisões de design corretas: segmentação, least privilege, defense-in-depth.",
            impact: "Arquitetura fraca requer patches constantes. Design seguro reduz risco global.",
            detection: [
              "Revise diagramas de arquitetura com threat modeling.",
              "Valide separação de responsabilidades (frontend/backend/DB).",
              "Confirme implementação de least privilege em componentes.",
              "Verifique se criptografia end-to-end está em design."
            ],
            tools: ["OWASP Threat Dragon", "Architecture review checklist", "NIST guidelines"],
            commands: ["n/a"],
            mitigation: [
              "Implementar defense-in-depth (múltiplas camadas).",
              "Separar dados sensíveis em componentes isolados.",
              "Usar micro-segmentação de rede.",
              "Implementar zero-trust architecture.",
              "Revisar arquitetura antes de implementação grande."
            ],
            references: ["NIST Application Security", "OWASP Secure Architecture"]
          }
        },
        {
          id: "sdp-training-modules",
          title: "Módulos de Treinamento por Vulnerabilidade",
          description: "Estrutura de treinamento para equipes aprenderem sobre vulnerabilidades comuns com exemplos práticos.",
          guide: {
            overview: "Treinamento efetivo requer exemplos code, demos e hands-on labs, não apenas slides.",
            impact: "Equipes bem treinadas reduzem vulnerabilidades em 60-70%.",
            detection: [
              "Valide se equipe conhece OWASP Top 10.",
              "Teste conhecimento com labs práticos.",
              "Revise se cada desenvolvedor passou por treinamento obrigatório."
            ],
            tools: [
              "OWASP WebGoat (hands-on training)",
              "OWASP Juice Shop (vulnerable app for learning)",
              "HackTheBox, TryHackMe (CTF platforms)",
              "Internal labs baseados em vulnerabilidades encontradas"
            ],
            commands: ["n/a"],
            mitigation: [
              "Criar labs por vulnerabilidade (XSS lab, SQLi lab, etc).",
              "Usar vulnerable apps (WebGoat, Juice Shop) para treinar.",
              "Fazer code katas de segurança semanalmente.",
              "Revisar vulnerabilidades encontradas como teaching moments.",
              "Documentar padrões seguros por linguagem/framework."
            ],
            references: [
              "OWASP WebGoat",
              "OWASP Juice Shop",
              "HackTheBox Academy",
              "PortSwigger Web Security Academy"
            ]
          }
        },
        {
          id: "sdp-presentation-prep",
          title: "Preparação de Apresentações de Segurança",
          description: "Guia para preparar apresentações efetivas sobre achados de segurança para diferentes audiências.",
          guide: {
            overview: "Apresentações efetivas adaptam mensagem para audience (executivos vs developers vs security team).",
            impact: "Comunicação clara de risco permite aprovação de investimentos em segurança.",
            detection: [
              "Valide se apresentação tem metáforas de negócio (não apenas técnica).",
              "Confirme que métricas de risco estão claras.",
              "Verifique se recomendações têm custo/benefício estimado."
            ],
            tools: ["PowerPoint/Keynote", "Tableau/Power BI para dashboards", "Dradis para relatórios"],
            commands: ["n/a"],
            steps: [
              "Audience: Executivos → Focar em impacto financeiro, conformidade legal, reputação",
              "Audience: Developers → Focar em código-exemplo, ferramentas, hands-on fix",
              "Audience: Security team → Focar em detalhes técnicos, prioritização de remediation",
              "Estrutura: Executive Summary (2 slides) → Findings (5-10 slides) → Roadmap (2 slides)",
              "Incluir: Dashboard de trending, comparação com benchmarks, roadmap de 30/90/180 dias"
            ],
            mitigation: [
              "Treinar apresentadores sobre comunicação de risco.",
              "Usar storytelling (contexto → problema → solução).",
              "Incluir demos/videos de vulnerabilidades reais.",
              "Fazer dry-runs antes da apresentação final.",
              "Preparar Q&A com perguntas antecipadas."
            ],
            evidence: [
              "Deck de apresentação com 15-20 slides bem estruturado.",
              "Dashboard de métricas de segurança trending.",
              "Roadmap de remediação com prazos e owners.",
              "Registro de apresentação (video/transcrição) para referência."
            ],
            references: [
              "NIST Risk Communication",
              "SANS Communicating Security",
              "Storytelling in Security"
            ]
          }
        }
      ]
    },
    {
      id: "sca",
      title: "Análise de Composição de Software (SCA)",
      summary: "Gerenciamento e análise de segurança de dependências de terceiros.",
      items: [
        {
          id: "sca-vulnerability-scanning",
          title: "Varredura de Vulnerabilidades em Dependências",
          description: "Utilize ferramentas de SCA para escanear continuamente as dependências do projeto em busca de vulnerabilidades conhecidas (CVEs).",
          guide: {
            overview: "Integre ferramentas de SCA ao seu pipeline de CI/CD e ao seu ambiente de desenvolvimento local para identificar componentes vulneráveis.",
            impact: "Dependências vulneráveis podem ser exploradas por invasores para comprometer a aplicação.",
            tools: ["npm audit", "pip-audit", "Snyk", "Trivy", "OWASP Dependency-Check"],
            commands: ["npm audit --audit-level=critical", "trivy fs ."],
            mitigation: ["Automatize a criação de pull requests para atualizar dependências vulneráveis.", "Defina uma política clara para lidar com vulnerabilidades (ex: corrigir todas as críticas em 48h)."],
            references: ["OWASP Top 10: A06-Vulnerable and Outdated Components"]
          }
        },
        {
          id: "sca-sbom",
          title: "Manutenção de um SBOM (Software Bill of Materials)",
          description: "Gere e mantenha um SBOM para ter um inventário completo de todas as dependências (diretas e transitivas) do seu projeto.",
          guide: {
            overview: "Um SBOM é um arquivo que lista todos os componentes de software em uma aplicação. Formatos comuns incluem CycloneDX e SPDX.",
            impact: "Um SBOM é essencial para a transparência da cadeia de suprimentos de software e para responder rapidamente a novas vulnerabilidades.",
            tools: ["CycloneDX CLI", "SPDX SBOM Generator", "Syft"],
            commands: ["syft . -o cyclonedx-json"],
            mitigation: ["Gere o SBOM a cada build no pipeline de CI/CD.", "Armazene os SBOMs em um repositório centralizado para fácil acesso."],
            references: ["NTIA: The Minimum Elements For a Software Bill of Materials"]
          }
        },
        {
          id: "sca-license-compliance",
          title: "Conformidade de Licenças",
          description: "Verifique as licenças das dependências para garantir que elas são compatíveis com as políticas da sua organização e não introduzem riscos legais.",
          guide: {
            overview: "Use ferramentas de SCA para identificar as licenças de todas as dependências e compará-las com uma lista de licenças aprovadas.",
            impact: "O uso de dependências com licenças restritivas pode levar a obrigações legais indesejadas, como a necessidade de abrir o código-fonte do seu produto.",
            tools: ["FOSSA", "Snyk License Compliance", "Trivy"],
            commands: ["trivy fs --format cyclonedx . | cyclonedx-cli-linux-x64 validate"],
            mitigation: ["Defina uma política de licenças de software aprovadas.", "Integre a verificação de licenças no pipeline de CI/CD para bloquear dependências não conformes."],
            references: ["OSI (Open Source Initiative)"]
          }
        }
      ]
    },
    {
      id: "vuln-management",
      title: "Gerenciamento de Vulnerabilidades",
      summary: "Processos e ciclos de remediação de vulnerabilidades descobertas.",
      items: [
        {
          id: "vm-triage-prioritization",
          title: "Triagem e Priorização de Vulnerabilidades",
          description: "Estabeleça critérios claros para priorizar remediação baseado em risco, exploitabilidade e impacto.",
          guide: {
            overview: "Nem todas as vulns devem ser corrigidas no mesmo prazo. Priorização permite alocar recursos eficientemente.",
            impact: "Falta de priorização resulta em desperdício de recursos ou deixa vulnerabilidades críticas sem corrigir.",
            detection: [
              "Valide se existe SLA por CVSS score.",
              "Confirme se vulns exploradas recebem tratamento urgente.",
              "Verifique se remediação de baixo risco pode ser agregada.",
              "Teste se descobertas duplicadas são consolidadas."
            ],
            tools: ["CVSS Score calculator (cvss-calculator.appspot.com)", "Vulnerability management platforms (Tenable, Qualys, Snyk)", "Jira/Azure DevOps"],
            commands: ["n/a"],
            steps: [
              "Estabelecer matriz de prioridade (CVSS × Exploitabilidade × Impacto Negócio).",
              "CVSS 9-10 (Critical): 72 horas",
              "CVSS 7-8.9 (High): 1 semana",
              "CVSS 5-6.9 (Medium): 2 semanas",
              "CVSS < 5 (Low): 30 dias ou próximo sprint",
              "Revisar prioridades semanalmente para novos dados de exploração."
            ],
            mitigation: [
              "Criar SLA formalizados por severidade.",
              "Implementar dashboard mostrando vulns por SLA.",
              "Escalar vulns vencidas para management.",
              "Permitir exceções temporárias com aprovação executiva.",
              "Revisar e ajustar critérios trimestral."
            ],
            evidence: [
              "Matriz de priorização documentada.",
              "SLA policy assinada por leadership.",
              "Dashboard mostrando cumprimento de SLA.",
              "Relatório trimestral de trends.",
              "Escalations apropriadamente documentados."
            ],
            references: ["CVSS v3.1 Specification", "NIST SP 800-40"]
          }
        },
        {
          id: "vm-remediation-tracking",
          title: "Rastreamento de Remediação e Validação",
          description: "Implemente processo de rastreamento de remediação até fechamento e re-teste.",
          guide: {
            overview: "Vulnerabilidades precisam ser rastreadas de descoberta → fix → re-teste → fechamento.",
            impact: "Sem rastreamento, vulns são perdidas ou fechadas sem verificação real de correção.",
            detection: [
              "Valide se cada vulnerabilidade tem ticket (Jira/Azure).",
              "Confirme se fix foi re-testado antes de marcar como resolved.",
              "Verifique se there's evidência de correção (commit hash, build number).",
              "Teste se vulns corrigidas não reaparecem (regression)."
            ],
            tools: ["Jira", "Azure DevOps", "GitHub Issues", "Bugzilla", "Vulnerability Management Systems"],
            commands: ["n/a"],
            steps: [
              "Criar ticket com: ID vuln, CVSS, description, proof-of-concept, remediation steps.",
              "Atribuir owner (developer, team lead).",
              "Developer corrige em branch feature.",
              "Security team re-testa em staging antes de approve merge.",
              "Adicionar testes automatizados para prevenir regression.",
              "Marcar como resolved com evidência (commit, build).",
              "Rastrear trending de time-to-fix (TTF) médio."
            ],
            mitigation: [
              "Usar template padronizado para tickets.",
              "Exigir code review + security review antes de merge.",
              "Implementar testes automatizados que falham se vuln retorna.",
              "Fazer re-scanning periódico para detectar regressão.",
              "Publicamente reconhecer equipes com melhor TTF."
            ],
            evidence: [
              "Template de ticket de vulnerabilidade.",
              "Screenshots mostrando rastreamento em Jira.",
              "Histório de re-testes com evidência.",
              "Dashboard mostrando Time-to-Fix trends.",
              "Gráfico de regression detection por período."
            ],
            references: ["NIST SP 800-40: Patch Management", "OWASP Vulnerability Management"]
          }
        },
        {
          id: "vm-metrics-reporting",
          title: "Métricas e Relatórios de Segurança",
          description: "Implemente dashboard e relatórios para rastrear progress na redução de risco.",
          guide: {
            overview: "Métricas permitem demonstrar progress e informar decisões de investimento em segurança.",
            impact: "Falta de métricas impossibilita demonstrar ROI de segurança e geralmente resulta em desinvestimento.",
            detection: [
              "Valide se existe dashboard público de vulnerabilidades.",
              "Confirme se trending está disponível (mês-a-mês, year-over-year).",
              "Verifique se métricas são alinhadas com objetivos estratégicos.",
              "Teste se reports automaticamente acessíveis para stakeholders."
            ],
            tools: ["Tableau", "Power BI", "Grafana", "ELK Stack", "Security Metrics tools (ThreadFix, Dradis)"],
            commands: ["n/a"],
            steps: [
              "Definir KPIs principais: Vulns descobertas, remediadas, Age (dias aberto), Time-to-Fix.",
              "Criar dashboard em Tableau/PowerBI/Grafana.",
              "Incluir gráficos: Trending, by-severity, by-product, by-team.",
              "Agregar dados de múltiplas ferramentas (SAST, DAST, pentest, dependency scanning).",
              "Publicar relatório executivo mensal.",
              "Incluir benchmarks de industria/histórico interno para comparação."
            ],
            mitigation: [
              "Treinar stakeholders a interpretar métricas.",
              "Usar storytelling (números + narrativa).",
              "Compartilhar metrics em town halls/all-hands.",
              "Vincular métricas a OKRs (Objectives & Key Results).",
              "Revisar e ajustar métricas quarterly."
            ],
            evidence: [
              "Dashboard executivo mostrando status de vulnerabilidades.",
              "Relatório mensal com trending e comparação.",
              "Benchmark report (industria vs próprio).",
              "Apresentação trimestral para C-suite.",
              "Archive histórico de métricas (12+ meses)."
            ],
            references: ["OWASP Metrics Project", "NIST Cybersecurity Framework Metrics", "SANS Metrics and Reporting"]
          }
        }
      ]
    }
  ]
};
