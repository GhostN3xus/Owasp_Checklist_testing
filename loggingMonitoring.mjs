/**
 * Logging, Monitoring & Incident Response
 * Práticas de logging seguro, SIEM, detecção de ameaças, resposta a incidentes
 */

export const loggingMonitoringChecklist = {
  id: "logging-monitoring",
  name: "Logging & Monitoring",
  description: "Logging Seguro, Monitoramento e Incident Response - SIEM, detecção de ameaças, forensics, playbooks de resposta a incidentes.",
  sections: [
    {
      id: "secure-logging",
      title: "Logging Seguro",
      summary: "Implementação de logs completos, seguros e úteis para auditoria e forensics.",
      items: [
        {
          id: "log-1",
          title: "Implementar logging completo de eventos de segurança",
          description: "Registrar autenticação, autorização, alterações de dados, acessos sensíveis.",
          guide: {
            overview: "Logs são essenciais para detecção de ataques, forensics e compliance. Devem capturar who, what, when, where, how.",
            impact: "Sem logs adequados, impossível detectar breaches, investigar incidentes ou provar compliance.",
            detection: [
              "Verificar se há logging de: login (success/fail), logout, access to sensitive data, data modifications, privilege changes, admin actions",
              "Validar log fields: timestamp, user_id, IP, action, resource, outcome (success/fail)",
              "Testar: logs são gerados em tempo real?"
            ],
            tools: ["Winston (Node.js)", "Log4j/Logback (Java)", "Python logging", "Serilog (.NET)"],
            commands: [
              "# Exemplo de log estruturado (JSON)",
              "{",
              "  \"timestamp\": \"2024-01-15T10:30:00Z\",",
              "  \"level\": \"INFO\",",
              "  \"event\": \"user.login.success\",",
              "  \"userId\": \"user-123\",",
              "  \"ip\": \"203.0.113.42\",",
              "  \"userAgent\": \"Mozilla/5.0...\",",
              "  \"sessionId\": \"sess-abc-xyz\"",
              "}",
              "",
              "# Log de acesso a dados sensíveis",
              "{",
              "  \"event\": \"data.access\",",
              "  \"userId\": \"admin-456\",",
              "  \"resource\": \"/api/users/789/credit-card\",",
              "  \"action\": \"READ\",",
              "  \"outcome\": \"success\"",
              "}"
            ],
            steps: [
              "1. Definir eventos críticos a logar: OWASP Logging Cheat Sheet",
              "2. Implementar logging library: Winston, Log4j, Python logging",
              "3. Estruturar logs em JSON (facilita parsing)",
              "4. Campos obrigatórios: timestamp (UTC), level, event, userId, IP",
              "5. Logar sucessos E falhas (tentativas de ataque)",
              "6. Evitar logs excessivos: não logar cada request HTTP (volumetria)",
              "7. Centralizar logs: enviar para SIEM/log aggregator",
              "8. Testar: simular eventos e verificar logs gerados"
            ],
            mitigation: [
              "Implementar logging em todos authentication/authorization points",
              "Usar structured logging (JSON) para facilitar análise",
              "Incluir context: userId, sessionId, correlationId",
              "Não logar dados sensíveis (passwords, tokens, PII - apenas redacted)",
              "Timestamp em UTC (evitar ambiguidade de timezone)",
              "Log retention policy: mínimo 90 dias (compliance pode exigir mais)",
              "Proteger logs: acesso restrito, tamper-evident"
            ],
            evidence: [
              "Análise de código: login endpoint sem logging",
              "Gap: alterações em roles/permissions não são logadas",
              "Log example: faltam campos userId e IP",
              "Proposta: implementar structured logging com Winston"
            ],
            references: [
              "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
              "https://www.owasp.org/index.php/Logging_Vocabulary_Cheat_Sheet",
              "NIST SP 800-92 - Guide to Computer Security Log Management"
            ]
          }
        },
        {
          id: "log-2",
          title: "Validar que logs não contêm dados sensíveis (passwords, tokens, PII)",
          description: "Verificar se logs fazem scrubbing/masking de credenciais, tokens e PII.",
          guide: {
            overview: "Logs frequentemente contêm senhas, tokens, CPF em plain text. Logs comprometidos = credentials comprometidas.",
            impact: "Vazamento de credenciais, tokens de sessão, PII via logs (violação LGPD/GDPR).",
            detection: [
              "Grep logs por padrões sensíveis: password=, token:, Authorization:, CPF, credit card",
              "Revisar código de logging: há sanitização?",
              "Testar: fazer request com credenciais e verificar logs"
            ],
            tools: ["grep", "log analysis tools", "secret scanners"],
            commands: [
              "# Scan de logs por dados sensíveis",
              "grep -i 'password\\|token\\|authorization\\|credit.card' /var/log/app/*.log",
              "",
              "# Padrões de CPF (Brasil)",
              "grep -E '[0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2}' /var/log/app/*.log",
              "",
              "# Verificar headers de auth em logs",
              "grep 'Authorization: Bearer' /var/log/nginx/access.log",
              "",
              "# Secret scanning em logs",
              "trufflehog filesystem /var/log/app/"
            ],
            steps: [
              "1. Listar dados sensíveis: passwords, tokens, API keys, PII (CPF, SSN, email, phone)",
              "2. Fazer grep em logs por padrões: password=, token:, Bearer, credit_card",
              "3. Revisar código: logger.info(`User login: ${user.password}`) = VULNERÁVEL",
              "4. Implementar scrubbing: redact/mask antes de logar",
              "5. Testar: fazer login e verificar se password aparece em log",
              "6. Automatizar: pre-commit hook para detectar logging de secrets",
              "7. Configurar log rotation com encryption at rest"
            ],
            mitigation: [
              "Implementar log scrubbing/sanitization",
              "Redact passwords: logger.info({ email, password: '[REDACTED]' })",
              "Mask PII: CPF 123.456.789-00 → CPF ***.***.***-00",
              "Nunca logar: Authorization headers, session tokens, API keys",
              "Usar allowlist: logar apenas campos aprovados",
              "Code review: verificar chamadas de logger",
              "Encryption at rest para logs armazenados"
            ],
            evidence: [
              "Log entry: {password: 'MySecretPass123!'} (plain text)",
              "Nginx access.log com Authorization: Bearer abc123...",
              "Application log com CPF completo: 123.456.789-00",
              "Código sem sanitização: logger.error({ user }) (loga objeto completo)"
            ],
            references: [
              "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
              "GDPR Article 32 - Security of processing",
              "LGPD Art. 46 - Segurança de dados pessoais"
            ]
          }
        }
      ]
    },
    {
      id: "siem-detection",
      title: "SIEM e Detecção de Ameaças",
      summary: "Centralização de logs, correlação de eventos, alertas de segurança.",
      items: [
        {
          id: "siem-1",
          title: "Implementar centralização de logs em SIEM",
          description: "Configurar envio de logs para plataforma SIEM (Splunk, ELK, Datadog) para análise centralizada.",
          guide: {
            overview: "SIEM (Security Information and Event Management) centraliza logs de múltiplas fontes, correlaciona eventos e gera alertas.",
            impact: "Detecção de ataques distribuídos, investigação de incidentes, compliance (SOC 2, PCI-DSS exigem SIEM).",
            detection: [
              "Verificar se logs são enviados para sistema centralizado",
              "Validar: todos componentes (app, DB, firewall, IDS) enviam logs?",
              "Testar: logs aparecem em tempo real no SIEM?"
            ],
            tools: [
              "ELK Stack (Elasticsearch, Logstash, Kibana)",
              "Splunk",
              "Datadog",
              "Sumo Logic",
              "Graylog",
              "Azure Sentinel",
              "AWS CloudWatch + Security Hub"
            ],
            commands: [
              "# Logstash config (enviar para ELK)",
              "input {",
              "  file {",
              "    path => '/var/log/app/*.log'",
              "    codec => json",
              "  }",
              "}",
              "output {",
              "  elasticsearch {",
              "    hosts => ['elasticsearch:9200']",
              "    index => 'app-logs-%{+YYYY.MM.dd}'",
              "  }",
              "}",
              "",
              "# Fluentd config (log forwarder)",
              "<source>",
              "  @type tail",
              "  path /var/log/app/*.log",
              "  format json",
              "</source>",
              "<match **>",
              "  @type elasticsearch",
              "  host elasticsearch",
              "  port 9200",
              "</match>"
            ],
            steps: [
              "1. Escolher SIEM: ELK (open-source), Splunk (enterprise), Datadog (SaaS)",
              "2. Configurar log shipping: Logstash, Fluentd, Filebeat",
              "3. Enviar logs de TODAS fontes: apps, databases, firewalls, IDS, cloud (CloudTrail)",
              "4. Parsear logs: extrair campos estruturados",
              "5. Criar índices/dashboards: visualizar eventos de segurança",
              "6. Testar: gerar evento de teste e verificar no SIEM",
              "7. Configurar retention: 90 dias (hot), 1 ano (cold storage)"
            ],
            mitigation: [
              "Centralizar TODOS os logs em SIEM (single source of truth)",
              "Usar log forwarders: Logstash, Fluentd, Vector",
              "Estruturar logs em JSON/CEF para parsing",
              "Implementar TLS para transmissão de logs (segurança)",
              "Configurar alertas para eventos críticos (próximo item)",
              "Dashboard de segurança: tentativas de login, erros 403, etc"
            ],
            evidence: [
              "Logs de aplicação não estão em SIEM (apenas local)",
              "Database audit logs não são coletados",
              "Proposta: implementar ELK Stack, Filebeat para shipping",
              "Estimativa: 10GB/dia de logs, retenção 90 dias"
            ],
            references: [
              "https://www.elastic.co/what-is/elk-stack",
              "https://www.splunk.com/",
              "https://www.datadoghq.com/product/log-management/",
              "NIST SP 800-92 - Guide to Computer Security Log Management"
            ]
          }
        },
        {
          id: "siem-2",
          title: "Configurar alertas para padrões suspeitos",
          description: "Criar regras de detecção: brute-force, privilege escalation, data exfiltration, anomalies.",
          guide: {
            overview: "SIEM deve gerar alertas em tempo real para atividades suspeitas, permitindo resposta rápida.",
            impact: "Detecção precoce de breaches (minutos vs meses), redução de dwell time, prevenção de danos.",
            detection: [
              "Configurar rules: 5+ failed logins = alerta, acesso a /admin por user comum, upload de 1GB+ em 1min",
              "Usar MITRE ATT&CK para mapear técnicas a detectar",
              "Testar: simular ataque e verificar se alerta é gerado"
            ],
            tools: ["Elastic SIEM Detection Rules", "Splunk Enterprise Security", "Sigma rules"],
            commands: [
              "# Elastic SIEM - Detection rule (KQL)",
              "event.category: authentication AND event.outcome: failure",
              "| where event.user_id exists",
              "| stats count by user_id",
              "| where count >= 5  # 5 falhas = alerta",
              "",
              "# Splunk - Correlation search",
              "index=app sourcetype=auth action=login outcome=failure",
              "| stats count by user_id",
              "| where count > 5",
              "| table user_id, count",
              "",
              "# Sigma rule (universal format)",
              "title: Brute Force Login Attempts",
              "logsource:",
              "  category: authentication",
              "detection:",
              "  selection:",
              "    event.outcome: failure",
              "  condition: selection | count(user_id) > 5",
              "level: high"
            ],
            steps: [
              "1. Mapear ameaças a detectar: brute-force, privilege escalation, data exfiltration, lateral movement",
              "2. Para cada ameaça, criar detection rule:",
              "   - Brute-force: 5+ login failures em 5min",
              "   - Privilege escalation: user role changed to admin",
              "   - Data exfiltration: 1GB+ uploaded em curto período",
              "   - Anomaly: acesso de IP novo/país novo",
              "3. Configurar thresholds (evitar false positives)",
              "4. Integrar com alerting: PagerDuty, Slack, email",
              "5. Definir severities: Critical → página oncall, High → Slack, Medium → email",
              "6. Testar rules: simular ataques e verificar alertas",
              "7. Tune rules: reduzir false positives baseado em feedback"
            ],
            mitigation: [
              "Implementar detection rules para MITRE ATT&CK TTPs",
              "Usar Sigma rules (universal, portable)",
              "Configurar alerting com on-call rotation",
              "Playbooks de resposta: O que fazer ao receber alerta X?",
              "Métricas: MTTD (Mean Time To Detect), MTTR (Mean Time To Respond)",
              "Continuous tuning: revisar rules mensalmente"
            ],
            evidence: [
              "SIEM configurado mas sem detection rules",
              "Teste: 50 login failures não geraram alerta",
              "Proposta: implementar 15 detection rules (starter set)",
              "Rules: brute-force, privilege escalation, SQLi attempts, etc"
            ],
            references: [
              "https://github.com/elastic/detection-rules",
              "https://github.com/SigmaHQ/sigma",
              "https://attack.mitre.org/",
              "https://www.splunk.com/en_us/blog/security/detection-spectrum.html"
            ]
          }
        }
      ]
    },
    {
      id: "incident-response",
      title: "Incident Response",
      summary: "Preparação, detecção, contenção, erradicação, recuperação e lessons learned.",
      items: [
        {
          id: "ir-1",
          title: "Desenvolver e testar Incident Response Plan",
          description: "Criar playbooks de resposta a incidentes, definir roles, praticar com tabletop exercises.",
          guide: {
            overview: "Incident Response Plan (IRP) define COMO responder a incidentes: quem faz o quê, quando, e como comunicar.",
            impact: "Sem IRP, resposta é caótica, lenta e ineficaz. Danos aumentam, custos sobem, compliance falha.",
            detection: [
              "Verificar se existe IRP documentado",
              "Validar: cobre principais cenários? (ransomware, data breach, DDoS)",
              "Testar: último tabletop exercise foi quando?"
            ],
            tools: ["NIST Incident Response Framework", "SANS Incident Handlers Handbook"],
            commands: [
              "# Não aplicável - processo/documentação",
              "# Deliverable: Incident Response Plan (PDF/Wiki)"
            ],
            steps: [
              "Fase 1 - Preparation:",
              "1. Formar CSIRT (Computer Security Incident Response Team)",
              "2. Definir roles: Incident Commander, Tech Lead, Communications, Legal",
              "3. Criar playbooks para cenários: ransomware, data breach, DDoS, insider threat",
              "4. Preparar ferramentas: forensics, backup, comunicação (war room)",
              "",
              "Fase 2 - Detection & Analysis:",
              "5. Alertas de SIEM → triage → classificar severity",
              "6. Coletar evidências: logs, memory dumps, network captures",
              "7. Análise: scope do incidente, sistemas afetados, dados comprometidos",
              "",
              "Fase 3 - Containment:",
              "8. Short-term: isolar sistemas comprometidos (network segmentation)",
              "9. Long-term: aplicar patches, fortalecer controles",
              "",
              "Fase 4 - Eradication:",
              "10. Remover malware, backdoors, contas comprometidas",
              "11. Validar: sistemas estão limpos?",
              "",
              "Fase 5 - Recovery:",
              "12. Restaurar sistemas a partir de backups limpos",
              "13. Monitorar para re-infection",
              "",
              "Fase 6 - Post-Incident:",
              "14. Lessons learned: O que deu certo? O que melhorar?",
              "15. Atualizar IRP baseado em aprendizados"
            ],
            mitigation: [
              "Documentar Incident Response Plan (NIST 800-61 framework)",
              "Playbooks por tipo de incidente: ransomware, phishing, data breach",
              "Definir SLAs: Critical incident = response em 15min",
              "Treinar equipe: tabletop exercises trimestrais",
              "Manter contact list: quem chamar? (legal, PR, CEO, customers)",
              "Testar backups: restore drills mensais",
              "Retainer com forensics firm (external help)"
            ],
            evidence: [
              "Ausência de IRP documentado",
              "CSIRT não formado (roles indefinidos)",
              "Último tabletop exercise: nunca",
              "Proposta: criar IRP baseado em NIST 800-61, formar CSIRT, schedule tabletop"
            ],
            references: [
              "NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide",
              "https://www.sans.org/white-papers/33901/",
              "https://www.cisa.gov/sites/default/files/publications/Incident-Response-Plan-Basics_508c.pdf"
            ]
          }
        },
        {
          id: "ir-2",
          title: "Implementar forensics readiness (coleta e preservação de evidências)",
          description: "Preparar capacidade de coletar evidências digitais para investigação e processos legais.",
          guide: {
            overview: "Forensics readiness: capacidade de coletar, preservar e analisar evidências digitais de forma forense (admissível em tribunal).",
            impact: "Sem forensics, impossível investigar incidentes profundamente, identificar atacante, ou suportar processos legais.",
            detection: [
              "Verificar: logs têm timestamps confiáveis? chain of custody?",
              "Validar: backups permitem point-in-time recovery?",
              "Testar: é possível fazer memory dump de servidores?"
            ],
            tools: [
              "Velociraptor (endpoint forensics)",
              "KAPE (Kroll Artifact Parser and Extractor)",
              "FTK Imager",
              "Autopsy",
              "Volatility (memory analysis)",
              "Wireshark/tcpdump"
            ],
            commands: [
              "# Memory dump (Linux)",
              "sudo dd if=/dev/mem of=memory.dump bs=1M",
              "# Ou usar LiME (Linux Memory Extractor)",
              "",
              "# Disk imaging",
              "sudo dd if=/dev/sda of=disk.img bs=4M status=progress",
              "sha256sum disk.img > disk.img.sha256  # Hash para integridade",
              "",
              "# Network capture",
              "tcpdump -i eth0 -w capture.pcap",
              "",
              "# Logs com timestamp confiável (NTP sync)",
              "timedatectl status  # Verificar sincronização NTP"
            ],
            steps: [
              "1. Sincronizar relógios com NTP (timestamps confiáveis)",
              "2. Habilitar audit logging completo (Linux auditd, Windows Security Log)",
              "3. Configurar log centralization (preserve chain of custody)",
              "4. Preparar ferramentas de forensics: Velociraptor, FTK Imager",
              "5. Documentar procedimentos de coleta (chain of custody)",
              "6. Treinar equipe: como coletar evidências sem contaminar",
              "7. Testar: simular coleta de evidências de sistema comprometido",
              "8. Manter backups imutáveis (WORM) para forensics"
            ],
            mitigation: [
              "NTP sync em TODOS sistemas (timestamps confiáveis)",
              "Centralizar logs em SIEM (tamper-evident)",
              "Implementar audit logging: Linux auditd, Windows Advanced Audit Policy",
              "Backups imutáveis (WORM, S3 Object Lock) para forensics",
              "Preparar forensics toolkit: imagens de VMs, memory dumps",
              "Documentar chain of custody procedures",
              "Treinamento: forensics basics para SOC team",
              "Retainer com forensics experts (external support)"
            ],
            evidence: [
              "Servidores sem sincronização NTP (timestamps não confiáveis)",
              "Ausência de ferramentas de forensics",
              "Logs locais (não centralizados, podem ser alterados)",
              "Proposta: implementar NTP, deploy Velociraptor, centralizar logs"
            ],
            references: [
              "NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response",
              "https://www.sans.org/white-papers/36287/",
              "https://www.velocidex.com/"
            ]
          }
        }
      ]
    }
  ]
};
