const serverHardening = {
  overview:
    "Práticas essenciais de hardening para servidores web, sistemas operacionais e serviços críticos.",
  stacks: [
    {
      id: "iis",
      name: "IIS",
      summary: "Checklist de segurança para Microsoft IIS.",
      items: [
        {
          id: "iis-1",
          title: "Desabilitar módulos não utilizados",
          description:
            "Garanta que apenas módulos necessários estejam habilitados para reduzir a superfície de ataque.",
          guide: {
            overview:
              "Mantenha somente módulos estritamente necessários para minimizar vetores de exploração.",
            impact:
              "Módulos desnecessários expõem handlers vulneráveis e ampliam a superfície de ataque.",
            detection: [
              "Compare módulos habilitados com baseline corporativo.",
              "Revise logs IIS para chamadas a handlers legados.",
              "Audite configurações após atualizações de patch."
            ],
            tools: ["appcmd", "IIS Manager"],
            commands: [
              "appcmd list module",
              "appcmd set config /section:modules /-[name='WebDAVModule']"
            ],
            steps: [
              "Inventarie módulos habilitados por site/aplicação.",
              "Desabilite componentes não utilizados e teste regressões.",
              "Implemente monitoramento para reativações não autorizadas."
            ],
            mitigation: [
              "Aplicar templates de configuração mínimos.",
              "Automatizar hardening com DSC/GPO.",
              "Revisar após cada atualização do IIS."
            ],
            evidence: [
              "Export de configuração mostrando módulos ativos.",
              "Plano de validação pós-mudança.",
              "Relatório de auditoria comprovando remoção."
            ],
            references: ["Microsoft IIS Security Hardening", "CIS IIS Benchmark"]
          }
        },
        {
          id: "iis-2",
          title: "Forçar TLS 1.2+",
          description:
            "Desabilite SSLv2/v3 e TLS 1.0/1.1 via registro e confirme com ferramentas de teste.",
          guide: {
            overview:
              "Certifique-se de que apenas protocolos modernos estejam habilitados no Schannel.",
            impact:
              "Protocolos legados permitem downgrade attacks e quebra de confidencialidade.",
            detection: [
              "Execute scans TLS periódicos.",
              "Verifique políticas de grupo aplicadas.",
              "Monitore logs de handshake com versões antigas."
            ],
            tools: ["PowerShell", "testssl.sh"],
            commands: [
              "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0 /v Enabled /t REG_DWORD /d 0 /f",
              "testssl.sh --fast https://hostname"
            ],
            steps: [
              "Aplicar ajustes via registro ou GPO.",
              "Reiniciar serviços para efetivar.",
              "Executar teste de validação com testssl.sh e registrar resultados."
            ],
            mitigation: [
              "Habilitar TLS 1.2+ com cipher suites fortes.",
              "Implementar monitoramento contínuo de conformidade.",
              "Documentar exceções para sistemas legados."
            ],
            evidence: [
              "Dump de configuração do Schannel.",
              "Relatório testssl confirmando protocolos habilitados.",
              "Ticket de mudança aprovado."
            ],
            references: ["Microsoft TLS Best Practices", "OWASP Server Security"]
          }
        }
      ]
    },
    {
      id: "apache",
      name: "Apache",
      summary: "Hardening para servidores Apache HTTPD.",
      items: [
        {
          id: "apache-1",
          title: "Habilitar ModSecurity e OWASP CRS",
          description:
            "Configure o WAF ModSecurity com conjunto de regras OWASP CRS atualizado.",
          guide: {
            overview:
              "ModSecurity com CRS oferece mitigação em camada 7 para ataques comuns.",
            impact:
              "Sem CRS atualizado, aplicações ficam expostas a ataques conhecidos (OWASP Top 10).",
            detection: [
              "Valide versão do CRS instalada.",
              "Monitore logs de bloqueio para eficácia e falsos positivos.",
              "Revise exceções e regras customizadas regularmente."
            ],
            tools: ["ModSecurity", "tail", "grep"],
            commands: [
              "a2enmod security2",
              "git clone https://github.com/coreruleset/coreruleset /etc/modsecurity.d/owasp-crs"
            ],
            steps: [
              "Instalar CRS e habilitar include no modsecurity.conf.",
              "Configurar paranoia level adequado.",
              "Monitorar logs para ajustar exceções."
            ],
            mitigation: [
              "Automatizar atualização de regras.",
              "Integrar alertas com SIEM.",
              "Testar alterações em ambiente de homologação."
            ],
            evidence: [
              "Arquivo de configuração com include do CRS.",
              "Relatório de eventos bloqueados.",
              "Plano de tuning documentado."
            ],
            references: ["OWASP ModSecurity CRS", "Apache Security Guide"]
          }
        },
        {
          id: "apache-2",
          title: "Ocultar versão do servidor",
          description:
            "Use diretivas ServerTokens Prod e ServerSignature Off para evitar fingerprinting.",
          guide: {
            overview:
              "Reduzir exposição de informações dificulta fingerprinting e exploração automatizada.",
            impact:
              "Divulgação de versão facilita exploração de vulnerabilidades específicas.",
            detection: [
              "Realizar requisições HEAD e verificar cabeçalhos Server.",
              "Auditar arquivos de configuração por diretivas ausentes.",
              "Utilizar scanners externos para confirmar."
            ],
            tools: ["curl", "apachectl"],
            commands: [
              "grep -i ServerTokens /etc/apache2/conf-enabled/security.conf",
              "curl -I https://hostname"
            ],
            steps: [
              "Definir ServerTokens Prod e ServerSignature Off.",
              "Recarregar serviço apache2.",
              "Validar cabeçalhos pós-ajuste."
            ],
            mitigation: [
              "Aplicar mesma configuração em proxies reversos.",
              "Adicionar headers customizados controlados.",
              "Monitorar alterações em arquivos de configuração."
            ],
            evidence: [
              "Saída do curl sem banner de versão.",
              "Commit de configuração versionado.",
              "Checklist de conformidade aprovado."
            ],
            references: ["CIS Apache Benchmark", "OWASP Secure Headers"]
          }
        }
      ]
    },
    {
      id: "nginx",
      name: "Nginx",
      summary: "Boas práticas de hardening para Nginx.",
      items: [
        {
          id: "nginx-1",
          title: "Implementar cabeçalhos de segurança",
          description:
            "Configure add_header para CSP, HSTS, X-Frame-Options, Permissions-Policy e X-Content-Type-Options.",
          guide: {
            overview:
              "Cabeçalhos padronizados reduzem risco de XSS, clickjacking e downgrade.",
            impact:
              "Sem cabeçalhos, usuários ficam expostos a ataques client-side frequentes.",
            detection: [
              "Capturar respostas HTTP e validar valores.",
              "Auditar configurações nginx.conf e includes.",
              "Monitorar scanners externos (Observatory)."
            ],
            tools: ["curl", "testssl.sh"],
            commands: [
              "add_header Content-Security-Policy \"default-src 'self'\" always;",
              "curl -I https://hostname"
            ],
            steps: [
              "Configurar cabeçalhos em nível http/server/location.",
              "Recarregar Nginx com validação de sintaxe.",
              "Executar testes para garantir aplicação em respostas de erro."
            ],
            mitigation: [
              "Definir políticas CSP adequadas ao aplicativo.",
              "Aplicar HSTS com preload quando viável.",
              "Manter documentação e exceções aprovadas."
            ],
            evidence: [
              "Saída do curl/testssl.",
              "Configuração versionada com add_header.",
              "Relatório Observatory pós-ajuste."
            ],
            references: ["Mozilla Observatory", "OWASP Secure Headers"]
          }
        },
        {
          id: "nginx-2",
          title: "Configurar rate limiting nativo",
          description:
            "Utilize limit_req_zone e limit_conn_zone para mitigar abusos antes do backend.",
          guide: {
            overview:
              "Rate limiting nativo protege a aplicação contra bursts antes de atingir o backend.",
            impact:
              "Sem rate limit, endpoints ficam vulneráveis a DoS e brute-force.",
            detection: [
              "Validar configuração ativa via nginx -T.",
              "Monitorar logs por respostas 503 (limite).",
              "Testar limites com ferramentas de carga."
            ],
            tools: ["nginx", "hey", "k6"],
            commands: [
              "limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;",
              "tail -f /var/log/nginx/error.log"
            ],
            steps: [
              "Definir zonas e aplicar limit_req/limit_conn.",
              "Recarregar serviço e monitorar métricas.",
              "Ajustar limites conforme comportamento real."
            ],
            mitigation: [
              "Integrar com WAF/CDN para camadas adicionais.",
              "Adicionar dashboards de observabilidade.",
              "Revisar limites periodicamente."
            ],
            evidence: [
              "Configuração nginx -T.",
              "Logs demonstrando bloqueios legítimos.",
              "Resultados de teste de carga pós-configuração."
            ],
            references: ["Nginx Rate Limiting Guide", "OWASP API Security"]
          }
        }
      ]
    },
    {
      id: "windows",
      name: "Windows Server",
      summary: "Baseline de segurança para servidores Windows.",
      items: [
        {
          id: "win-1",
          title: "Aplicar CIS Benchmark via LGPO",
          description:
            "Importe templates de política local que atendam ao CIS Benchmark para Windows Server.",
          guide: {
            overview:
              "Aplicar baseline CIS fortalece políticas de segurança do Windows Server.",
            impact:
              "Sem baseline, permissões fracas e serviços inseguros permanecem habilitados.",
            detection: [
              "Executar scripts de compliance (LGPO, SecPol).",
              "Comparar estado atual com baseline desejado.",
              "Monitorar mudanças via GPO auditing."
            ],
            tools: ["LGPO", "PowerShell"],
            commands: [
              "LGPO.exe /m CIS_WindowsServer.inf",
              "powershell Get-SmbServerConfiguration"
            ],
            steps: [
              "Importar template CIS.",
              "Validar configurações críticas (SMB, RDP).",
              "Documentar exceções necessárias."
            ],
            mitigation: [
              "Automatizar aplicação via DSC/GPO.",
              "Planejar revisões periódicas.",
              "Implementar monitoramento de drift."
            ],
            evidence: [
              "Relatório de compliance pós-aplicação.",
              "Captura de comandos confirmando configuração.",
              "Lista de exceções aprovadas."
            ],
            references: ["CIS Windows Server Benchmark", "Microsoft Security Baselines"]
          }
        },
        {
          id: "win-2",
          title: "Habilitar auditoria avançada",
          description:
            "Configure políticas de auditoria para logar eventos críticos (logon, alteração de políticas, AD).",
          guide: {
            overview:
              "Auditoria detalhada garante trilha de auditoria para detectar atividades suspeitas.",
            impact:
              "Sem logs, incidentes passam despercebidos e dificultam resposta forense.",
            detection: [
              "Revisar políticas atuais com auditpol /get.",
              "Verificar se eventos estão chegando ao SIEM.",
              "Monitorar volume e ruído para ajustes."
            ],
            tools: ["auditpol", "Event Viewer", "SIEM"],
            commands: [
              "auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
              "Event Viewer -> Windows Logs -> Security"
            ],
            steps: [
              "Configurar categorias críticas (Account Logon, Policy Change).",
              "Redirecionar logs para canal seguro.",
              "Testar geração e coleta de eventos."
            ],
            mitigation: [
              "Criar alertas no SIEM para eventos de alto risco.",
              "Implementar retenção adequada.",
              "Revisar configurações após incidentes."
            ],
            evidence: [
              "Export de auditpol mostrando categorias habilitadas.",
              "Eventos coletados no SIEM.",
              "Procedimento de resposta anexado."
            ],
            references: ["Microsoft Advanced Audit Policy", "CIS Windows Logging"]
          }
        }
      ]
    },
    {
      id: "linux",
      name: "Linux",
      summary: "Hardening genérico para distribuições Linux.",
      items: [
        {
          id: "linux-1",
          title: "Executar Lynis",
          description:
            "Use Lynis para avaliação de hardening e implemente recomendações críticas.",
          guide: {
            overview:
              "Lynis gera avaliação abrangente do estado de hardening do servidor Linux.",
            impact:
              "Ignorar recomendações mantém configurações fracas e aumenta superfície de ataque.",
            detection: [
              "Executar lynis audit system periodicamente.",
              "Comparar hardening index com metas.",
              "Monitorar mudanças não autorizadas."
            ],
            tools: ["Lynis"],
            commands: [
              "lynis audit system",
              "grep 'Hardening index' /var/log/lynis-report.dat"
            ],
            steps: [
              "Rodar auditoria completa.",
              "Classificar recomendações por severidade.",
              "Implementar ações corretivas priorizadas."
            ],
            mitigation: [
              "Automatizar aplicação de recomendações críticas.",
              "Integrar resultados em CMDB.",
              "Definir plano de melhoria contínua."
            ],
            evidence: [
              "Relatório Lynis anexado.",
              "Tabela de ações realizadas.",
              "Hardening index comparativo (antes/depois)."
            ],
            references: ["Lynis Documentation", "CIS Linux Benchmark"]
          }
        },
        {
          id: "linux-2",
          title: "Configurar firewall e fail2ban",
          description:
            "Aplique regras de iptables/nftables mínimas e habilite fail2ban para serviços expostos.",
          guide: {
            overview:
              "Firewall e fail2ban reduzem superfície e bloqueiam brute force automaticamente.",
            impact:
              "Sem controles, hosts ficam suscetíveis a varreduras, brute force e movimento lateral.",
            detection: [
              "Revisar regras firewall ativas.",
              "Verificar jails configuradas.",
              "Monitorar logs de bloqueio e alertas."
            ],
            tools: ["ufw", "fail2ban", "iptables"],
            commands: [
              "ufw status verbose",
              "fail2ban-client status sshd"
            ],
            steps: [
              "Definir política default deny.",
              "Habilitar jails essenciais (sshd, nginx).",
              "Configurar alertas via e-mail/syslog."
            ],
            mitigation: [
              "Automatizar deploy de regras com Ansible.",
              "Integrar fail2ban com sistemas de reputação.",
              "Revisar regras após alterações de serviços."
            ],
            evidence: [
              "Saída do ufw status.",
              "Log de bloqueio fail2ban.",
              "Diagrama de fluxo de rede atualizado."
            ],
            references: ["OWASP Server Security", "CIS Linux Firewall"]
          }
        }
      ]
    }
  ]
};
