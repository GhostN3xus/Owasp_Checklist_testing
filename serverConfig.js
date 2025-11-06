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
          verification: [
            "appcmd list module",
            "appcmd set config /section:modules /-[name='WebDAVModule']"
          ],
          notes:
            "Remova WebDAV, Sample Content e serviços legados se não forem necessários."
        },
        {
          id: "iis-2",
          title: "Forçar TLS 1.2+",
          description:
            "Desabilite SSLv2/v3 e TLS 1.0/1.1 via registro e confirme com ferramentas de teste.",
          verification: [
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0 /v Enabled /t REG_DWORD /d 0 /f",
            "testssl.sh --fast https://hostname"
          ],
          notes: "Automatize via GPO ou DSC."
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
          verification: [
            "a2enmod security2",
            "git clone https://github.com/coreruleset/coreruleset /etc/modsecurity.d/owasp-crs"
          ],
          notes:
            "Ajuste exceções para evitar falsos positivos e monitore logs em tempo real."
        },
        {
          id: "apache-2",
          title: "Ocultar versão do servidor",
          description:
            "Use diretivas ServerTokens Prod e ServerSignature Off para evitar fingerprinting.",
          verification: [
            "grep -i ServerTokens /etc/apache2/conf-enabled/security.conf",
            "curl -I https://hostname"
          ],
          notes: "Combine com banners customizados no load balancer."
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
          verification: [
            "add_header Content-Security-Policy \"default-src 'self'\" always;",
            "curl -I https://hostname"
          ],
          notes:
            "Use sempre diretiva always para respostas 4xx/5xx."
        },
        {
          id: "nginx-2",
          title: "Configurar rate limiting nativo",
          description:
            "Utilize limit_req_zone e limit_conn_zone para mitigar abusos antes do backend.",
          verification: [
            "limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;",
            "tail -f /var/log/nginx/error.log"
          ],
          notes: "Combine com logs estruturados para observabilidade."
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
          verification: [
            "LGPO.exe /m CIS_WindowsServer.inf",
            "powershell Get-SmbServerConfiguration"
          ],
          notes:
            "Automatize com Ansible ou DSC. Documente exceções."
        },
        {
          id: "win-2",
          title: "Habilitar auditoria avançada",
          description:
            "Configure políticas de auditoria para logar eventos críticos (logon, alteração de políticas, AD).",
          verification: [
            "auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
            "Event Viewer -> Windows Logs -> Security"
          ],
          notes: "Envie logs para SIEM centralizado."
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
          verification: ["lynis audit system", "grep 'Hardening index' /var/log/lynis-report.dat"],
          notes: "Priorize recomendações High e Warning."
        },
        {
          id: "linux-2",
          title: "Configurar firewall e fail2ban",
          description:
            "Aplique regras de iptables/nftables mínimas e habilite fail2ban para serviços expostos.",
          verification: [
            "ufw status verbose",
            "fail2ban-client status sshd"
          ],
          notes: "Integre alertas com monitoramento 24/7."
        }
      ]
    }
  ]
};
