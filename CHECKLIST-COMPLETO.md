# ✅ Checklist Completo de Segurança

Este documento consolida as principais checagens utilizadas no dashboard. Use-o como referência rápida ou para revisar o conteúdo de forma offline. Cada item no painel possui guia com impacto, técnicas de detecção, ferramentas, comandos, mitigações e evidências recomendadas.

## OWASP Top 10 (2021)

1. **A01 – Controle de Acesso Quebrado**
   - Verifique RBAC/ABAC no backend.
   - Garanta revogação de tokens no logout.
   - Implemente política *deny-by-default*.
2. **A02 – Criptografia quebrada**
   - Use TLS 1.2+ com Perfect Forward Secrecy.
   - Armazene segredos com KMS/HSM.
   - Evite algoritmos inseguros (MD5, SHA1, RC4).
3. **A03 – Injeção**
   - Queries parametrizadas.
   - Validação de inputs e encoding de saída.
   - Limite privilégios do usuário do banco.
4. **A04 – Design inseguro**
   - Aplique *threat modeling* contínuo.
   - Adote segurança por padrão.
5. **A05 – Configuração incorreta**
   - Cabeçalhos HTTP de segurança.
   - Patches aplicados e hardening de componentes.
6. **A06 – Componentes vulneráveis**
   - Gestão de dependências, SBOM, SCA.
7. **A07 – Identificação e autenticação quebradas**
   - MFA obrigatório, proteções anti brute-force.
8. **A08 – Falhas de integridade de software e dados**
   - Assinaturas digitais, pipelines DevSecOps.
9. **A09 – Logging e monitoramento insuficientes**
   - Centralize logs, configure alertas.
10. **A10 – SSRF**
    - Filtre destinos, use redes segregadas.

## OWASP API Security Top 10 (2023)

- **API1** – Broken Object Level Authorization
- **API2** – Broken Authentication
- **API3** – Broken Object Property Level Authorization
- **API4** – Rate Limiting
- **API5** – Broken Function Level Authorization
- **API6** – Mass Assignment
- **API7** – Server Side Request Forgery
- **API8** – Security Misconfiguration
- **API9** – Improper Inventory Management
- **API10** – Unsafe Consumption of APIs

Cada tópico possui recomendações práticas de mitigação, validação automatizada e testes manuais.

## PTES – Penetration Testing Execution Standard

1. **Pre-engagement** – Escopo, contratos, requisitos legais.
2. **Inteligência** – Coleta passiva e ativa de informações.
3. **Modelagem de ameaças** – Classificação de ativos, riscos, impacto.
4. **Análise de vulnerabilidades** – Scans automatizados, validação manual.
5. **Exploração** – Execução de payloads e obtenção de acesso.
6. **Pós-exploração** – Movimento lateral, persistência, extração de dados.
7. **Relatórios** – Evidências, recomendações e priorização.

## SAST por Linguagem

- **JavaScript/Node.js** – ESLint, Semgrep, Snyk, npm audit.
- **Python** – Bandit, Semgrep, safety.
- **Go** – gosec, govulncheck, trivy.
- **Java** – SpotBugs, SonarQube, Dependency-Check.
- **C#/.NET** – SecurityCodeScan, Roslyn Analyzers, GitHub Advanced Security.
- **Swift/Kotlin** – MobSF, Semgrep, Xcode/Android Lint.

## DAST / Testes Dinâmicos

- XSS, SQLi, SSRF, IDOR, Broken Auth, CSRF, LFI/RFI, CORS.
- Utilize ferramentas como Burp, ZAP, dalfox, ffuf, nikto, nuclei.

## Hardening de Servidores

- **IIS** – TLS moderno, módulos mínimos, Request Filtering.
- **Apache** – ModSecurity, ServerTokens Prod, TLS otimizado.
- **Nginx** – Cabeçalhos, rate limiting, proxy seguro.
- **Windows** – GPO endurecidas, auditoria avançada, patching.
- **Linux** – Lynis, firewall, fail2ban, SSH endurecido.

> Este checklist é complementar aos detalhes presentes na interface do dashboard. Expanda a aplicação conforme as demandas do seu time AppSec.
