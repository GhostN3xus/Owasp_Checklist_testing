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
    }
  ]
};
