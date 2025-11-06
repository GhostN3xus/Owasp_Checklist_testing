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
          id: "sdp-dependency-management",
          title: "Gerenciamento de Dependências",
          description: "Mantenha as dependências do projeto atualizadas e use ferramentas para escanear por vulnerabilidades conhecidas (CVEs).",
          guide: {
            overview: "Use ferramentas como o Dependabot ou o Renovate para automatizar a atualização de dependências. Use scanners de SCA (Software Composition Analysis).",
            impact: "Dependências vulneráveis podem ser exploradas por invasores para comprometer a aplicação.",
            tools: ["npm audit", "pip-audit", "Snyk", "Trivy"],
            commands: ["npm audit", "trivy fs ."],
            mitigation: ["Mantenha um inventário de dependências (SBOM).", "Defina uma política para atualização de dependências com vulnerabilidades críticas."],
            references: ["OWASP Top 10: A06-Vulnerable and Outdated Components"]
          }
        },
        {
          id: "sdp-secrets-management",
          title: "Gerenciamento de Segredos",
          description: "Não armazene segredos (senhas, chaves de API, tokens) no código-fonte. Use um cofre de segredos.",
          guide: {
            overview: "Utilize serviços como HashiCorp Vault, AWS Secrets Manager ou Azure Key Vault para gerenciar segredos. Injete segredos no ambiente de execução.",
            impact: "Segredos no código-fonte podem vazar através de repositórios públicos, comprometendo sistemas inteiros.",
            tools: ["Git-secrets", "TruffleHog", "Vault"],
            commands: ["trufflehog filesystem ."],
            mitigation: ["Implemente varredura de segredos no pipeline de CI/CD para bloquear commits com segredos.", "Rotacione segredos regularmente."],
            references: ["OWASP Cheat Sheet: Secrets Management"]
          }
        }
      ]
    }
  ]
};
