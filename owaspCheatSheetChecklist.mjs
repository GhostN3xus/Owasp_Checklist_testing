export const owaspCheatSheetChecklist = {
  id: "owasp-cheat-sheets",
  name: "OWASP Cheat Sheets",
  description: "Um checklist baseado nas principais OWASP Cheat Sheet Series para aprofundar em tópicos específicos de segurança.",
  sections: [
    {
      id: "cs-input-validation",
      title: "Input Validation Cheat Sheet",
      summary: "Validação de todas as entradas externas para garantir que são seguras antes de serem processadas.",
      items: [
        {
          id: "cs-iv-1",
          title: "Implementar Validação do Lado do Servidor",
          description: "Garanta que toda a validação de entrada seja realizada no lado do servidor. A validação do lado do cliente pode ser contornada.",
          guide: {
            overview: "A validação deve ocorrer no servidor, pois o cliente (navegador) está sob o controle do usuário e não é confiável.",
            impact: "A falta de validação no servidor pode permitir ataques de injeção, XSS e outras vulnerabilidades.",
            mitigation: ["Replique ou realize toda a validação crítica no backend.", "Nunca confie em dados vindos do cliente."],
            references: ["OWASP Cheat Sheet: Input Validation"]
          }
        },
        {
          id: "cs-iv-2",
          title: "Usar Listas de Permissões (Allow-Lists)",
          description: "Valide as entradas com base em um conjunto de caracteres, padrões ou valores permitidos, em vez de tentar bloquear caracteres maliciosos (deny-lists).",
          guide: {
            overview: "É mais seguro definir o que é permitido do que tentar adivinhar todas as possíveis entradas maliciosas.",
            impact: "Deny-lists são frequentemente incompletas e podem ser contornadas com novas técnicas de ataque ou encodings.",
            mitigation: ["Use expressões regulares para validar formatos estritos (ex: datas, IDs numéricos, CEP).", "Para campos com valores fixos (ex: menus dropdown), valide se o valor recebido está na lista de opções válidas."],
            references: ["OWASP Cheat Sheet: Input Validation"]
          }
        }
      ]
    },
    {
      id: "cs-xss-prevention",
      title: "Cross-Site Scripting (XSS) Prevention Cheat Sheet",
      summary: "Técnicas para prevenir a execução de scripts maliciosos no navegador do usuário.",
      items: [
        {
          id: "cs-xss-1",
          title: "Realizar Output Encoding",
          description: "Faça o 'escape' de todos os dados não confiáveis antes de inseri-los no HTML para garantir que sejam tratados como texto pelo navegador.",
          guide: {
            overview: "Use bibliotecas de encoding para o contexto apropriado (HTML Body, HTML Attribute, JavaScript, CSS, URL).",
            impact: "A falta de encoding de saída é a causa raiz da maioria das vulnerabilidades de XSS.",
            tools: ["OWASP Java Encoder", "Funções de escape de frameworks (ex: `htmlspecialchars` no PHP, `escape` no Jinja2)."],
            mitigation: ["Utilize um framework que faça o encoding de saída por padrão (ex: React, Angular).", "Codifique os dados no ponto mais próximo de onde eles são inseridos na página."],
            references: ["OWASP Cheat Sheet: XSS Prevention"]
          }
        },
        {
          id: "cs-xss-2",
          title: "Implementar Content Security Policy (CSP)",
          description: "Use o cabeçalho HTTP Content-Security-Policy para instruir o navegador a carregar apenas recursos de fontes permitidas.",
          guide: {
            overview: "CSP é uma camada de defesa em profundidade que pode mitigar o impacto de um XSS, mesmo que ele ocorra.",
            impact: "Uma CSP forte pode bloquear a execução de scripts inline e a comunicação com domínios maliciosos.",
            mitigation: ["Comece com uma política restritiva (`default-src 'self'`) e adicione as fontes necessárias.", "Evite o uso de `'unsafe-inline'` e `'unsafe-eval'`."],
            references: ["OWASP Cheat Sheet: Content Security Policy"]
          }
        }
      ]
    },
    {
      id: "cs-auth-cheatsheet",
      title: "Authentication Cheat Sheet",
      summary: "Práticas recomendadas para implementar processos de autenticação seguros.",
      items: [
        {
          id: "cs-auth-1",
          title: "Armazenamento Seguro de Senhas",
          description: "Use um algoritmo de hash adaptativo e com 'sal' para armazenar senhas.",
          guide: {
            overview: "Algoritmos como bcrypt, scrypt ou Argon2 são projetados para serem lentos, dificultando ataques de força bruta offline.",
            impact: "O uso de hashes fracos (como MD5 ou SHA-1) pode permitir que invasores recuperem as senhas originais em caso de vazamento de dados.",
            mitigation: ["Use uma biblioteca de criptografia testada e recomendada pela comunidade.", "Use um 'sal' único para cada usuário."],
            references: ["OWASP Cheat Sheet: Password Storage"]
          }
        },
        {
          id: "cs-auth-2",
          title: "Proteção Contra Enumeração de Usuários",
          description: "Garanta que as páginas de login, recuperação de senha e registro de conta respondam com mensagens genéricas, independentemente de o usuário existir ou não.",
          guide: {
            overview: "Respostas diferentes para usuários existentes e inexistentes permitem que um invasor descubra nomes de usuário válidos.",
            impact: "A enumeração de usuários é o primeiro passo para ataques de força bruta ou de 'credential stuffing'.",
            mitigation: ["Use a mesma mensagem de erro genérica em todos os casos (ex: 'Nome de usuário ou senha inválidos.').", "Retorne a mesma resposta HTTP (ex: 200 OK) em ambos os cenários para evitar a enumeração por tempo de resposta."],
            references: ["OWASP Cheat Sheet: Authentication"]
          }
        }
      ]
    }
  ]
};
