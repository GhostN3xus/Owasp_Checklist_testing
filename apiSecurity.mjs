/**
 * OWASP API Security Top 10 2023
 * Checklist completo para testes de segurança em APIs REST, GraphQL e gRPC
 */

export const apiSecurityChecklist = {
  id: "owasp-api",
  name: "OWASP API Security",
  description: "OWASP API Security Top 10 (2023) - Testes especializados para APIs REST, GraphQL, gRPC e WebSockets com exemplos práticos e ferramentas.",
  sections: [
    {
      id: "api01",
      title: "API1:2023 – Broken Object Level Authorization (BOLA/IDOR)",
      summary: "Manipulação de IDs de objetos para acessar recursos de outros usuários sem autorização.",
      items: [
        {
          id: "api01-1",
          title: "Testar acesso horizontal (IDOR) em endpoints de recursos",
          description: "Verificar se usuários conseguem acessar/modificar objetos de outros usuários mudando IDs nos parâmetros.",
          guide: {
            overview: "BOLA/IDOR é a vulnerabilidade #1 em APIs. Ocorre quando a API não valida se o usuário autenticado tem permissão para acessar o recurso específico solicitado.",
            impact: "Vazamento de dados sensíveis, modificação de recursos de terceiros, violação de privacidade (LGPD/GDPR), comprometimento total da confidencialidade.",
            detection: [
              "Capture requisições a recursos (GET /api/users/123, PUT /api/orders/456)",
              "Modifique IDs para valores de outros usuários (incremental, GUID)",
              "Compare respostas: 200 OK = vulnerável, 403 Forbidden = protegido",
              "Teste com diferentes perfis (admin, user, guest)"
            ],
            tools: ["Burp Suite (Autorize extension)", "Postman", "OWASP ZAP", "Arjun", "ffuf"],
            commands: [
              "# Teste manual com curl",
              "curl -H 'Authorization: Bearer TOKEN_USER1' https://api.example.com/api/users/999",
              "",
              "# Fuzzing de IDs com ffuf",
              "ffuf -u https://api.example.com/api/orders/FUZZ -w ids.txt -H 'Authorization: Bearer TOKEN' -mc 200",
              "",
              "# Burp Suite Autorize extension",
              "1. Instalar extensão Autorize",
              "2. Configurar tokens de diferentes usuários",
              "3. Ativar intercept e observar respostas automáticas"
            ],
            steps: [
              "1. Mapear todos endpoints que recebem IDs (path params, query strings, body)",
              "2. Criar 2+ contas de teste com dados isolados",
              "3. Autenticar como User A e capturar token",
              "4. Fazer requisição para recurso de User B usando token de User A",
              "5. Verificar se API retorna dados de User B (vulnerável) ou 403 (seguro)",
              "6. Testar operações CRUD: GET, PUT, PATCH, DELETE",
              "7. Testar com IDs inválidos, negativos, UUID de outros tenants"
            ],
            mitigation: [
              "Implementar verificação de ownership em TODOS os endpoints",
              "Usar mapeamento indireto: userId do token JWT vs ID do recurso no DB",
              "Aplicar middleware de autorização: if (resource.ownerId !== req.user.id) return 403",
              "Evitar expor IDs sequenciais (preferir UUIDs)",
              "Implementar testes automatizados de autorização (policy-as-code)"
            ],
            evidence: [
              "Screenshot da requisição com token User A + ID User B retornando 200 OK",
              "Diff de responses mostrando dados de User B",
              "Curl command reproduzindo o exploit",
              "Código do endpoint mostrando ausência de verificação de ownership"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
              "https://portswigger.net/web-security/access-control/idor",
              "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
            ]
          }
        },
        {
          id: "api01-2",
          title: "Validar autorização em relações nested (sub-recursos)",
          description: "Testar acesso a recursos aninhados como /users/123/documents/456 verificando ownership em ambos os níveis.",
          guide: {
            overview: "Muitas APIs falham ao validar ownership em recursos nested. Ex: validam /users/123 mas não /users/123/documents/456.",
            impact: "Bypass de autorização em recursos secundários, acesso a documentos/comentários/anexos de outros usuários.",
            detection: [
              "Identificar endpoints com estrutura hierárquica (/parent/{id}/child/{id})",
              "Testar com ID de parent válido do usuário + ID de child de outro usuário",
              "Testar com ID de parent de outro usuário + ID de child qualquer"
            ],
            tools: ["Burp Suite", "Postman Collections", "Custom scripts"],
            commands: [
              "# Teste de parent válido + child de outro user",
              "curl -H 'Authorization: Bearer MY_TOKEN' https://api.example.com/api/users/MY_ID/documents/OTHER_USER_DOC_ID",
              "",
              "# Script Python para fuzzing de nested resources",
              "import requests",
              "for parent_id in my_valid_ids:",
              "    for child_id in range(1, 1000):",
              "        r = requests.get(f'/api/users/{parent_id}/docs/{child_id}', headers={'Authorization': token})",
              "        if r.status_code == 200: print(f'[!] Leaked: {child_id}')"
            ],
            steps: [
              "1. Mapear recursos hierárquicos (parent → child → grandchild)",
              "2. Criar dados de teste: User A com docs [1,2,3], User B com docs [4,5,6]",
              "3. Autenticar como User A",
              "4. Requisitar GET /users/USER_A_ID/documents/4 (doc de User B)",
              "5. Verificar se retorna 200 (vulnerável) ou 403/404 (seguro)",
              "6. Testar operações de escrita: POST, PUT, DELETE em sub-recursos"
            ],
            mitigation: [
              "Validar ownership em TODOS os níveis da hierarquia",
              "Query: SELECT * FROM documents WHERE id=? AND userId=? (validar ambos)",
              "Usar framework de autorização: can(user, 'read', document)",
              "Implementar testes de regressão para nested resources"
            ],
            evidence: [
              "Requisição mostrando acesso a /users/A/docs/B (cross-user)",
              "Response body com dados do documento de outro usuário",
              "Database query mostrando ausência de WHERE userId=?"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
              "https://github.com/OWASP/API-Security/blob/master/editions/2023/en/0xa1-broken-object-level-authorization.md"
            ]
          }
        }
      ]
    },
    {
      id: "api02",
      title: "API2:2023 – Broken Authentication",
      summary: "Falhas em mecanismos de autenticação que permitem assumir identidade de outros usuários.",
      items: [
        {
          id: "api02-1",
          title: "Testar ausência de rate limiting em endpoints de autenticação",
          description: "Verificar se é possível realizar brute-force em /login, /forgot-password, /otp sem bloqueio.",
          guide: {
            overview: "APIs frequentemente não implementam rate limiting adequado, permitindo ataques de força bruta em credenciais.",
            impact: "Compromise de contas por brute-force, credential stuffing, enumeração de usuários, bypass de MFA.",
            detection: [
              "Enviar 100+ requisições ao endpoint /login em curto período",
              "Observar se há bloqueio temporário, CAPTCHA ou HTTP 429",
              "Testar com credenciais válidas após tentativas falhas"
            ],
            tools: ["Hydra", "Burp Intruder", "ffuf", "Custom scripts"],
            commands: [
              "# Brute-force com Hydra",
              "hydra -L users.txt -P passwords.txt api.example.com https-post-form '/api/login:username=^USER^&password=^PASS^:F=Invalid credentials'",
              "",
              "# Rate limiting test com curl loop",
              "for i in {1..200}; do curl -X POST https://api.example.com/api/login -d '{\"email\":\"test@example.com\",\"password\":\"wrong\"}'; done",
              "",
              "# Burp Intruder",
              "1. Capturar requisição POST /api/login",
              "2. Send to Intruder → Positions → Mark password field",
              "3. Payloads → Simple list com 1000 senhas comuns",
              "4. Start attack → Observar se há bloqueio após N tentativas"
            ],
            steps: [
              "1. Identificar endpoints de autenticação: /login, /token, /auth, /oauth",
              "2. Fazer 10 tentativas de login com senha errada",
              "3. Verificar se há bloqueio (429, CAPTCHA, delay)",
              "4. Testar com IPs diferentes (bypass por IP)",
              "5. Testar /forgot-password com enumeração de emails",
              "6. Testar OTP/2FA com brute-force de códigos 0000-9999"
            ],
            mitigation: [
              "Implementar rate limiting: 5 tentativas/minuto por IP + user",
              "Usar CAPTCHA após 3 tentativas falhas",
              "Implementar account lockout temporário (15min) após 5 falhas",
              "Adicionar delay exponencial entre tentativas",
              "Monitorar e alertar sobre padrões de brute-force"
            ],
            evidence: [
              "Log de 100+ requisições consecutivas sem bloqueio",
              "Screenshot do Burp Intruder com 1000 requests sem 429",
              "Código do endpoint mostrando ausência de rate limiting",
              "Conta comprometida via brute-force com logs de timestamp"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
              "https://www.rfc-editor.org/rfc/rfc6749#section-10.13"
            ]
          }
        },
        {
          id: "api02-2",
          title: "Validar implementação segura de JWT (algoritmo, expiração, secret)",
          description: "Verificar se JWTs usam algoritmo seguro (não 'none'), têm expiração curta e secret forte.",
          guide: {
            overview: "JWTs mal implementados permitem: algoritmo 'none', secret fraco, sem expiração, claims manipuláveis.",
            impact: "Criação de tokens falsificados, escalação de privilégios (admin: true), sessões perpétuas.",
            detection: [
              "Decodificar JWT (jwt.io) e verificar: alg, exp, claims",
              "Testar algoritmo 'none': {\"alg\":\"none\"}",
              "Tentar brute-force de secret com hashcat/john",
              "Modificar claims (role: admin) e re-assinar com secret fraco"
            ],
            tools: ["jwt_tool", "jwt.io", "Burp JWT Editor", "hashcat"],
            commands: [
              "# Decodificar JWT",
              "echo 'eyJhbGc...' | base64 -d",
              "",
              "# Testar algoritmo 'none' com jwt_tool",
              "python3 jwt_tool.py TOKEN -X a",
              "",
              "# Brute-force de secret",
              "hashcat -a 0 -m 16500 jwt.txt rockyou.txt",
              "",
              "# Modificar claim com jwt_tool",
              "python3 jwt_tool.py TOKEN -T",
              "# Alterar {\"role\":\"user\"} para {\"role\":\"admin\"}",
              "# Re-assinar com secret crackeado"
            ],
            steps: [
              "1. Capturar token JWT do header Authorization: Bearer",
              "2. Decodificar no jwt.io: verificar alg (deve ser RS256/ES256, não HS256 com secret fraco)",
              "3. Verificar claim 'exp': deve ter expiração < 1h",
              "4. Testar algoritmo 'none': modificar header {\"alg\":\"none\"}, remover signature",
              "5. Testar brute-force de secret se alg=HS256",
              "6. Modificar claims sensíveis (userId, role) e validar se API aceita",
              "7. Testar reutilização de token após logout"
            ],
            mitigation: [
              "Usar algoritmos assimétricos: RS256 (chave pública/privada)",
              "Se usar HS256: secret com 256+ bits de entropia (não 'secret123')",
              "Configurar expiração curta: 15min (access) + refresh token",
              "Validar claims críticos no backend: iss, aud, exp, nbf",
              "Implementar token blacklist/revocation para logout",
              "Nunca colocar dados sensíveis em JWT (são apenas base64)"
            ],
            evidence: [
              "JWT decodificado mostrando {\"alg\":\"none\"}",
              "Screenshot do jwt_tool com signature bypass",
              "Secret crackeado: 'secretkey123'",
              "Request com JWT modificado (admin:true) retornando 200 OK",
              "Código mostrando validação inadequada de signature"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
              "https://jwt.io/introduction",
              "https://tools.ietf.org/html/rfc7519",
              "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
            ]
          }
        }
      ]
    },
    {
      id: "api03",
      title: "API3:2023 – Broken Object Property Level Authorization",
      summary: "Exposição ou modificação de propriedades sensíveis de objetos (mass assignment, data leakage).",
      items: [
        {
          id: "api03-1",
          title: "Testar Mass Assignment (Autobinding de campos sensíveis)",
          description: "Verificar se é possível modificar campos restritos (isAdmin, role, balance) enviando-os no body da requisição.",
          guide: {
            overview: "APIs que fazem bind automático de JSON para objetos podem permitir modificação de campos não esperados.",
            impact: "Escalação de privilégios (isAdmin=true), modificação de saldo/créditos, bypass de workflow.",
            detection: [
              "Capturar requisição PUT/PATCH de atualização de perfil",
              "Adicionar campos sensíveis no JSON: {\"isAdmin\":true, \"role\":\"admin\", \"balance\":99999}",
              "Verificar se campos foram atualizados no banco (re-fetch do objeto)"
            ],
            tools: ["Burp Suite", "Postman", "curl"],
            commands: [
              "# Request normal de atualização",
              "curl -X PUT https://api.example.com/api/users/123 \\",
              "  -H 'Authorization: Bearer TOKEN' \\",
              "  -d '{\"name\":\"John\",\"email\":\"john@example.com\"}'",
              "",
              "# Mass assignment attack",
              "curl -X PUT https://api.example.com/api/users/123 \\",
              "  -H 'Authorization: Bearer TOKEN' \\",
              "  -d '{\"name\":\"John\",\"isAdmin\":true,\"role\":\"admin\",\"balance\":999999}'"
            ],
            steps: [
              "1. Identificar endpoint de atualização: PUT/PATCH /users/{id}",
              "2. Fazer requisição legítima e observar campos permitidos",
              "3. Listar campos sensíveis da model: isAdmin, role, verified, balance, credits",
              "4. Adicionar esses campos no JSON de atualização",
              "5. Fazer nova GET do objeto e verificar se campos foram alterados",
              "6. Testar em endpoints de criação (POST) também"
            ],
            mitigation: [
              "Usar whitelist de campos permitidos (DTO/Schema validation)",
              "Frameworks: Express-validator, Joi, Yup, Zod",
              "Nunca fazer: const user = await User.update(req.body)",
              "Fazer: const user = await User.update({ name: req.body.name, email: req.body.email })",
              "Implementar field-level permissions (role pode editar X, mas não Y)"
            ],
            evidence: [
              "Request com {\"isAdmin\":true} no body",
              "Response mostrando campo atualizado",
              "Screenshot do banco de dados com isAdmin=1",
              "Código do endpoint sem validação de campos"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
              "https://cwe.mitre.org/data/definitions/915.html"
            ]
          }
        },
        {
          id: "api03-2",
          title: "Identificar exposição excessiva de dados (data leakage)",
          description: "Verificar se API retorna mais dados que o necessário (senhas, tokens, campos internos).",
          guide: {
            overview: "APIs frequentemente retornam objetos completos do banco sem filtrar campos sensíveis.",
            impact: "Vazamento de PII, senhas hashed, tokens internos, dados de debug, estrutura do banco.",
            detection: [
              "Fazer GET em endpoints de listagem/detalhes",
              "Inspecionar response JSON procurando: password, passwordHash, token, secret, internal_id",
              "Comparar com documentação da API (Swagger): campos não documentados são red flags"
            ],
            tools: ["Burp Suite", "jq (parse JSON)", "Postman"],
            commands: [
              "# Listar usuários e buscar campos sensíveis",
              "curl https://api.example.com/api/users | jq '.[] | keys'",
              "",
              "# Procurar por padrões sensíveis",
              "curl https://api.example.com/api/users | grep -i 'password\\|token\\|secret\\|ssn\\|credit_card'",
              "",
              "# Diff entre documentação e resposta real",
              "diff <(curl /api/users | jq 'keys') swagger-documented-fields.txt"
            ],
            steps: [
              "1. Listar todos endpoints GET (listagem e detalhes)",
              "2. Para cada endpoint, capturar response completa",
              "3. Buscar campos: password*, *token*, *secret*, *internal*, ssn, cpf, credit_card",
              "4. Verificar se há dados de relacionamentos desnecessários (user.orders.payment.creditCard)",
              "5. Comparar com necessidade do frontend: API deve retornar apenas o necessário"
            ],
            mitigation: [
              "Usar DTOs/Serializers para controlar campos retornados",
              "Nunca fazer: res.json(user) (retorna tudo do DB)",
              "Fazer: res.json({ id: user.id, name: user.name, email: user.email })",
              "Frameworks: class-transformer, GraphQL (client escolhe campos), JSON:API",
              "Remover campos sensíveis: @Exclude() password; na model"
            ],
            evidence: [
              "Response JSON com campo 'passwordHash': '$2b$10...'",
              "Campos internos expostos: 'internal_user_id', 'db_migration_version'",
              "Screenshot do Burp mostrando 'creditCardNumber' em resposta",
              "Comparação: documentação lista 5 campos, API retorna 25"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
              "https://cwe.mitre.org/data/definitions/213.html"
            ]
          }
        }
      ]
    },
    {
      id: "api04",
      title: "API4:2023 – Unrestricted Resource Consumption",
      summary: "Falta de limites de taxa, paginação, tamanho de payload que levam a DoS ou abuso de recursos.",
      items: [
        {
          id: "api04-1",
          title: "Testar ausência de paginação e limites em listagens",
          description: "Verificar se endpoints GET /items retornam TODOS os registros sem limite, causando timeout/overhead.",
          guide: {
            overview: "APIs sem paginação podem retornar milhões de registros de uma vez, causando DoS não intencional.",
            impact: "Timeout de requests, consumo excessivo de banda, crash de servidor/banco, abuso de dados.",
            detection: [
              "Fazer GET em endpoints de listagem sem parâmetros ?limit=",
              "Observar se retorna array com 1000s de items",
              "Medir tempo de resposta e tamanho (MB)"
            ],
            tools: ["curl", "Postman", "Browser DevTools"],
            commands: [
              "# Request sem paginação",
              "curl -w 'Time: %{time_total}s Size: %{size_download} bytes\\n' https://api.example.com/api/products",
              "",
              "# Testar com limite alto",
              "curl 'https://api.example.com/api/products?limit=999999'",
              "",
              "# Medir resposta",
              "time curl https://api.example.com/api/users > output.json",
              "ls -lh output.json  # Verificar tamanho em MB"
            ],
            steps: [
              "1. Listar endpoints de coleções: /users, /products, /orders",
              "2. Fazer request sem parâmetros de paginação",
              "3. Contar items retornados: curl /api/users | jq 'length'",
              "4. Se > 100 items: ausência de paginação default",
              "5. Testar ?limit=999999 para verificar se aceita valores altos",
              "6. Medir impacto: tempo de resposta, uso de CPU no servidor"
            ],
            mitigation: [
              "Implementar paginação obrigatória: ?page=1&limit=20",
              "Limitar max items por página: limit <= 100",
              "Usar cursor-based pagination para performance (não offset)",
              "Retornar metadata: { data: [...], total: 1000, page: 1, hasMore: true }",
              "Implementar rate limiting global: 100 req/min"
            ],
            evidence: [
              "Response com 50,000 items em array único",
              "Screenshot do DevTools Network: 45MB de download, 15s de tempo",
              "Log do servidor com query SELECT * FROM users (sem LIMIT)",
              "Gráfico de CPU spike durante request"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
              "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#pagination"
            ]
          }
        },
        {
          id: "api04-2",
          title: "Validar limites de tamanho de payload (file upload, JSON)",
          description: "Testar envio de payloads massivos (100MB JSON, arquivos gigantes) para causar DoS.",
          guide: {
            overview: "APIs sem limite de tamanho de body podem ser exploradas enviando payloads enormes.",
            impact: "Crash de servidor, consumo de disco, memory exhaustion, DoS.",
            detection: [
              "Enviar POST com JSON de 100MB",
              "Upload de arquivo de 1GB",
              "Enviar array com 1 milhão de items"
            ],
            tools: ["curl", "Python requests", "Burp Repeater"],
            commands: [
              "# Gerar JSON massivo",
              "python3 -c 'import json; print(json.dumps({\"data\": [\"x\"*1000000]*1000}))' > huge.json",
              "",
              "# Enviar payload massivo",
              "curl -X POST https://api.example.com/api/data \\",
              "  -H 'Content-Type: application/json' \\",
              "  -d @huge.json",
              "",
              "# Upload de arquivo gigante",
              "dd if=/dev/zero of=huge.bin bs=1M count=1024  # 1GB",
              "curl -X POST https://api.example.com/api/upload \\",
              "  -F 'file=@huge.bin'"
            ],
            steps: [
              "1. Identificar endpoints POST/PUT com body JSON ou file upload",
              "2. Gerar payload de 100MB (JSON nested, array massivo)",
              "3. Enviar request e observar comportamento: timeout? error? aceito?",
              "4. Testar file upload com arquivo de 1GB",
              "5. Monitorar servidor: uso de memória, CPU, disco",
              "6. Verificar se há validação de Content-Length"
            ],
            mitigation: [
              "Configurar limite de body size no servidor: Express - express.json({ limit: '1mb' })",
              "Nginx: client_max_body_size 10m;",
              "Validar Content-Length antes de processar body",
              "Para uploads: limite por tipo de arquivo, scan de malware",
              "Rejeitar requests > limite com 413 Payload Too Large",
              "Usar streaming para arquivos grandes (não carregar em memória)"
            ],
            evidence: [
              "Request com Content-Length: 104857600 (100MB)",
              "Log de erro do servidor: MemoryError/OutOfMemory",
              "Screenshot do htop mostrando 99% memory usage",
              "Código sem validação de file size"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "api05",
      title: "API5:2023 – Broken Function Level Authorization (BFLA)",
      summary: "Acesso a funções administrativas por usuários comuns (endpoints /admin sem validação).",
      items: [
        {
          id: "api05-1",
          title: "Enumerar e testar endpoints administrativos sem autorização",
          description: "Identificar rotas /admin, /internal, /debug e testar acesso com token de usuário comum.",
          guide: {
            overview: "APIs expõem endpoints administrativos que não validam role do usuário, permitindo acesso indevido.",
            impact: "Acesso a funções críticas (delete all, change config), comprometimento total do sistema.",
            detection: [
              "Fazer wordlist de rotas: /api/admin, /api/internal, /api/v1/debug",
              "Testar com token de user comum: curl -H 'Authorization: Bearer USER_TOKEN' /api/admin/users",
              "Observar: 200 OK = vulnerável, 403 = protegido"
            ],
            tools: ["ffuf", "dirsearch", "Burp Suite", "Arjun"],
            commands: [
              "# Fuzzing de rotas administrativas",
              "ffuf -u https://api.example.com/api/FUZZ -w admin-routes.txt -H 'Authorization: Bearer USER_TOKEN' -mc 200,401,403",
              "",
              "# Wordlist de rotas comuns",
              "cat admin-routes.txt",
              "admin",
              "admin/users",
              "admin/delete",
              "internal/config",
              "debug/logs",
              "v1/admin",
              "",
              "# Teste manual",
              "curl -H 'Authorization: Bearer USER_TOKEN' https://api.example.com/api/admin/users"
            ],
            steps: [
              "1. Criar lista de possíveis rotas admin: /admin, /internal, /debug, /staff, /manage",
              "2. Autenticar como usuário comum e obter token",
              "3. Fazer fuzzing de rotas com token comum",
              "4. Para cada rota encontrada (200 OK), testar operações críticas",
              "5. Verificar se há validação de role no código backend",
              "6. Testar métodos HTTP alternativos: GET, POST, PUT, DELETE, PATCH"
            ],
            mitigation: [
              "Implementar role-based access control (RBAC) em TODOS os endpoints",
              "Middleware de autorização: if (user.role !== 'admin') return 403",
              "Usar frameworks de autorização: Casbin, CASL, Permit.io",
              "Segmentar rotas por role: /api/admin/* exige role=admin",
              "Implementar testes automatizados: admin pode acessar /admin/*, user não pode"
            ],
            evidence: [
              "Request com USER_TOKEN para /api/admin/users retornando 200 OK",
              "Response com lista de todos usuários do sistema",
              "Código do endpoint sem verificação de role",
              "Log mostrando user comum acessando função administrativa"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "api06",
      title: "API6:2023 – Unrestricted Access to Sensitive Business Flows",
      summary: "Automação de fluxos críticos sem proteção (compras em massa, vote manipulation, scalping).",
      items: [
        {
          id: "api06-1",
          title: "Testar automação de fluxos críticos (compra, voto, reserva)",
          description: "Verificar se é possível automatizar ações críticas sem CAPTCHA ou rate limiting.",
          guide: {
            overview: "APIs permitem automação de fluxos como compra de ingressos, votos, reservas sem mecanismos anti-bot.",
            impact: "Scalping de ingressos, manipulação de votações, esgotamento de estoque, abuso de promoções.",
            detection: [
              "Identificar fluxo crítico: POST /api/purchase, POST /api/vote, POST /api/reserve",
              "Criar script que faz 100 requisições consecutivas",
              "Verificar se há bloqueio, CAPTCHA ou delay"
            ],
            tools: ["Python requests", "Selenium", "Burp Intruder"],
            commands: [
              "# Script Python para automação",
              "import requests",
              "for i in range(100):",
              "    r = requests.post('https://api.example.com/api/purchase',",
              "                      json={'productId': 123, 'quantity': 10},",
              "                      headers={'Authorization': f'Bearer {token}'})",
              "    print(f'[{i}] Status: {r.status_code}')",
              "",
              "# Selenium para bypass de proteções frontend",
              "from selenium import webdriver",
              "driver = webdriver.Chrome()",
              "for i in range(50):",
              "    driver.get('https://example.com/vote?candidate=X')",
              "    driver.find_element_by_id('vote-button').click()"
            ],
            steps: [
              "1. Mapear fluxos críticos de negócio: compra, voto, reserva, cadastro, resgate de cupom",
              "2. Capturar requisição POST do fluxo",
              "3. Replicar 50x em loop e verificar se todas são aceitas",
              "4. Testar com múltiplos IPs/sessões",
              "5. Verificar se há CAPTCHA, proof-of-work, rate limiting",
              "6. Medir impacto: conseguiu esgotar estoque? manipular votação?"
            ],
            mitigation: [
              "Implementar CAPTCHA em fluxos críticos (reCAPTCHA v3)",
              "Rate limiting agressivo: 1 compra/minuto por user + IP",
              "Device fingerprinting para detectar automação",
              "Proof-of-work client-side (gerar hash antes de submit)",
              "Análise comportamental: tempo entre ações, padrões de mouse",
              "Queue system para releases limitados (ingressos, produtos limitados)"
            ],
            evidence: [
              "Script Python com 100 compras bem-sucedidas",
              "Screenshot do sistema com 100 pedidos criados em 30 segundos",
              "Logs do servidor sem rate limiting",
              "Análise de estoque: 1000 items → 0 em 2 minutos por automação"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "api07",
      title: "API7:2023 – Server Side Request Forgery (SSRF)",
      summary: "Manipulação de URLs/IPs em parâmetros da API para fazer servidor atacar recursos internos.",
      items: [
        {
          id: "api07-1",
          title: "Testar SSRF em parâmetros de URL/webhook/callback",
          description: "Verificar se API faz requisições a URLs fornecidas pelo usuário sem validação.",
          guide: {
            overview: "APIs que fazem HTTP requests baseadas em input do usuário podem ser exploradas para SSRF.",
            impact: "Acesso a recursos internos (AWS metadata, Redis, databases), port scanning, bypass de firewall.",
            detection: [
              "Identificar parâmetros: url, webhook, callback, imageUrl, feedUrl",
              "Testar com URLs internas: http://localhost, http://169.254.169.254 (AWS metadata)",
              "Observar se servidor faz request e retorna resposta"
            ],
            tools: ["Burp Collaborator", "ngrok", "webhook.site"],
            commands: [
              "# Teste com localhost",
              "curl -X POST https://api.example.com/api/import \\",
              "  -d '{\"url\":\"http://localhost:3306\"}'  # Tentar acessar MySQL interno",
              "",
              "# AWS metadata SSRF",
              "curl -X POST https://api.example.com/api/fetch-image \\",
              "  -d '{\"imageUrl\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'",
              "",
              "# Burp Collaborator (detectar outbound connections)",
              "curl -X POST https://api.example.com/api/webhook \\",
              "  -d '{\"callback\":\"http://burpcollaborator.net/ssrf-test\"}'",
              "",
              "# Port scanning",
              "for port in {1..1000}; do",
              "  curl -X POST https://api.example.com/api/ping -d \"{\\\"host\\\":\\\"127.0.0.1:$port\\\"}\"",
              "done"
            ],
            steps: [
              "1. Identificar endpoints que aceitam URLs: /fetch, /import, /proxy, /webhook",
              "2. Testar com URL interna: http://127.0.0.1, http://localhost, http://0.0.0.0",
              "3. Testar AWS metadata: http://169.254.169.254/latest/meta-data/",
              "4. Testar file:// protocol: file:///etc/passwd",
              "5. Usar Burp Collaborator para confirmar outbound request",
              "6. Testar bypass de filtros: http://127.1, http://[::1], http://2130706433 (decimal IP)"
            ],
            mitigation: [
              "Implementar whitelist de domínios permitidos",
              "Bloquear IPs privados: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x",
              "Validar schema: apenas https:// permitido",
              "Usar biblioteca de validação: OWASP Java HTML Sanitizer",
              "Fazer request em rede isolada (sem acesso a recursos internos)",
              "Desabilitar redirects automáticos em HTTP client"
            ],
            evidence: [
              "Request com {\"url\":\"http://169.254.169.254/...\"} retornando AWS credentials",
              "Response com conteúdo de http://localhost:6379 (Redis)",
              "Burp Collaborator mostrando DNS lookup + HTTP request do servidor",
              "Port scan results: portas 22, 3306, 6379 abertas internamente"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
              "https://portswigger.net/web-security/ssrf"
            ]
          }
        }
      ]
    },
    {
      id: "api08",
      title: "API8:2023 – Security Misconfiguration",
      summary: "Configurações inseguras: CORS aberto, debug mode, TLS fraco, headers faltando.",
      items: [
        {
          id: "api08-1",
          title: "Validar configuração de CORS (Cross-Origin Resource Sharing)",
          description: "Verificar se API permite qualquer origem (Access-Control-Allow-Origin: *).",
          guide: {
            overview: "CORS mal configurado permite que sites maliciosos façam requests à API em nome do usuário.",
            impact: "Roubo de tokens/cookies, exfiltração de dados, CSRF em APIs.",
            detection: [
              "Fazer request com Origin: https://malicious.com",
              "Verificar response header: Access-Control-Allow-Origin",
              "Se retornar * ou echo do Origin enviado: vulnerável"
            ],
            tools: ["curl", "Burp Suite", "Browser DevTools"],
            commands: [
              "# Testar CORS",
              "curl -H 'Origin: https://evil.com' \\",
              "     -H 'Access-Control-Request-Method: POST' \\",
              "     -H 'Access-Control-Request-Headers: authorization' \\",
              "     -X OPTIONS \\",
              "     https://api.example.com/api/users",
              "",
              "# Verificar response headers",
              "# Vulnerável se retornar:",
              "Access-Control-Allow-Origin: *",
              "Access-Control-Allow-Origin: https://evil.com",
              "Access-Control-Allow-Credentials: true  (combinado com * = vulnerável)"
            ],
            steps: [
              "1. Fazer preflight OPTIONS request com Origin: https://attacker.com",
              "2. Verificar Access-Control-Allow-Origin no response",
              "3. Testar wildcards: *, null, regex bypass (evil-api.example.com)",
              "4. Verificar se Allow-Credentials: true (permite cookies)",
              "5. Testar exploit real: criar página HTML que faz fetch() à API"
            ],
            mitigation: [
              "Implementar whitelist de origens permitidas",
              "Nunca usar Access-Control-Allow-Origin: * com credentials",
              "Validar Origin header no backend antes de setar CORS",
              "Usar SameSite=Strict em cookies",
              "Para APIs públicas sem autenticação: * é aceitável"
            ],
            evidence: [
              "Request com Origin: https://evil.com",
              "Response com Access-Control-Allow-Origin: *",
              "PoC HTML fazendo fetch() de dados autenticados",
              "Screenshot do console mostrando dados exfiltrados"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
              "https://portswigger.net/web-security/cors",
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
            ]
          }
        },
        {
          id: "api08-2",
          title: "Verificar presença de security headers (HSTS, CSP, X-Frame-Options)",
          description: "Validar se API retorna headers de segurança essenciais.",
          guide: {
            overview: "Headers de segurança protegem contra ataques de client-side (XSS, Clickjacking, MITM).",
            impact: "Clickjacking, downgrade de HTTPS, XSS, MIME sniffing attacks.",
            detection: [
              "Fazer request à API e inspecionar headers",
              "Verificar ausência de: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options"
            ],
            tools: ["curl", "securityheaders.com", "Mozilla Observatory"],
            commands: [
              "# Verificar headers",
              "curl -I https://api.example.com/api/users",
              "",
              "# Headers esperados:",
              "Strict-Transport-Security: max-age=31536000; includeSubDomains",
              "X-Content-Type-Options: nosniff",
              "X-Frame-Options: DENY",
              "Content-Security-Policy: default-src 'self'",
              "X-XSS-Protection: 0  (deprecated, remover)",
              "Referrer-Policy: strict-origin-when-cross-origin"
            ],
            steps: [
              "1. Fazer request à API e capturar response headers",
              "2. Verificar ausência de headers críticos",
              "3. Testar impacto: carregar API em iframe (X-Frame-Options)",
              "4. Verificar TLS: openssl s_client -connect api.example.com:443",
              "5. Usar ferramentas automatizadas: securityheaders.com"
            ],
            mitigation: [
              "Configurar headers no servidor web (Nginx, Apache) ou framework",
              "Helmet.js (Express): app.use(helmet())",
              "Headers obrigatórios: HSTS, X-Content-Type-Options: nosniff",
              "Headers recomendados: CSP, Referrer-Policy, Permissions-Policy",
              "Remover headers que revelam tecnologia: X-Powered-By, Server"
            ],
            evidence: [
              "curl -I output mostrando ausência de HSTS",
              "Screenshot do securityheaders.com com grade F",
              "API carregada em iframe (falta X-Frame-Options)",
              "Comparação: API atual vs headers recomendados"
            ],
            references: [
              "https://owasp.org/www-project-secure-headers/",
              "https://securityheaders.com/",
              "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "api09",
      title: "API9:2023 – Improper Inventory Management",
      summary: "Versões antigas de API expostas, documentação desatualizada, endpoints shadow/debug.",
      items: [
        {
          id: "api09-1",
          title: "Enumerar versões antigas de API e testar se ainda estão ativas",
          description: "Identificar /api/v1, /api/v2, /api/old e verificar se versões antigas (vulneráveis) estão acessíveis.",
          guide: {
            overview: "APIs mantêm versões antigas ativas que não recebem patches de segurança.",
            impact: "Exploração de vulnerabilidades já corrigidas em v3 mas presentes em v1, bypass de mitigações.",
            detection: [
              "Fazer fuzzing de versões: /api/v1, /api/v2, /api/old, /api/beta, /api/legacy",
              "Comparar funcionalidade e segurança entre versões",
              "Testar vulnerabilidades conhecidas em versões antigas"
            ],
            tools: ["ffuf", "Burp Suite", "Postman"],
            commands: [
              "# Fuzzing de versões",
              "ffuf -u https://api.example.com/api/FUZZ/users -w versions.txt",
              "",
              "# versions.txt:",
              "v1",
              "v2",
              "v3",
              "old",
              "legacy",
              "beta",
              "dev",
              "internal",
              "",
              "# Comparar endpoints",
              "curl https://api.example.com/api/v1/users  # Sem autenticação?",
              "curl https://api.example.com/api/v3/users  # Com autenticação?"
            ],
            steps: [
              "1. Identificar versão atual da API (documentação, headers)",
              "2. Fazer fuzzing de versões: v1, v2, v0, old, legacy, alpha, beta",
              "3. Para cada versão encontrada, testar endpoints críticos",
              "4. Comparar comportamento: v1 tem rate limiting? v3 tem?",
              "5. Testar vulnerabilidades corrigidas em v-latest mas presentes em v-old",
              "6. Verificar se documentação lista todas versões ativas"
            ],
            mitigation: [
              "Descontinuar versões antigas: retornar 410 Gone",
              "Manter apenas últimas 2 versões ativas",
              "Documentar claramente deprecation timeline",
              "Aplicar patches de segurança em TODAS as versões ativas",
              "Usar API Gateway para versioning e deprecation unificados"
            ],
            evidence: [
              "GET /api/v1/users retorna 200 OK (versão de 2019)",
              "Documentação menciona apenas v3, mas v1 e v2 estão ativas",
              "Exploit em v1: sem rate limiting, mas v3 tem",
              "Comparação de security headers: v1 tem menos proteções"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
              "https://apisecurity.io/encyclopedia/content/api-inventory"
            ]
          }
        }
      ]
    },
    {
      id: "api10",
      title: "API10:2023 – Unsafe Consumption of APIs",
      summary: "Consumo inseguro de APIs de terceiros sem validação de dados recebidos.",
      items: [
        {
          id: "api10-1",
          title: "Validar tratamento de dados de APIs de terceiros (XSS, SQLi via API externa)",
          description: "Verificar se aplicação valida/sanitiza dados recebidos de APIs externas antes de usar.",
          guide: {
            overview: "APIs que consomem dados de terceiros (pagamentos, geolocalização) podem receber payloads maliciosos.",
            impact: "XSS via dados de API externa, SQLi se dados forem usados em queries, RCE em casos extremos.",
            detection: [
              "Identificar integrações com APIs externas (Stripe, Google Maps, weather API)",
              "Testar se dados retornados são sanitizados antes de exibir",
              "Inserir payload XSS em dados mockados de API externa"
            ],
            tools: ["Burp Suite", "Postman", "Mock servers"],
            commands: [
              "# Mock API maliciosa",
              "# Configurar mock server para retornar payload XSS",
              "{",
              "  \"userName\": \"<script>alert('XSS')</script>\",",
              "  \"address\": \"'; DROP TABLE users;--\"",
              "}",
              "",
              "# Verificar se aplicação renderiza sem sanitização",
              "# Ou se usa dados em SQL query sem prepared statements"
            ],
            steps: [
              "1. Mapear integrações com APIs de terceiros",
              "2. Identificar dados recebidos: nome, endereço, descrição, etc",
              "3. Criar mock da API externa retornando payloads maliciosos",
              "4. Observar se aplicação: a) sanitiza dados, b) valida schema, c) usa direto",
              "5. Testar XSS: <script>alert(1)</script>",
              "6. Testar SQLi: '; DROP TABLE--",
              "7. Verificar logs de erro: stack traces revelando vulnerabilidades?"
            ],
            mitigation: [
              "Validar schema de dados recebidos (JSON Schema, Zod)",
              "Sanitizar TODOS os dados de APIs externas antes de usar",
              "Usar prepared statements para dados em queries SQL",
              "Escape de HTML ao renderizar dados de terceiros",
              "Implementar timeout e retry em chamadas externas",
              "Ter fallback se API externa estiver comprometida"
            ],
            evidence: [
              "Mock API retornando {\"name\":\"<script>alert(1)</script>\"}",
              "Screenshot da aplicação renderizando XSS",
              "Código mostrando uso direto de data.userName sem sanitização",
              "SQL query concatenando dados de API: 'SELECT * FROM users WHERE name=' + externalData.name"
            ],
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
              "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "graphql",
      title: "GraphQL Security",
      summary: "Testes específicos para APIs GraphQL (introspection, depth limit, batching attacks).",
      items: [
        {
          id: "graphql-1",
          title: "Testar introspection ativa e vazamento de schema",
          description: "Verificar se GraphQL introspection está habilitada em produção, revelando schema completo.",
          guide: {
            overview: "GraphQL introspection permite query do schema completo, revelando tipos, campos, mutations não documentados.",
            impact: "Exposição de funcionalidades internas, descoberta de endpoints admin, mapeamento completo da API.",
            detection: [
              "Fazer query de introspection: __schema { types { name fields { name } } }",
              "Se retornar schema completo: introspection está ativa"
            ],
            tools: ["GraphQL Playground", "Insomnia", "Burp Suite GraphQL extension"],
            commands: [
              "# Query de introspection",
              "curl -X POST https://api.example.com/graphql \\",
              "  -H 'Content-Type: application/json' \\",
              "  -d '{\"query\": \"{ __schema { types { name } } }\"}'",
              "",
              "# Introspection completa",
              "curl -X POST https://api.example.com/graphql \\",
              "  -H 'Content-Type: application/json' \\",
              "  -d @introspection-query.json",
              "",
              "# Ferramenta automatizada",
              "graphql-voyager https://api.example.com/graphql"
            ],
            steps: [
              "1. Fazer POST para endpoint GraphQL",
              "2. Enviar introspection query: { __schema { queryType { name } } }",
              "3. Se retornar dados (não erro): introspection ativa",
              "4. Fazer full introspection e mapear: queries, mutations, subscriptions",
              "5. Procurar por campos admin, internal, debug",
              "6. Documentar tipos e campos não documentados"
            ],
            mitigation: [
              "Desabilitar introspection em produção",
              "Apollo Server: introspection: process.env.NODE_ENV !== 'production'",
              "GraphQL Yoga: disableIntrospection: true",
              "Ou implementar autenticação para introspection (apenas admins)",
              "Usar API Gateway para bloquear queries de introspection"
            ],
            evidence: [
              "Response de introspection query com schema completo",
              "Screenshot do GraphQL Voyager mostrando mapa da API",
              "Lista de mutations não documentadas: deleteAllUsers, resetDatabase",
              "Comparação: documentação pública vs schema real (campos ocultos)"
            ],
            references: [
              "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
              "https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/",
              "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"
            ]
          }
        },
        {
          id: "graphql-2",
          title: "Testar ataques de depth/complexity (Nested queries DoS)",
          description: "Criar queries profundamente aninhadas para causar DoS por consumo de recursos.",
          guide: {
            overview: "GraphQL permite queries nested ilimitadas que podem sobrecarregar servidor/banco.",
            impact: "DoS, timeout de servidor, consumo excessivo de CPU/memória, crash de banco de dados.",
            detection: [
              "Criar query com 50+ níveis de nesting",
              "Observar tempo de resposta e uso de recursos",
              "Verificar se há limite de profundidade"
            ],
            tools: ["GraphQL Playground", "curl", "Custom scripts"],
            commands: [
              "# Query nested extrema (depth attack)",
              "curl -X POST https://api.example.com/graphql -d '{",
              "  \"query\": \"{ users { posts { comments { author { posts { comments { author { posts { comments { author { id } } } } } } } } } }\"",
              "}'",
              "",
              "# Complexity attack (batch queries)",
              "curl -X POST https://api.example.com/graphql -d '{",
              "  \"query\": \"{ q1: users { id } q2: users { id } q3: users { id } ... q100: users { id } }\"",
              "}'"
            ],
            steps: [
              "1. Mapear relacionamentos do schema: User → Posts → Comments → Author",
              "2. Criar query nested: user.posts.comments.author.posts.comments (10+ níveis)",
              "3. Enviar query e medir tempo de resposta",
              "4. Incrementar profundidade até causar timeout ou erro",
              "5. Testar batch queries: 100 queries em uma única requisição",
              "6. Monitorar servidor: CPU, memória, queries SQL geradas"
            ],
            mitigation: [
              "Implementar max query depth: 5-7 níveis",
              "Apollo Server: validationRules: [depthLimit(7)]",
              "Implementar query complexity analysis",
              "Limitar batching: max 5 queries por request",
              "Usar dataloader para evitar N+1 queries",
              "Timeout de queries: 10 segundos máximo"
            ],
            evidence: [
              "Query com 20 níveis de nesting",
              "Log de timeout: 'Query exceeded 30s limit'",
              "Screenshot do database log: 10,000 SELECT queries geradas",
              "Gráfico de CPU: spike de 100% durante query"
            ],
            references: [
              "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#depth-limiting",
              "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
              "https://github.com/stems/graphql-depth-limit"
            ]
          }
        }
      ]
    }
  ]
};
