/**
 * Business Logic Vulnerabilities
 * Falhas em regras de negócio que não são detectadas por scanners automatizados
 * Requerem compreensão do contexto e fluxo da aplicação
 */

export const businessLogicChecklist = {
  id: "business-logic",
  name: "Business Logic Flaws",
  description: "Vulnerabilidades de Lógica de Negócio - Falhas em workflows, validações de estado, race conditions e bypass de processos que requerem análise manual contextual.",
  sections: [
    {
      id: "bl-workflow",
      title: "Bypass de Workflow e Sequência de Passos",
      summary: "Manipulação de ordem de operações, pular etapas obrigatórias, acessar estados inválidos.",
      items: [
        {
          id: "bl-workflow-1",
          title: "Testar bypass de etapas obrigatórias em processos multi-step",
          description: "Verificar se é possível pular validações intermediárias (ex: checkout sem pagamento).",
          guide: {
            overview: "Processos multi-step (registro, checkout, aprovação) podem permitir pular etapas críticas.",
            impact: "Compras sem pagamento, cadastros sem verificação, aprovações sem autorização.",
            detection: [
              "Mapear workflow: Step 1 → Step 2 → Step 3 → Complete",
              "Tentar acessar Step 3 diretamente sem passar por Step 2",
              "Modificar state flags: completed=true, verified=true",
              "Testar direct object manipulation: POST /complete sem /payment"
            ],
            tools: ["Burp Suite", "Postman", "Browser DevTools"],
            commands: [
              "# Exemplo: Checkout em 3 passos",
              "# Normal flow:",
              "POST /cart/add-items",
              "POST /checkout/shipping",
              "POST /checkout/payment  # Validação de cartão",
              "POST /checkout/complete",
              "",
              "# Bypass attempt:",
              "POST /cart/add-items",
              "POST /checkout/complete  # Pular shipping e payment",
              "",
              "# Testar com session manipulation:",
              "# Modificar cookie: checkout_step=3 (ao invés de incrementar naturalmente)"
            ],
            steps: [
              "1. Mapear todos endpoints do workflow e ordem esperada",
              "2. Capturar requests de cada step",
              "3. Tentar chamar step final sem intermediários",
              "4. Verificar se backend valida steps anteriores (server-side state)",
              "5. Testar manipulação de flags: isVerified, hasPayment, isApproved",
              "6. Verificar se há validação de sequência no servidor",
              "7. Testar com múltiplas sessões/browsers (session inconsistency)"
            ],
            mitigation: [
              "Validar estado SERVER-SIDE em cada step",
              "Usar state machine pattern: definir transições permitidas",
              "Verificar pré-condições: if (!user.hasCompletedPayment) return 403",
              "Usar transaction IDs: cada step valida ID e status anterior",
              "Implementar idempotency: prevenir duplicação de steps",
              "Logs de auditoria para sequências anormais"
            ],
            evidence: [
              "Request POST /checkout/complete sem POST /payment anterior",
              "Response 200 OK com pedido criado (valor $0)",
              "Código mostrando ausência de validação de estado",
              "Pedido no DB: status='completed', payment_status='pending'"
            ],
            references: [
              "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
              "https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html",
              "https://portswigger.net/web-security/logic-flaws"
            ]
          }
        },
        {
          id: "bl-workflow-2",
          title: "Validar proteção contra workflow reverso (rollback indevido)",
          description: "Testar se usuário pode voltar a estados anteriores após conclusão (ex: editar pedido após pagamento).",
          guide: {
            overview: "Workflows devem impedir retorno a estados anteriores após ações irreversíveis.",
            impact: "Modificação de pedidos aprovados, alteração de votos, cancelamento de transações finalizadas.",
            detection: [
              "Completar workflow (ex: pedido pago e confirmado)",
              "Tentar acessar endpoints de steps anteriores",
              "Modificar dados já 'locked': UPDATE order SET price=0 WHERE id=X",
              "Verificar se há validação de 'final state'"
            ],
            tools: ["Burp Suite Repeater", "Postman"],
            commands: [
              "# Fluxo normal:",
              "POST /order/create → order_id: 123, status: draft",
              "POST /order/123/confirm → status: confirmed",
              "POST /order/123/pay → status: paid",
              "",
              "# Rollback attempt:",
              "PUT /order/123 {\"items\": [...], \"price\": 0}  # Após status=paid",
              "# Deve retornar 403: Order is locked",
              "",
              "# DELETE /order/123  # Após pagamento",
              "# Deve falhar: Cannot delete paid order"
            ],
            steps: [
              "1. Completar workflow até estado final (paid, approved, published)",
              "2. Capturar requests de modificação de steps anteriores",
              "3. Tentar editar entidade: PUT /resource/id",
              "4. Tentar deletar: DELETE /resource/id",
              "5. Verificar se API retorna 403 ou permite modificação",
              "6. Testar rollback de status: PATCH /order/123 {\"status\":\"draft\"}",
              "7. Verificar se há state validation: if (order.status === 'paid') reject()"
            ],
            mitigation: [
              "Implementar state locking: recursos em estado final são read-only",
              "Validar transições de estado: paid → cancelled pode exigir approval",
              "Usar event sourcing: append-only log de eventos (não DELETE/UPDATE)",
              "Audit trail: registrar tentativas de rollback indevido",
              "UI: desabilitar botões de edição após finalização (mas validar server-side!)"
            ],
            evidence: [
              "PUT /order/123 após pagamento retorna 200 OK (vulnerável)",
              "Pedido modificado após confirmação",
              "Código sem validação: if (order.status === 'paid') throw new Error()",
              "Screenshot: produto editado após entrega"
            ],
            references: [
              "https://portswigger.net/web-security/logic-flaws/examples",
              "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"
            ]
          }
        }
      ]
    },
    {
      id: "bl-economic",
      title: "Falhas de Lógica Econômica (Pricing, Currency, Quantity)",
      summary: "Manipulação de preços, quantidades negativas, overflow de valores, arbitragem de moedas.",
      items: [
        {
          id: "bl-econ-1",
          title: "Testar manipulação de preços e quantidades",
          description: "Verificar se preços podem ser alterados client-side ou via parameter tampering.",
          guide: {
            overview: "Apps que confiam em preços enviados pelo client podem ser explorados para compras fraudulentas.",
            impact: "Compras com preço $0, quantidades negativas gerando crédito, descontos indevidos.",
            detection: [
              "Capturar request de checkout",
              "Modificar price=100.00 para price=0.01",
              "Testar quantity=-10 (receber crédito ao invés de pagar)",
              "Verificar se servidor valida preços contra catálogo"
            ],
            tools: ["Burp Suite", "Browser DevTools"],
            commands: [
              "# Request normal:",
              "POST /checkout",
              "{",
              "  \"items\": [",
              "    {\"productId\": 123, \"quantity\": 2, \"price\": 50.00}",
              "  ]",
              "}",
              "",
              "# Tampering:",
              "POST /checkout",
              "{",
              "  \"items\": [",
              "    {\"productId\": 123, \"quantity\": 100, \"price\": 0.01}",
              "    {\"productId\": 456, \"quantity\": -50, \"price\": 100.00}  # Ganha $5000",
              "  ]",
              "}"
            ],
            steps: [
              "1. Adicionar produto ao carrinho e capturar request de checkout",
              "2. Modificar campo 'price' para valor baixo: 0.01",
              "3. Submeter e verificar se pedido é aceito",
              "4. Testar quantidade negativa: quantity: -10",
              "5. Testar overflow: quantity: 99999999999",
              "6. Verificar se total calculado server-side: SUM(catalog.price * qty)",
              "7. Testar discount codes com valores negativos"
            ],
            mitigation: [
              "NUNCA confiar em preços enviados pelo client",
              "Calcular total server-side: SELECT price FROM products WHERE id=? * quantity",
              "Validar quantity > 0 e < max_per_order",
              "Validar discount codes contra database",
              "Usar integer types para monetary values (evitar float errors)",
              "Implementar fraud detection: pedidos com price=0 são flagged"
            ],
            evidence: [
              "Request com price: 0.01 sendo aceito",
              "Pedido criado com total: $0.10 (real: $100)",
              "Código confiando em req.body.price ao invés de DB lookup",
              "Screenshot do pedido confirmado com preço manipulado"
            ],
            references: [
              "https://portswigger.net/web-security/logic-flaws/examples",
              "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
              "CWE-840: Business Logic Errors"
            ]
          }
        },
        {
          id: "bl-econ-2",
          title: "Validar proteção contra race conditions em recursos limitados",
          description: "Testar se múltiplas requisições simultâneas podem explorar recursos limitados (estoque, créditos, cupons únicos).",
          guide: {
            overview: "Race conditions permitem que múltiplos requests consumam recurso único (cupom, último item em estoque).",
            impact: "Uso múltiplo de cupons únicos, compra de mais itens que estoque disponível, double-spending de créditos.",
            detection: [
              "Identificar recurso limitado: estoque=1, cupom uso único, saldo de créditos",
              "Enviar múltiplas requests simultâneas (Burp Intruder, scripts)",
              "Verificar se todas são aceitas (race condition) ou apenas primeira"
            ],
            tools: ["Burp Suite Intruder", "Turbo Intruder", "Python multiprocessing"],
            commands: [
              "# Script Python - Race condition test",
              "import requests",
              "from concurrent.futures import ThreadPoolExecutor",
              "",
              "def buy_item():",
              "    r = requests.post('https://api.example.com/buy', ",
              "                      json={'productId': 123, 'couponCode': 'SINGLE_USE'},",
              "                      headers={'Authorization': f'Bearer {token}'})",
              "    return r.status_code",
              "",
              "# Enviar 10 requests simultâneos",
              "with ThreadPoolExecutor(max_workers=10) as executor:",
              "    results = list(executor.map(lambda _: buy_item(), range(10)))",
              "",
              "print(f'Successful requests: {results.count(200)}')",
              "# Se > 1: race condition (cupom usado múltiplas vezes)"
            ],
            steps: [
              "1. Identificar endpoint com recurso limitado (estoque, cupom, créditos)",
              "2. Preparar request válida (Burp Repeater)",
              "3. Enviar 10+ requests simultâneas (Burp Intruder > Null payloads > thread count 10)",
              "4. Observar quantas retornam 200 OK",
              "5. Verificar estado do recurso: estoque=-5? cupom usado 10x?",
              "6. Confirmar race condition se múltiplas requests foram aceitas",
              "7. Testar com timing: espaçar requests por milissegundos"
            ],
            mitigation: [
              "Usar database transactions com locks: SELECT ... FOR UPDATE",
              "Implementar idempotency keys: cada request tem UUID único",
              "Atomic operations: DECREMENT stock WHERE stock > 0",
              "Distributed locks: Redis SETNX para recursos globais",
              "Optimistic locking: version numbers em updates",
              "Rate limiting agressivo em endpoints críticos",
              "Queue system para processar sequencialmente"
            ],
            evidence: [
              "10 requests simultâneas, 7 retornaram 200 OK",
              "Cupom 'SINGLE_USE' usado 7 vezes",
              "Estoque: -6 (negativo, race condition confirmada)",
              "Código sem transaction/lock: estoque verificado e decrementado em 2 queries separadas"
            ],
            references: [
              "https://portswigger.net/web-security/race-conditions",
              "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
              "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization"
            ]
          }
        }
      ]
    },
    {
      id: "bl-privilege",
      title: "Abuso de Funcionalidades e Privilégios",
      summary: "Uso indevido de features legítimas para fins maliciosos, automação excessiva, farming.",
      items: [
        {
          id: "bl-priv-1",
          title: "Identificar funcionalidades legítimas exploráveis para abuso",
          description: "Mapear features que podem ser automatizadas ou usadas em escala para ganho indevido.",
          guide: {
            overview: "Features legítimas (referral, trial, free tier) podem ser exploradas para farming, farming de bônus, fraude.",
            impact: "Abuso de programas de referral, criação massiva de contas trial, farming de recursos gratuitos.",
            detection: [
              "Identificar features com incentivos: $10 por indicação, 30 dias grátis",
              "Testar automação: criar 100 contas via script",
              "Verificar limites: quantas contas trial por IP/device?",
              "Analisar: feature pode ser explorada para ganho financeiro?"
            ],
            tools: ["Selenium", "Puppeteer", "Python requests", "Temporary email services"],
            commands: [
              "# Script de automação de referral abuse",
              "import requests",
              "import random",
              "",
              "referral_code = 'ABC123'  # Código do atacante",
              "",
              "for i in range(100):",
              "    fake_email = f'user{i}@tempmail.com'",
              "    requests.post('https://api.example.com/signup', json={",
              "        'email': fake_email,",
              "        'password': 'Password123!',",
              "        'referralCode': referral_code  # $10 por signup",
              "    })",
              "",
              "# Atacante ganha $1000 em bônus de referral"
            ],
            steps: [
              "1. Mapear features com incentivos financeiros ou recursos gratuitos",
              "2. Analisar limites: quantas vezes posso usar? por IP? por device?",
              "3. Testar criação em massa de contas (email temporário)",
              "4. Verificar se há validação: KYC, phone verification, CAPTCHA",
              "5. Testar se bônus de referral pode ser auto-referral",
              "6. Analisar se trial pode ser renovado infinitamente",
              "7. Verificar se há fraud detection para padrões anômalos"
            ],
            mitigation: [
              "Implementar KYC (Know Your Customer) para bônus",
              "Limitar por device fingerprint, não apenas IP",
              "Phone verification (SMS) para dificultar automação",
              "CAPTCHA em ações que geram incentivos",
              "Fraud detection: flag contas criadas em massa, mesmo IP, padrões similares",
              "Manual review para payouts acima de threshold",
              "Limitar trials: 1 por cartão de crédito (mesmo que não cobre)",
              "Velocity checks: max 5 signups/hora por IP"
            ],
            evidence: [
              "100 contas criadas via script em 10 minutos",
              "Todas usaram mesmo referral code",
              "$1000 em bônus acumulados sem validação",
              "Ausência de CAPTCHA, phone verification, fraud detection"
            ],
            references: [
              "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
              "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "bl-timing",
      title: "Timing e Sequência de Eventos",
      summary: "Exploração de janelas temporais, condições de corrida temporal, expiração inadequada.",
      items: [
        {
          id: "bl-timing-1",
          title: "Testar reutilização de tokens/códigos após expiração ou uso",
          description: "Verificar se OTP, reset tokens, vouchers podem ser reutilizados após consumo.",
          guide: {
            overview: "Tokens/códigos devem ser invalidados após uso ou expiração, prevenindo replay attacks.",
            impact: "Reutilização de OTP para múltiplos logins, reset tokens reutilizáveis, vouchers usados infinitamente.",
            detection: [
              "Receber token/código (OTP, password reset, voucher)",
              "Usar uma vez com sucesso",
              "Tentar reusar: deve falhar",
              "Verificar se há invalidação no banco: token_used=true, used_at=timestamp"
            ],
            tools: ["Burp Repeater", "curl"],
            commands: [
              "# Password reset flow:",
              "POST /forgot-password → Email com token: abc123",
              "POST /reset-password {\"token\": \"abc123\", \"newPassword\": \"Pass1\"}",
              "# Response: 200 OK, password alterado",
              "",
              "# Replay attack:",
              "POST /reset-password {\"token\": \"abc123\", \"newPassword\": \"Hacked123\"}",
              "# Se retornar 200 OK: token reutilizável (vulnerável)",
              "# Se retornar 400 'Token already used': seguro"
            ],
            steps: [
              "1. Requisitar token: OTP, password reset, voucher",
              "2. Usar token com sucesso (1ª vez)",
              "3. Capturar request de uso",
              "4. Reenviar mesma request (2ª vez)",
              "5. Verificar se é aceita (vulnerável) ou rejeitada",
              "6. Testar após expiração: token de 5min usado após 10min",
              "7. Verificar database: tokens marcados como 'used'?"
            ],
            mitigation: [
              "Invalidar token após primeiro uso: UPDATE tokens SET used=true WHERE token=?",
              "Implementar expiração: exp_at < NOW()",
              "Usar tokens de uso único (UUID v4, não sequenciais)",
              "Armazenar hash de tokens (não plain text)",
              "Logs de uso: user_id, token, used_at, IP",
              "Rate limiting: max 3 tentativas de reset/hora"
            ],
            evidence: [
              "Token reutilizado com sucesso 5x",
              "Database: tokens table sem coluna 'used' ou 'used_at'",
              "Código sem invalidação após uso",
              "OTP usado 2 dias após geração (sem expiração)"
            ],
            references: [
              "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
              "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
              "CWE-294: Authentication Bypass by Capture-replay"
            ]
          }
        }
      ]
    }
  ]
};
