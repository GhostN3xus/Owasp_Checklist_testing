# 🔍 OWASP Top 10 2021 - Guia Completo e Expandido

## Vulnerabilidades Web Críticas com Exemplos Práticos

---

## 📖 Índice

1. [A01 - Broken Access Control](#a01-broken-access-control)
2. [A02 - Cryptographic Failures](#a02-cryptographic-failures)
3. [A03 - Injection](#a03-injection)
4. [A04 - Insecure Design](#a04-insecure-design)
5. [A05 - Security Misconfiguration](#a05-security-misconfiguration)
6. [A06 - Vulnerable and Outdated Components](#a06-vulnerable-and-outdated-components)
7. [A07 - Authentication Failures](#a07-authentication-failures)
8. [A08 - Software and Data Integrity Failures](#a08-software-and-data-integrity-failures)
9. [A09 - Logging and Monitoring Failures](#a09-logging-and-monitoring-failures)
10. [A10 - Server-Side Request Forgery (SSRF)](#a10-ssrf)

---

## A01 - Broken Access Control {#a01-broken-access-control}

### 📌 Explicação Simples

Broken Access Control significa que **usuários podem acessar dados/funções que não deveriam**.

Exemplos do dia-a-dia:
- Usuário normal vê dados de admin
- Usuário vê dados de outro usuário
- Sem autenticação em função crítica

### 🔧 Explicação Técnica

Access Control é um mecanismo que decide:
- **Quem** pode acessar (autenticação)
- **O Quê** pode acessar (autorização)
- **Quando** pode acessar (temporal)
- **Como** pode acessar (método)

**Tipos Comuns de Falhas:**

1. **Insecure Direct Object Reference (IDOR)**
```
GET /api/user/123/profile
GET /api/user/124/profile ← Posso acessar outro usuário?

Aplicação não valida se esse ID pertence a mim
Resultado: Acesso a dados de outro usuário
```

2. **Horizontal Escalation (mesmo nível)**
```
Usuário 1: /api/users/1/data
Usuário 2: /api/users/1/data ← Acesso sem validação
```

3. **Vertical Escalation (privilégio elevado)**
```
User (ramo baixo): GET /api/admin/users → Acesso concedido!
Deveria ser admin only
```

4. **Path Traversal**
```
GET /api/download?file=report.pdf
GET /api/download?file=../../../etc/passwd ← Acessa arquivo do sistema!
```

5. **Função Administrativa Desprotegida**
```
/admin/dashboard → Sem check de role
Qualquer usuário acessava!
```

### 💡 Exemplos Práticos

**Exemplo 1: IDOR em Aplicação Bancária**

Código Vulnerável (Node.js):
```javascript
app.get('/api/account/:accountId/balance', (req, res) => {
  const { accountId } = req.params;

  // NÃO VALIDA SE O USUÁRIO PODE ACESSAR ESSA CONTA!
  const balance = db.query(
    "SELECT balance FROM accounts WHERE id = ?",
    [accountId]
  );

  res.json({ balance });
});

// Atacante faz:
// GET /api/account/999/balance → Acessa conta de outro usuário!
```

Código Seguro:
```javascript
app.get('/api/account/:accountId/balance', authenticateUser, (req, res) => {
  const { accountId } = req.params;
  const { userId } = req.user;

  // VALIDA OWNERSHIP
  const account = db.query(
    "SELECT * FROM accounts WHERE id = ? AND owner_id = ?",
    [accountId, userId]
  );

  if (!account) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json({ balance: account.balance });
});
```

**Exemplo 2: Path Traversal**

Vulnerável:
```python
@app.route('/download')
def download():
    filename = request.args.get('file')
    # PERIGOSO: não valida path
    with open(f'/uploads/{filename}', 'r') as f:
        return f.read()

# Ataque: /download?file=../../../etc/passwd
```

Seguro:
```python
from pathlib import Path

@app.route('/download')
def download():
    filename = request.args.get('file')

    # Validar que é arquivo permitido
    upload_dir = Path('/uploads').resolve()
    file_path = (upload_dir / filename).resolve()

    # Verificar que file_path está dentro de upload_dir
    if not str(file_path).startswith(str(upload_dir)):
        abort(403)

    return send_file(file_path)
```

### ⌨️ Como Testar

**Testes Manuais com Burp Suite:**

```
1. Abrir Burp Suite Community
2. Proxy → Intercept requests ON
3. Navegar pela aplicação
4. Em cada requisição com ID:
   ├─ Mudar o ID para ID de outro usuário
   ├─ Verificar se acessa dados
   ├─ Tentar IDs aleatórios/negativos
   └─ Tentar IDs de admin

5. Testar modificação:
   ├─ GET /user/1 → Acesso OK
   ├─ GET /user/2 → Acesso negado?
   └─ PATCH /user/2 → Pode modificar outro usuário?

6. Testar path traversal:
   ├─ /download?file=report.pdf ✓
   ├─ /download?file=../report.pdf
   ├─ /download?file=..%2Freport.pdf (encoded)
   └─ /download?file=....//report.pdf (bypass)
```

**Teste Automatizado (Python com Requests):**

```python
import requests
import json

BASE_URL = "http://vulnerable-app.local"

def test_idor():
    """Teste se app valida ownership"""

    # Login como User 1
    resp = requests.post(f"{BASE_URL}/login", json={
        "username": "user1",
        "password": "password123"
    })
    token = resp.json()['token']
    headers = {"Authorization": f"Bearer {token}"}

    # Acessar dados de User 1 (seu próprio)
    user1_data = requests.get(
        f"{BASE_URL}/api/user/1/profile",
        headers=headers
    )
    assert user1_data.status_code == 200
    print(f"✓ User 1 pode acessar seu perfil")

    # Tentar acessar dados de User 2 (outro usuário)
    user2_data = requests.get(
        f"{BASE_URL}/api/user/2/profile",
        headers=headers
    )

    if user2_data.status_code == 200:
        print(f"✗ CRÍTICO: User 1 conseguiu acessar perfil de User 2!")
        print(f"Dados vazados: {user2_data.json()}")
        return False
    else:
        print(f"✓ Acesso negado (esperado)")
        return True

if __name__ == "__main__":
    test_idor()
```

### 🛠️ Ferramentas Recomendadas

| Ferramenta | Tipo | Uso | Link |
|-----------|------|-----|------|
| **Burp Suite Community** | Manual | Interceptar e modificar requisições | https://portswigger.net/burp |
| **OWASP ZAP** | Automatizado | Scan de IDOR | https://www.zaproxy.org/ |
| **Nuclei** | Automatizado | Exploits predefinidos | https://github.com/projectdiscovery/nuclei |
| **Postman** | API Testing | Testar autorização em APIs | https://www.postman.com/ |

### 📚 Checklist de Teste

```
[ ] Testar cada ID com valores diferentes (1, 2, 100, 999, -1)
[ ] Testar sequência de IDs (1, 2, 3... pode enumerar?)
[ ] Testar com usuários de roles diferentes (user, admin)
[ ] Testar path traversal (../, ..%2F, ....%2f%2f)
[ ] Testar sem autenticação (remover token)
[ ] Testar com token de outro usuário
[ ] Testar funções administrativas
[ ] Testar PATCH/PUT para modificar dados de outro usuário
[ ] Testar mass assignment (?role=admin&email=novo@email.com)
[ ] Analisar respostas 403 vs 404 (information disclosure)
```

### 🔗 Referências

- [OWASP Broken Access Control](https://owasp.org/www-community/attacks/Insecure_Direct_Object_References)
- [PortSwigger IDOR](https://portswigger.net/web-security/access-control/idor)
- [HackerOne: Top IDOR Submissions](https://hackerone.com/)

---

## A02 - Cryptographic Failures {#a02-cryptographic-failures}

### 📌 Explicação Simples

Falhas criptográficas significa que **dados sensíveis não estão protegidos**.

Exemplos:
- Senhas armazenadas em texto plano
- Comunicação sem HTTPS
- Chaves criptográficas fracas
- Algoritmos desatualizados (MD5, SHA1)

### 🔧 Explicação Técnica

**Tipos de Falhas Criptográficas:**

1. **Senhas em Texto Plano**
```
❌ Ruim:
INSERT INTO users (username, password)
VALUES ('admin', 'admin123');

✓ Bom:
$2b$12$R9h/cIPz0gi.URNNGH3H... (bcrypt hash)
```

2. **Dados Sensíveis sem Criptografia em Trânsito**
```
❌ HTTP: GET /api/user?ssn=123-45-6789
✓ HTTPS: GET /api/user?ssn=123-45-6789 (criptografado)
```

3. **Armazenamento de Dados Sensíveis em Texto Plano**
```
❌ BD: credit_card = "4111-1111-1111-1111"
✓ BD: credit_card_hash = "abc123def456..." + tokenização
```

4. **Chaves Criptográficas Fracas**
```
❌ key = "password123"
✓ key = (256 bits random gerado com /dev/urandom)
```

5. **Algoritmos Desatualizados**
```
❌ MD5, SHA1 (quebrados)
✓ SHA-256, SHA-3, Argon2 (seguros)
```

### 💡 Exemplos Práticos

**Exemplo 1: Hash de Senha Inseguro**

Código Vulnerável:
```python
import hashlib

def register_user(username, password):
    # PÉSSIMO: MD5 é quebrado!
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashed]
    )

# Ataque: Rainbow tables quebram MD5 em segundos
```

Código Seguro:
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

hasher = PasswordHasher()

def register_user(username, password):
    # Argon2 é resistente a GPU cracking
    hashed = hasher.hash(password)
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashed]
    )

def login_user(username, password):
    user = db.query("SELECT password FROM users WHERE username = ?", [username])
    try:
        hasher.verify(user['password'], password)
        return True  # Login OK
    except VerifyMismatchError:
        return False  # Senha incorreta
```

**Exemplo 2: Dados Sensíveis em Texto Plano**

Vulnerável:
```javascript
// Armazenar token simples
localStorage.setItem('token', token);  // Exposto a XSS!

// Enviar dados sensíveis em URL
fetch('/api/data?ssn=123-45-6789');  // Logs expõem SSN!
```

Seguro:
```javascript
// HttpOnly cookie (não acessível por JavaScript)
// Backend seta: Set-Cookie: token=xyz; HttpOnly; Secure

// Enviar dados sensíveis no body
fetch('/api/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ssn: '123-45-6789' })
});
```

**Exemplo 3: Comunicação sem HTTPS**

Código Vulnerável:
```javascript
// Conectar a API sem HTTPS
const API_URL = "http://api.example.com";  // NÃO CRIPTOGRAFADO!
```

Código Seguro:
```javascript
// Sempre HTTPS
const API_URL = "https://api.example.com";

// Forçar HTTPS no backend
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.header('host')}${req.url}`);
  }
  next();
});
```

### ⌨️ Como Testar

**1. Verificar Protocolo HTTP/HTTPS**

```bash
# Testar se site aceita HTTP (BAD)
curl -v http://example.com

# Verificar HSTS header (força HTTPS)
curl -I https://example.com | grep Strict-Transport-Security
```

**2. Testar Armazenamento de Senhas**

```python
import requests
import hashlib

# Simular captura de BD (hipotético)
hashed_password = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5("password")

# Testar com hashcat
# hashcat -m 0 hashes.txt rockyou.txt

# Ou rainbow tables
def check_md5_weak():
    # MD5 é reversível rapidamente
    cracked = online_md5_lookup(hashed_password)  # Acha em dicts online
    print(f"Password cracked: {cracked}")
```

**3. Verificar Algoritmo de Hash**

```bash
# Se conseguir acesso a BD (teste de penetração autorizado)
SELECT password FROM users LIMIT 1;

# Identificar algoritmo:
$2b$12$... → Bcrypt (SEGURO)
$2y$12$... → bcrypt com bug fix
$1$...     → MD5 crypt (INSEGURO)
$6$...     → SHA-512 crypt (OK mas Argon2 é melhor)
plaintext  → CRÍTICO!
```

### 📚 Checklist de Teste

```
[ ] Forçar HTTP (sem S) → redireciona para HTTPS?
[ ] Verificar HSTS header
[ ] Testar dados sensíveis em URL (SSN, credit card)
[ ] Testar dados sensíveis em headers
[ ] Verificar certificado SSL (validade, assinatura)
[ ] Testar com ferramenta de MITM (mitmproxy)
[ ] Verificar cookies (Secure, HttpOnly, SameSite flags)
[ ] Analisar método de hash de senha (se conseguir BD)
[ ] Testar força de chaves criptográficas (gerador aleatório?)
[ ] Verificar se dados em cache contêm info sensível
[ ] Testar se dados deletados são realmente deletados
```

### 🛠️ Ferramentas Recomendadas

| Ferramenta | Uso |
|-----------|-----|
| **Burp Suite** | Verificar headers, interceptar HTTPS |
| **Wireshark** | Capturar tráfego (para ver diferença HTTP vs HTTPS) |
| **mitmproxy** | MITM testing |
| **hashcat** | Crack hashes |
| **John the Ripper** | Password cracking |

### 📚 Referências

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Argon2 Memory Hard](https://github.com/P-H-C/phc-winner-argon2)

---

## A03 - Injection {#a03-injection}

### 📌 Explicação Simples

Injection significa **inserir código malicioso em um comando**.

Tipos:
- SQL Injection: Manipular query do banco
- Command Injection: Executar comandos do SO
- LDAP Injection: Manipular queries LDAP
- XPath Injection: Manipular queries XML

### 🔧 Explicação Técnica

**Fluxo de Ataque Injection:**

```
1. Aplicação espera: ID = 5
   SELECT * FROM users WHERE id = 5

2. Atacante manda: ID = 5 OR 1=1
   SELECT * FROM users WHERE id = 5 OR 1=1
   (Retorna TODOS os usuários!)

3. Aplicação executa comando sem validar
   Resultado: Extração de dados
```

**Tipos Comuns:**

**1. SQL Injection**
```sql
Input: ' OR '1'='1
Query: SELECT * FROM users WHERE email = '' OR '1'='1'
Resultado: Todos os usuários

Input: '; DROP TABLE users; --
Query: SELECT * FROM users; DROP TABLE users; --
Resultado: Tabela deletada (CRÍTICO!)

Input: ' UNION SELECT version() --
Resultado: Versão do BD exposto
```

**2. Command Injection**
```bash
Input: ; rm -rf /
Command: ping -c 5 ; rm -rf /
Resultado: Sistema formatado!

Input: | whoami
Command: ping -c 5 | whoami
Resultado: Executa whoami
```

**3. LDAP Injection**
```ldap
Input: *
Query: (&(uid=*))
Resultado: Todos os usuários autenticam
```

### 💡 Exemplos Práticos

**Exemplo 1: SQL Injection em Login**

Vulnerável:
```python
def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(query)
    return user

# Ataque:
# username: admin' --
# password: qualquer_coisa
# Query vira: SELECT * FROM users WHERE username = 'admin' -- AND password = 'qualquer_coisa'
# Resultado: Login como admin sem senha!
```

Seguro:
```python
def login(username, password):
    # Prepared Statement - valores separados do SQL
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    user = db.execute(query, [username, password])
    return user
```

**Exemplo 2: Command Injection**

Vulnerável:
```python
import os

def ping_host(hostname):
    # PERIGOSO: executa comando shell
    output = os.system(f"ping -c 5 {hostname}")
    return output

# Ataque:
# hostname: "localhost; rm -rf /"
# Comando: ping -c 5 localhost; rm -rf /
```

Seguro:
```python
import subprocess

def ping_host(hostname):
    # Validar hostname
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname")

    # Usar subprocess com lista (sem shell=True)
    result = subprocess.run(
        ["ping", "-c", "5", hostname],
        capture_output=True,
        text=True,
        timeout=10  # Timeout contra DoS
    )
    return result.stdout
```

### ⌨️ Como Testar - SQL Injection

**Teste Manual com Burp:**

```
1. Interceptar login
2. Enviar: username = admin' --
           password = qualquer_coisa
3. Se login bem-sucedido → SQLi confirmado

4. Extrair dados (UNION):
   username = admin' UNION SELECT NULL, version() --
   Retorna versão do BD

5. Enumerar tabelas:
   UNION SELECT NULL, table_name FROM information_schema.tables
```

**SQLMap - Automatizado:**

```bash
# Scan básico
sqlmap -u "http://app.com/login.php" --forms --batch

# Target específico
sqlmap -u "http://app.com/search.php?q=test" -p q

# Dumpar BD
sqlmap -u "http://app.com/search.php?q=test" -p q --dbs
sqlmap -u "http://app.com/search.php?q=test" -p q -D db_name --tables
sqlmap -u "http://app.com/search.php?q=test" -p q -D db_name -T users --dump

# Reverse shell
sqlmap -u "http://app.com/search.php?q=test" -p q --os-shell
```

### 📚 Checklist de Teste

```
SQL Injection:
[ ] Testar todos os parâmetros com: ' " ` -- # /* */
[ ] Testar UNION SELECT
[ ] Testar Boolean-based blind
[ ] Testar Time-based blind
[ ] Testar Error-based
[ ] Testar Out-of-band (DNS, HTTP)
[ ] Usar SQLMap para scan automatizado
[ ] Verificar se query em logs

Command Injection:
[ ] Testar: ; & | ` $() && ||
[ ] Verificar whitelist de caracteres
[ ] Testar bypass (${IFS}, variáveis)
[ ] Verificar se executa em shell ou subprocess
```

### 🛠️ Ferramentas

| Ferramenta | Uso |
|-----------|-----|
| **SQLMap** | Automatizado SQL Injection |
| **Burp Suite Intruder** | Testar payloads |
| **Commix** | Command Injection testing |

---

## A04 - Insecure Design {#a04-insecure-design}

### 📌 Explicação Simples

Insecure Design significa **falhas no design/arquitetura**, não em implementação.

Exemplo:
- Resetar senha sem verificação adequada
- Recuperação de conta sem MFA
- Validação fraca de negócio

### 🔧 Explicação Técnica

**Diferença: Insecure Design vs Insecure Implementation**

```
INSECURE DESIGN (Problema de Arquitetura):
  Fluxo de reset de senha:
  1. Clicar "Esqueci Senha"
  2. Email com link único
  3. Link gera nova senha
  └─ Design fraco: Link nunca expira, token previsível

INSECURE IMPLEMENTATION (Código ruim):
  Código: password = md5(input)  # Deveria ser Argon2
  └─ Design é OK, implementação é ruim
```

**Exemplos de Insecure Design:**

1. **Bypass de Validação de Negócio**
```
E-commerce permite retorno de 30 dias
Usuário coloca item na cesta → 31 dias depois → Compra → Retorna
Design fraco: Sem validação de data
```

2. **Recuperação de Conta Insegura**
```
Fluxo:
1. Username
2. Email (manda código)
3. Código (6 dígitos, 24h de validade)
4. Nova senha

Problema: 6 dígitos = 1 em 1 milhão, força bruta possível
```

3. **Avaliação Incorreta de Risco**
```
Upload de arquivo:
- Sem verificação de tipo
- Sem limite de tamanho
- Sem scan de vírus
- Armazenado com extensão original
```

### 💡 Exemplos Práticos

**Exemplo 1: Fluxo de Password Reset Seguro vs Inseguro**

Inseguro:
```python
# Quando user clica "Reset Password"
reset_token = request.args.get('token')  # Predictable, e.g., "user123_1"
user = db.query("SELECT * FROM users WHERE reset_token = ?", [reset_token])

if not user:
    return "Token inválido"

new_password = request.form.get('new_password')
db.execute("UPDATE users SET password = ? WHERE id = ?", [hash(new_password), user.id])

# Problema: Token previsível, nunca expira, reutilizável
```

Seguro:
```python
import secrets
from datetime import datetime, timedelta

# Gerar token
reset_token = secrets.token_urlsafe(32)  # 256 bits de aleatoriedade
expires_at = datetime.now() + timedelta(hours=1)  # Expira em 1h

db.execute(
    "UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?",
    [reset_token, expires_at, user.id]
)

# Validar reset
token = request.args.get('token')
user = db.query(
    "SELECT * FROM users WHERE reset_token = ? AND reset_expires > ?",
    [token, datetime.now()]
)

if not user:
    return "Token inválido ou expirado", 400

new_password = request.form.get('new_password')
hashed = argon2.hash(new_password)
db.execute(
    "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
    [hashed, user.id]
)

# Pode logarse depois, MFA recomendado
```

**Exemplo 2: Upload de Arquivo Inseguro vs Seguro**

Inseguro:
```python
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    # Nenhuma validação!
    file.save(f'/uploads/{file.filename}')
    return "Uploaded!"

# Problemas:
# - Aceita qualquer tipo
# - Sem limite de tamanho
# - Sem scan de malware
# - Armazenado com nome original
# - Acessível via web!
```

Seguro:
```python
import mimetypes
import os
import magic  # python-magic para validar MIME real
from werkzeug.utils import secure_filename
from uuid import uuid4

ALLOWED_MIME = {'image/jpeg', 'image/png', 'application/pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
UPLOAD_DIR = '/uploads_private'  # Fora do webroot

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

    # 1. Validar tamanho
    file.seek(0, os.SEEK_END)
    if file.tell() > MAX_FILE_SIZE:
        return "File too large", 400
    file.seek(0)

    # 2. Validar MIME type (real, não extension)
    file_mime = magic.from_buffer(file.read(1024), mime=True)
    if file_mime not in ALLOWED_MIME:
        return f"File type not allowed: {file_mime}", 400
    file.seek(0)

    # 3. Scan com ClamAV
    if not scan_with_clamscan(file):
        return "File contains malware", 400

    # 4. Salvar com nome seguro + UUID
    secure_name = secure_filename(file.filename)
    filename = f"{uuid4()}_{secure_name}"
    filepath = os.path.join(UPLOAD_DIR, filename)

    file.save(filepath)

    # 5. Servir com headers seguros
    return f"/api/download/{filename}"

@app.route('/api/download/<filename>')
def download(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)

    # Validar path
    if not os.path.abspath(filepath).startswith(UPLOAD_DIR):
        abort(403)

    response = send_file(filepath)
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

---

## A05 - Security Misconfiguration {#a05-security-misconfiguration}

### 📌 Explicação Simples

Security Misconfiguration é deixar **algo inseguro por padrão ou por erro**.

Exemplos:
- Defaults não alterados (senha admin padrão)
- Funcionalidades desnecessárias ativas
- Erros detalhados expostos
- Headers de segurança faltando

### 🔧 Explicação Técnica

**Checklist Comum:**

```
Servidor Web:
[ ] Versão exposta (Remove via header)
[ ] Directory listing ativo (Desabilitar)
[ ] Debug mode ativo em produção
[ ] HTTPS certificates auto-assinados
[ ] Portas desnecessárias abertas (8080, 8443, etc)

Aplicação:
[ ] Default credentials não alteradas
[ ] Funcionalidades admin expostas
[ ] Verbose error messages
[ ] Logs contêm dados sensíveis
[ ] Configs sensíveis em arquivos públicos (.env)

Banco de Dados:
[ ] Porta padrão exposta (3306, 5432)
[ ] Sem autenticação
[ ] User padrão (root, sa, admin)
[ ] Sem criptografia de comunicação
```

### 💡 Exemplos Práticos

**Exemplo 1: Default Credentials**

Vulnerável:
```
Tomcat: http://localhost:8080/manager
Username: tomcat
Password: tomcat (PADRÃO!)

Resultado: Acesso a console de administração
```

Seguro:
```
1. Mudar credentials padrão imediatamente
2. Usar senhas aleatórias 20+ caracteres
3. Armazenar em vault (não em código)
4. Usar MFA se possível
```

**Exemplo 2: Debug Mode em Produção**

Vulnerável (Flask):
```python
if __name__ == '__main__':
    app.run(debug=True)  # NUNCA em produção!

# Debug mode expõe:
# - Stack traces completos
# - Variáveis locais
# - Código fonte
# - Caminho do arquivo
```

Seguro:
```python
if __name__ == '__main__':
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug)

# .env.production:
FLASK_ENV=production
```

**Exemplo 3: Expor Informações Sensível em Erros**

Vulnerável:
```python
@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    try:
        user = db.query(f"SELECT * FROM users WHERE id = {user_id}")
        return user
    except Exception as e:
        # PÉSSIMO: Expõe stack trace completo
        return {"error": str(e)}, 500
        # Cliente vê: "sqlite3.OperationalError: no such table: users"
```

Seguro:
```python
import logging

logger = logging.getLogger(__name__)

@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    try:
        user = db.query("SELECT * FROM users WHERE id = ?", [user_id])
        return user
    except Exception as e:
        # Log details (interno)
        logger.error(f"DB error getting user {user_id}: {e}")
        # Return generic message (cliente)
        return {"error": "Internal server error"}, 500
```

### ⌨️ Como Testar

**1. Header Enumeration com curl:**

```bash
# Ver headers
curl -I https://app.com

# Deve mostrar:
# ✓ X-Frame-Options: DENY
# ✓ X-Content-Type-Options: nosniff
# ✓ Content-Security-Policy: ...
# ✓ Strict-Transport-Security: ...

# NÃO deve mostrar:
# ✗ Server: Apache/2.4.1 (versionamento)
# ✗ X-Powered-By: PHP/7.4.0
```

**2. Teste de Default Credentials:**

```bash
# Comum padrão (ports):
# 8080, 8443 (aplicações)
# 3306 (MySQL)
# 5432 (PostgreSQL)
# 6379 (Redis)
# 27017 (MongoDB)

# Testar padrão
mysql -h localhost -u root
mysql -h localhost -u root -p  # tenta sem senha
```

**3. Teste de Directory Listing:**

```bash
curl -I https://app.com/uploads/
# Se retorna listagem de arquivos → BAD

# Desabilitar (Apache):
<Directory /var/www/html/uploads>
    Options -Indexes
</Directory>
```

### 📚 Referências

- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

---

## A06 - Vulnerable and Outdated Components {#a06-vulnerable-and-outdated-components}

### 📌 Explicação Simples

Usar **componentes/bibliotecas com vulnerabilidades conhecidas**.

Exemplo:
- jQuery 1.8 tem XSS
- Log4j 2.14 tem RCE crítica
- Apache Struts 2 tem RCE

### 🔧 Explicação Técnica

**Por que é Crítico:**

```
Desenvolver código seguro: DIFÍCIL
Explorar CVE conhecida em dependência: FÁCIL

Exemplo - Log4j RCE (CVE-2021-44228):
1. Dependência: log4j 2.14.1
2. Exploit público: 1 linha de código
3. Impacto: RCE em qualquer servidor usando log4j

Solução: Atualizar para log4j 2.17.0+
```

### 💡 Como Gerenciar

**1. Inventário de Dependências (SBOM):**

```bash
# Node.js
npm list  # Listar todas as dependências

# Python
pip list
pip list --outdated

# Java
mvn dependency:list
gradle dependencies

# Ver dados sensíveis em deps
npm audit  # Encontra vulnerabilidades
```

**2. Scanning Automatizado:**

```bash
# Snyk
snyk test
snyk monitor

# OWASP Dependency-Check
dependency-check --scan .

# Trivy (containers)
trivy scan .

# Renovate (GitHub)
# Cria PRs automaticamente para atualizar deps
```

**3. Exemplo: Atualizar Vulnerabilidade**

```bash
# Antes
npm list log4j
# log4j@2.14.1 (VULNERÁVEL)

# Depois
npm install log4j@2.17.0
# log4j@2.17.0 (SEGURO)

# Verificar se funciona
npm test
```

### 📚 Checklist

```
[ ] Listar todas as dependências (incluindo transitive)
[ ] Verificar versões (npm outdated, snyk test)
[ ] Buscar CVEs (snyk, OSV, NVD)
[ ] Atualizar com segurança (testar antes de prod)
[ ] Monitorar continuamente (renovate, dependabot)
[ ] Remover dependências não usadas
[ ] Usar versões exatas, não ranges (npm install --save-exact)
```

---

## A07 - Authentication Failures {#a07-authentication-failures}

### 📌 Explicação Simples

**Falhas de Autenticação** = não conseguir validar quem você é.

Exemplos:
- Brute force de senha
- Sessão não expirada
- Resetar senha fácil demais
- Sem MFA

### 💡 Exemplo Prático

**Brute Force de Login:**

```bash
# Ferramentas
hydra -l admin -P rockyou.txt http-post-form://app.com/login:username=^USER^&password=^PASS^
medusa -h app.com -u admin -P rockyou.txt -M http

# Proteção:
[ ] Rate limiting (máx 5 tentativas/5min por IP)
[ ] Account lockout (temporário após falhas)
[ ] CAPTCHA após 3 falhas
[ ] MFA (2FA)
[ ] Monitorar padrões de login anormais
```

---

## A08 - Software and Data Integrity Failures {#a08-software-and-data-integrity-failures}

### 📌 Explicação Simples

Não garantir que **software/dados não foram modificados**.

Exemplos:
- Update sem assinatura
- Dados sem integridade
- Dependências de fonte não confiável

---

## A09 - Logging and Monitoring Failures {#a09-logging-and-monitoring-failures}

### 📌 Explicação Simples

Não **logar eventos** importantes ou não conseguir detectar ataques.

Exemplo:
- Sem logs de login
- Logs sem timestamp
- Alertas não configurados

---

## A10 - Server-Side Request Forgery (SSRF) {#a10-ssrf}

### 📌 Explicação Simples

Fazer o **servidor fazer requisição para lugar que não deveria**.

Exemplo:
```
App faz: fetch(user_provided_url)
Usuário envia: http://internal-api:8080/admin
Resultado: Acesso a sistema interno!
```

### 🔧 Como Defender

```python
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    # Validar URL
    try:
        parsed = urlparse(url)
    except:
        return False

    # Validar scheme
    if parsed.scheme not in ('http', 'https'):
        return False

    # Validar hostname (evitar internal IPs)
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        # Bloquear IPs locais
        if ip.is_private or ip.is_loopback:
            return False
    except:
        pass

    # Whitelist de dominios
    ALLOWED = ['api.example.com', 'cdn.example.com']
    if parsed.hostname not in ALLOWED:
        return False

    return True

@app.route('/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url')

    if not is_safe_url(url):
        return {"error": "Invalid URL"}, 400

    response = requests.get(url, timeout=5)
    return response.json()
```

---

## 📊 Tabela Resumo - OWASP Top 10

| # | Vulnerabilidade | Cause | Impact | Mitigation |
|---|-----------------|-------|--------|-----------|
| **A01** | Broken Access Control | Falta validação | Acesso indevido | RBAC, validação ownership |
| **A02** | Cryptographic Failures | Dados sem encrypt | Exposição | HTTPS, hash seguro |
| **A03** | Injection | Input não validado | RCE, data breach | Prepared statements |
| **A04** | Insecure Design | Arquitetura fraca | Bypass lógica | STRIDE, threat model |
| **A05** | Misconfiguration | Defaults inseguros | Vários | Hardening, auditoria |
| **A06** | Vulnerable Components | Deps desatualizadas | RCE | SCA, scanning |
| **A07** | Auth Failures | Senhas fracas | Bypass | MFA, rate limit |
| **A08** | Data Integrity | Sem assinatura | Modificação | Assinatura, HMAC |
| **A09** | Logging Failures | Sem monitoramento | Detecção fraca | SIEM, alertas |
| **A10** | SSRF | URL não validada | Acesso interno | URL whitelist |

---

## 🎯 Próximos Passos

1. **Praticar**: DVWA, WebGoat, Juice Shop
2. **Automatizar**: SAST/DAST em CI/CD
3. **Documentar**: Criar checklist próprio
4. **Certificar**: CEH, OSCP, eJPT

---

<div align="center">

**⭐ Comece testando uma vulnerabilidade por vez**

**Segurança web é aprendizado contínuo**

</div>
