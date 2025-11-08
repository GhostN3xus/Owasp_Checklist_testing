# 🔐 Guia Completo de Validação de Dados em Python

## 📋 Índice

1. [Fundamentos de Validação](#fundamentos)
2. [Validações de Entrada](#validações-de-entrada)
3. [Sanitização e Limpeza](#sanitização-e-limpeza)
4. [Bibliotecas Recomendadas](#bibliotecas-recomendadas)
5. [Testes de Segurança](#testes-de-segurança)
6. [Checklist SAST](#checklist-sast)

---

## Fundamentos

### O que é Validação de Dados?

Validação é confirmar que dados recebidos:
- ✅ Estão no formato esperado
- ✅ Têm tamanho apropriado
- ✅ Não contêm payloads maliciosos
- ✅ Respeitam as regras de negócio

### Princípios Principais

```
1. Nunca confie em entrada do usuário
2. Valide sempre no backend
3. Use whitelists (não blacklists)
4. Registre tentativas suspeitas
5. Retorne erros genéricos ao cliente
```

---

## Validações de Entrada

### 1. Validação de Email

**Ponto SAST:** Verificar se emails são validados antes de serem usados

```python
# ❌ INSEGURO - Regex muito simples
import re
simple_email_regex = r".+@.+"

# ✅ SEGURO - RFC 5322 simplificado
import re

def validate_email(email):
    """Validação segura de email"""
    # Validar comprimento
    if not email or len(email) > 254 or len(email) < 3:
        raise ValueError("Email inválido: tamanho")

    # Validar formato
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        raise ValueError("Email inválido: formato")

    # Validar domínio resolvível (opcional)
    return email.lower()

# ✅ MELHOR - Usando biblioteca
from email_validator import validate_email, EmailNotValidError

def safe_validate_email(email):
    try:
        valid = validate_email(email)
        return valid.email
    except EmailNotValidError as e:
        raise ValueError(f"Email inválido: {str(e)}")

# ✅ MELHOR - Pydantic para type-safe
from pydantic import BaseModel, EmailStr

class User(BaseModel):
    email: EmailStr
    name: str

user = User(email="user@example.com", name="John")
```

**Checklist SAST:**
- [ ] Email validado com regex robusto ou biblioteca
- [ ] Tamanho máximo limitado (254 caracteres)
- [ ] Validação ocorre no backend
- [ ] Nenhuma confiança em validação frontend

---

### 2. Validação de URLs

**Ponto SAST:** Garantir que URLs externas não causem SSRF

```python
# ❌ INSEGURO
from urllib.parse import urlparse

def parse_url(url):
    return urlparse(url)

# ✅ SEGURO - Com whitelist
def validate_redirect_url(url, allowed_domains):
    """Validar URL de redirecionamento contra whitelist"""
    try:
        parsed = urlparse(url)

        # Validar protocolo
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Protocolo não permitido")

        # Validar domínio contra whitelist
        if parsed.netloc not in allowed_domains:
            raise ValueError(f"Domínio {parsed.netloc} não permitido")

        # Validar não é localhost (SSRF)
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            raise ValueError("Redirecionamento local não permitido")

        return url
    except Exception as e:
        raise ValueError(f"URL inválida: {str(e)}")

# ✅ MELHOR - Usando urllib3.util.url
from urllib.parse import urlparse
import socket

def validate_url_ssrf_safe(url):
    """Validar URL prevenindo SSRF"""
    parsed = urlparse(url)

    # Validar protocolo
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Protocolo deve ser http ou https")

    # Resolver hostname para verificar privado
    try:
        ip = socket.gethostbyname(parsed.hostname)

        # Verificar se é IP privado
        private_ips = [
            '127.0.0.1', '10.', '172.16.', '192.168.',
            '169.254.', '::1', 'localhost'
        ]

        if any(ip.startswith(range) for range in private_ips):
            raise ValueError("IP privado detectado - SSRF bloqueado")

    except socket.gaierror:
        raise ValueError("Hostname não pode ser resolvido")

    return url
```

**Checklist SAST:**
- [ ] URLs validadas com whitelist de domínios
- [ ] Protocolos permitidos (https://, http://)
- [ ] Sem protocolos perigosos (file://, ftp://)
- [ ] SSRF testado e prevenido

---

### 3. Validação de Números

**Ponto SAST:** Evitar overflow e injection

```python
# ❌ INSEGURO
def parse_amount(amount):
    return float(amount)

# ✅ SEGURO - Validação completa
from decimal import Decimal, InvalidOperation

def validate_amount(amount):
    """Validar montante monetário"""
    try:
        # Usar Decimal para valores monetários (evita floating point issues)
        num = Decimal(str(amount))

        # Validar range
        if num < 0 or num > Decimal('999999.99'):
            raise ValueError("Valor fora do range permitido")

        # Validar casas decimais
        if num.as_tuple().exponent < -2:
            raise ValueError("Máximo 2 casas decimais")

        return num
    except (InvalidOperation, ValueError) as e:
        raise ValueError(f"Montante inválido: {str(e)}")

# ✅ MELHOR - Pydantic
from pydantic import BaseModel, validator
from decimal import Decimal

class Payment(BaseModel):
    amount: Decimal

    @validator('amount')
    def validate_amount(cls, v):
        if v <= 0 or v > 999999.99:
            raise ValueError('Montante inválido')
        return round(v, 2)

# ✅ MELHOR - Field validation
from typing import Annotated
from pydantic import BaseModel, Field

class Order(BaseModel):
    total: Annotated[float, Field(gt=0, lt=999999.99)]
```

**Checklist SAST:**
- [ ] Usar Decimal para valores monetários
- [ ] Range de valores definido
- [ ] Casas decimais controladas
- [ ] Testes com valores extremos

---

### 4. Validação de Strings

**Ponto SAST:** Prevenir injection, XSS e path traversal

```python
# ❌ INSEGURO
def save_user_bio(bio):
    db.update(bio=bio)

# ✅ SEGURO - Validações específicas
import re

def validate_user_bio(bio):
    """Validar biografia do usuário"""
    # Tipo
    if not isinstance(bio, str):
        raise TypeError("Bio deve ser string")

    # Tamanho
    if len(bio) > 500:
        raise ValueError("Bio muito longa")

    if len(bio.strip()) == 0:
        raise ValueError("Bio não pode estar vazia")

    # Caracteres perigosos (HTML tags, scripts)
    dangerous_patterns = [
        r'<script', r'javascript:', r'onclick',
        r'<iframe', r'<embed', r'<object'
    ]

    bio_lower = bio.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, bio_lower):
            raise ValueError("Bio contém conteúdo perigoso")

    return bio.strip()

# ✅ MELHOR - HTML escape
import html

def sanitize_bio(bio):
    """Escapar HTML e validar"""
    validated = validate_user_bio(bio)
    return html.escape(validated)

# ✅ MELHOR - Pydantic
from pydantic import BaseModel, validator

class UserProfile(BaseModel):
    bio: str

    @validator('bio')
    def validate_bio(cls, v):
        if len(v) > 500:
            raise ValueError('Bio muito longa')

        # Rejeitar HTML tags
        if re.search(r'<[^>]+>', v):
            raise ValueError('Tags HTML não permitidas')

        return v.strip()
```

**Checklist SAST:**
- [ ] Tamanho máximo definido
- [ ] Caracteres especiais validados
- [ ] HTML tags escapadas
- [ ] Expressões regulares testadas

---

### 5. Validação de Enums/Valores Permitidos

**Ponto SAST:** Garantir apenas valores esperados

```python
# ❌ INSEGURO
def update_status(status):
    db.update(status=status)  # Aceita qualquer valor!

# ✅ SEGURO - Enum explícito
from enum import Enum

class OrderStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

def update_status(status):
    try:
        valid_status = OrderStatus(status)
        db.update(status=valid_status)
    except ValueError:
        raise ValueError(f"Status inválido: {status}")

# ✅ MELHOR - Pydantic
from pydantic import BaseModel, validator

class Order(BaseModel):
    status: OrderStatus

    @validator('status', pre=True)
    def validate_status(cls, v):
        if isinstance(v, OrderStatus):
            return v
        try:
            return OrderStatus(v)
        except ValueError:
            raise ValueError(f"Status inválido: {v}")

# ✅ MELHOR - Literal typing
from typing import Literal

def process_order(status: Literal["pending", "approved", "rejected"]):
    if status not in ["pending", "approved", "rejected"]:
        raise ValueError("Status inválido")
```

**Checklist SAST:**
- [ ] Enum definido com valores permitidos
- [ ] Validação antes de usar
- [ ] Nenhuma conversão implícita de strings
- [ ] Testes com valores inválidos

---

### 6. Validação de Arquivos

**Ponto SAST:** Prevenir upload malicioso

```python
# ❌ INSEGURO
import os
import uuid

def handle_file_upload(file, destination):
    file.save(destination)

# ✅ SEGURO - Validação completa
import os
import mimetypes
from pathlib import Path

def validate_file_upload(file, max_size=5*1024*1024):
    """Validar upload de arquivo"""

    # Tipo MIME
    allowed_mimes = {'image/jpeg', 'image/png', 'application/pdf'}
    if file.content_type not in allowed_mimes:
        raise ValueError(f"Tipo não permitido: {file.content_type}")

    # Tamanho
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    if file_size > max_size:
        raise ValueError("Arquivo muito grande")
    file.seek(0)

    # Nome (path traversal)
    filename = Path(file.filename)

    # Rejeitar path traversal
    if '..' in str(filename) or filename.is_absolute():
        raise ValueError("Nome de arquivo inválido")

    # Sanitizar nome
    safe_name = "".join(c for c in filename.name if c.isalnum() or c in '._-')
    if not safe_name:
        raise ValueError("Nome de arquivo vazio após sanitização")

    return file, safe_name

# ✅ MELHOR - Usar UUID
import uuid
from pathlib import Path

def save_uploaded_file(file, upload_dir):
    """Salvar arquivo com UUID"""

    validated_file, original_name = validate_file_upload(file)

    # Gerar UUID como nome
    ext = Path(original_name).suffix
    new_filename = f"{uuid.uuid4()}{ext}"

    # Salvar em diretório seguro
    safe_path = Path(upload_dir) / new_filename
    validated_file.save(safe_path)

    return new_filename

# ✅ MELHOR - Magic bytes check
import magic

def validate_file_magic_bytes(file_path):
    """Validar conteúdo do arquivo via magic bytes"""
    mime = magic.Magic(mime=True)
    detected_mime = mime.from_file(file_path)

    allowed_mimes = {'image/jpeg', 'image/png', 'application/pdf'}
    if detected_mime not in allowed_mimes:
        raise ValueError(f"Tipo de arquivo inválido (conteúdo): {detected_mime}")
```

**Checklist SAST:**
- [ ] MIME type validado
- [ ] Tamanho do arquivo limitado
- [ ] Magic bytes verificados
- [ ] Nome do arquivo sanitizado
- [ ] Path traversal testado
- [ ] Extensão controlada

---

### 7. Validação de Autenticação/Tokens

**Ponto SAST:** Validar JWT e sessões

```python
# ❌ INSEGURO
import jwt

def verify_token(token):
    return jwt.decode(token, 'secret', algorithms=['HS256'])

# ✅ SEGURO - Com validação completa
from datetime import datetime, timedelta
import jwt

def validate_token(token_string):
    """Validar JWT token"""

    # Validar tipo
    if not isinstance(token_string, str):
        raise ValueError("Token deve ser string")

    # Remover prefixo Bearer
    if token_string.startswith('Bearer '):
        token_string = token_string[7:]

    try:
        # Verificar assinatura e expiração
        payload = jwt.decode(
            token_string,
            key=os.getenv('JWT_SECRET'),
            algorithms=['HS256']  # Whitelist algoritmos!
        )

        # Validar claims obrigatórios
        if 'user_id' not in payload or 'iat' not in payload:
            raise ValueError("Token incompleto")

        # Validar não foi revogado (checklist em Redis)
        if is_token_revoked(token_string):
            raise ValueError("Token revogado")

        return payload

    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado")
    except jwt.InvalidSignatureError:
        raise ValueError("Assinatura inválida")
    except jwt.DecodeError:
        raise ValueError("Token inválido")

# ✅ MELHOR - PyJWT com validação completa
from datetime import datetime, timedelta
import jwt

def create_secure_token(user_id):
    """Criar token seguro"""
    payload = {
        'user_id': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iss': 'my-app',
        'aud': 'my-app'
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')

# ✅ MELHOR - Flask-JWT-Extended
from flask_jwt_extended import create_access_token, jwt_required

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(hours=1)
        )
        return {'access_token': access_token}

    raise ValueError("Credenciais inválidas")

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return {'user_id': current_user_id}
```

**Checklist SAST:**
- [ ] JWT assinatura verificada
- [ ] Expiração validada
- [ ] Claims obrigatórios verificados
- [ ] Algoritmos permitidos limitados
- [ ] Tokens revogados no logout
- [ ] Teste com tokens expirados/inválidos

---

## Sanitização e Limpeza

### HTML Escaping

```python
# ❌ INSEGURO
from jinja2 import Template

def display_comment(comment):
    template = Template("<p>{{ comment }}</p>")
    return template.render(comment=comment)  # Sem autoescape!

# ✅ SEGURO - HTML escape
import html

def escape_html(text):
    """Escapar caracteres HTML"""
    return html.escape(text)

comment = "<script>alert('xss')</script>"
safe = escape_html(comment)
print(safe)  # &lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;

# ✅ MELHOR - Jinja2 com autoescape
from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/comments/<comment>')
def show_comment(comment):
    # Jinja2 autoescape habilitado por padrão
    return render_template_string('<p>{{ comment }}</p>', comment=comment)

# ✅ MELHOR - Markupsafe
from markupsafe import escape

@app.route('/user/<username>')
def user_profile(username):
    safe_username = escape(username)
    return f"<h1>Bem-vindo {safe_username}</h1>"
```

### SQL Query Parameterization

```python
# ❌ INSEGURO - SQL Injection
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

# ✅ SEGURO - Prepared statements (ORM)
from sqlalchemy import text

def get_user_by_id(user_id):
    # SQLAlchemy com ORM (parameterizado automaticamente)
    user = db.session.query(User).filter(User.id == user_id).first()
    return user

# ✅ SEGURO - Raw SQL com placeholders
def get_user_by_email(email):
    query = text("SELECT * FROM users WHERE email = :email")
    result = db.execute(query, {"email": email})
    return result.fetchone()

# ✅ MELHOR - SQLAlchemy Core
from sqlalchemy import select

def get_user_by_username(username):
    stmt = select(User).where(User.username == username)
    user = db.session.execute(stmt).scalar()
    return user

# ❌ INSEGURO em SQLAlchemy
def bad_query(field, value):
    # NÃO FAZER ISTO!
    query = f"SELECT * FROM users WHERE {field} = '{value}'"

# ✅ SEGURO em SQLAlchemy
def safe_query(field, value):
    # Usar getattr ou mapping explícito
    valid_fields = {'email', 'username', 'id'}
    if field not in valid_fields:
        raise ValueError("Campo inválido")

    stmt = select(User).where(getattr(User, field) == value)
    return db.session.execute(stmt).scalar()
```

---

## Bibliotecas Recomendadas

### 1. **Pydantic** - Schema validation

```bash
pip install pydantic
```

```python
from pydantic import BaseModel, EmailStr, validator

class User(BaseModel):
    email: EmailStr
    age: int
    role: str

    @validator('age')
    def age_must_be_valid(cls, v):
        if v < 0 or v > 120:
            raise ValueError('Age must be between 0 and 120')
        return v

    @validator('role')
    def role_must_be_valid(cls, v):
        if v not in ['user', 'admin', 'moderator']:
            raise ValueError('Invalid role')
        return v
```

### 2. **Marshmallow** - Object serialization

```bash
pip install marshmallow
```

```python
from marshmallow import Schema, fields, validate, ValidationError

class UserSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8)
    )
    role = fields.Str(
        validate=validate.OneOf(['user', 'admin'])
    )

schema = UserSchema()
try:
    result = schema.load({"email": "test@example.com", "password": "secure123", "role": "user"})
except ValidationError as err:
    print(err.messages)
```

### 3. **email-validator** - Email validation

```bash
pip install email-validator
```

```python
from email_validator import validate_email, EmailNotValidError

def check_email(email):
    try:
        valid = validate_email(email)
        return valid.email
    except EmailNotValidError as e:
        raise ValueError(f"Email inválido: {str(e)}")
```

### 4. **bleach** - HTML sanitization

```bash
pip install bleach
```

```python
import bleach

def sanitize_html(html_content):
    """Permitir apenas tags seguras"""
    allowed_tags = ['b', 'i', 'em', 'strong']
    return bleach.clean(html_content, tags=allowed_tags, strip=True)
```

### 5. **python-magic** - File type detection

```bash
pip install python-magic
```

```python
import magic

def check_file_type(file_path):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    return file_type
```

---

## Testes de Segurança

### Teste de Payloads Comuns

```python
# arquivo: test_validation.py
import pytest
from validation import (
    validate_email,
    validate_user_bio,
    validate_amount,
    validate_file_upload
)

class TestXSSPrevention:
    xss_payloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror="alert(1)">',
        'javascript:alert(1)',
        '<svg onload="alert(1)">',
        '<iframe src="javascript:alert(1)"></iframe>'
    ]

    @pytest.mark.parametrize("payload", xss_payloads)
    def test_rejects_xss_payloads(self, payload):
        with pytest.raises(ValueError):
            validate_user_bio(payload)

class TestSQLInjection:
    sql_payloads = [
        "' OR '1'='1",
        "1; DROP TABLE users;--",
        "admin'--",
        "' UNION SELECT * FROM users;--"
    ]

    def test_uses_parameterized_queries(self):
        # Verificar código fonte
        with open('db.py', 'r') as f:
            code = f.read()

        # Deve usar ? ou :param
        assert '?' in code or ':' in code
        # Não deve usar f-strings em queries
        assert 'f"SELECT' not in code

class TestEmailValidation:
    def test_valid_emails(self):
        valid = [
            'user@example.com',
            'john.doe@company.co.uk',
            'test+tag@example.com'
        ]
        for email in valid:
            assert validate_email(email) == email.lower()

    def test_invalid_emails(self):
        invalid = [
            'invalid',
            'test@',
            '@example.com',
            'test @example.com',
            'a' * 250 + '@example.com'  # Too long
        ]
        for email in invalid:
            with pytest.raises(ValueError):
                validate_email(email)

class TestAmountValidation:
    def test_valid_amounts(self):
        valid = ['10.50', '100', '0.01']
        for amount in valid:
            result = validate_amount(amount)
            assert result > 0

    def test_invalid_amounts(self):
        invalid = ['-10', 'abc', '1000000.00', '10.123']
        for amount in invalid:
            with pytest.raises(ValueError):
                validate_amount(amount)

class TestFileUpload:
    def test_rejects_oversized_files(self, tmp_path):
        # Criar arquivo grande
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b'x' * (6 * 1024 * 1024))

        with pytest.raises(ValueError):
            validate_file_upload(large_file)

    def test_prevents_path_traversal(self):
        dangerous_names = [
            '../../../etc/passwd',
            '..\\..\\windows\\system32',
            '/etc/passwd',
            'C:\\Windows\\System32'
        ]

        for name in dangerous_names:
            # Não deve permitir
            with pytest.raises(ValueError):
                validate_filename(name)
```

---

## Checklist SAST

### Usando Bandit

```bash
pip install bandit semgrep
```

```bash
# Executar Bandit para detectar vulnerabilidades
bandit -r . -f json -o bandit-report.json

# Executar Semgrep
semgrep --config=p/security-audit -j4 --json -o semgrep-report.json
```

### Checklist Manual

- [ ] Todas as entradas validadas no backend
- [ ] Whitelists usadas para enums
- [ ] Emails validados com email-validator
- [ ] URLs validadas contra whitelist
- [ ] Números validados com Decimal
- [ ] HTML escapado antes de exibir
- [ ] Arquivos validados (tipo, tamanho, conteúdo)
- [ ] Tokens JWT verificados
- [ ] Prepared statements em todas as queries
- [ ] Mensagens de erro não expõem informações
- [ ] Testes com payloads maliciosos
- [ ] Rate limiting em endpoints críticos
- [ ] Logging de tentativas suspeitas

---

## Resumo

**Regras de Ouro:**
1. ✅ **Valide SEMPRE no backend**
2. ✅ **Use whitelists, não blacklists**
3. ✅ **Implemente prepared statements**
4. ✅ **Escape output para o contexto correto**
5. ✅ **Registre tentativas suspeitas**
6. ✅ **Use Pydantic/Marshmallow**
7. ✅ **Teste com payloads de ataque conhecidos**

