# 🔐 Guia Completo de Validação de Dados em JavaScript/TypeScript

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

Validação é o processo de confirmar que os dados recebidos:
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

```javascript
// ❌ INSEGURO - Regex muito simples
const simpleEmailRegex = /.+@.+/;

// ✅ SEGURO - RFC 5322 simplificado
const validEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
};

// ✅ MELHOR - Usando biblioteca
import validator from 'validator';

const validateEmail = (email) => {
  if (!validator.isEmail(email)) {
    throw new Error('Email inválido');
  }
  return email;
};

// ✅ TypeScript + Zod (Type-safe)
import { z } from 'zod';

const emailSchema = z.string().email().max(254);
const validatedEmail = emailSchema.parse(userInput);
```

**Checklist SAST:**
- [ ] Email validado com regex robusto ou biblioteca
- [ ] Tamanho máximo limitado (254 caracteres)
- [ ] Validação ocorre no backend
- [ ] Nenhuma confiança em validação frontend

---

### 2. Validação de URLs

**Ponto SAST:** Garantir que URLs externas não causem SSRF ou redirecionamentos maliciosos

```javascript
// ❌ INSEGURO
const parseUrl = (url) => new URL(url);

// ✅ SEGURO - Com whitelist
const isAllowedUrl = (url, allowedDomains) => {
  try {
    const parsedUrl = new URL(url);
    return allowedDomains.includes(parsedUrl.hostname);
  } catch {
    return false;
  }
};

// ✅ MELHOR - Usando Zod
import { z } from 'zod';

const urlSchema = z.string().url().refine(
  (url) => {
    const domain = new URL(url).hostname;
    return ['example.com', 'trusted.com'].includes(domain);
  },
  { message: 'Domínio não permitido' }
);

const validateRedirectUrl = (url) => {
  return urlSchema.parse(url);
};
```

**Checklist SAST:**
- [ ] URLs validadas com whitelist de domínios
- [ ] Protocolos permitidos definidos (https://, http://)
- [ ] Sem suporte a protocolos perigosos (javascript:, data:)
- [ ] Prevenção de SSRF testada

---

### 3. Validação de Números

**Ponto SAST:** Evitar ataques de overflow, injection de números e falhas de lógica

```javascript
// ❌ INSEGURO
const parseAmount = (amount) => parseFloat(amount);

// ✅ SEGURO - Validação completa
const validateAmount = (amount) => {
  const num = parseFloat(amount);

  // Validar tipo
  if (isNaN(num)) throw new Error('Deve ser um número');

  // Validar range
  if (num < 0 || num > 999999.99) throw new Error('Valor fora do range');

  // Validar casas decimais
  if (Math.round(num * 100) / 100 !== num) {
    throw new Error('Máximo 2 casas decimais');
  }

  return num;
};

// ✅ MELHOR - TypeScript + Zod
const amountSchema = z.number().min(0).max(999999.99);

const processPayment = (amount: unknown) => {
  const validated = amountSchema.parse(amount);
  return validated;
};
```

**Checklist SAST:**
- [ ] Números validados contra NaN
- [ ] Range de valores definido
- [ ] Casas decimais controladas
- [ ] Testes com valores extremos executados

---

### 4. Validação de Strings

**Ponto SAST:** Prevenir injection attacks, XSS e path traversal

```javascript
// ❌ INSEGURO - Aceita qualquer string
const saveUserBio = (bio) => {
  db.update({ bio });
};

// ✅ SEGURO - Validações específicas
const validateUserBio = (bio) => {
  // Tipo
  if (typeof bio !== 'string') throw new Error('Deve ser string');

  // Tamanho
  if (bio.length > 500) throw new Error('Bio muito longa');
  if (bio.length < 0) throw new Error('Bio vazia');

  // Caracteres perigosos
  const dangerousPatterns = /<script|javascript:|onclick|eval|/gi;
  if (dangerousPatterns.test(bio)) {
    throw new Error('Contém conteúdo perigoso');
  }

  return bio.trim();
};

// ✅ MELHOR - HTML escaping
import DOMPurify from 'dompurify';

const sanitizeBio = (bio) => {
  return DOMPurify.sanitize(bio, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong']
  });
};

// ✅ MELHOR - TypeScript + Zod
const bioSchema = z.string()
  .min(1)
  .max(500)
  .refine(
    (val) => !/<script|javascript:|onclick/i.test(val),
    { message: 'Contém tags perigosas' }
  );
```

**Checklist SAST:**
- [ ] Tamanho máximo definido
- [ ] Caracteres especiais validados
- [ ] HTML tags escapadas antes de exibir
- [ ] Expressões regulares testadas contra payloads conhecidos

---

### 5. Validação de Enums/Valores Permitidos

**Ponto SAST:** Garantir que apenas valores esperados sejam aceitos

```javascript
// ❌ INSEGURO - String desvalidada
const updateStatus = (status) => {
  db.update({ status }); // Aceita qualquer valor!
};

// ✅ SEGURO - Enum explícito
const STATUS = {
  PENDING: 'PENDING',
  APPROVED: 'APPROVED',
  REJECTED: 'REJECTED'
};

const validateStatus = (status) => {
  if (!Object.values(STATUS).includes(status)) {
    throw new Error(`Status inválido: ${status}`);
  }
  return status;
};

// ✅ MELHOR - TypeScript
enum OrderStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED'
}

const updateStatus = (status: OrderStatus) => {
  // TypeScript garante apenas valores válidos
  db.update({ status });
};

// ✅ MELHOR - Zod
const statusSchema = z.enum(['PENDING', 'APPROVED', 'REJECTED']);
```

**Checklist SAST:**
- [ ] Enum definido com valores permitidos
- [ ] Validação antes de usar em lógica crítica
- [ ] Nenhuma conversão implícita de strings para enum
- [ ] Testes com valores inválidos executados

---

### 6. Validação de Arquivos

**Ponto SAST:** Prevenir upload de arquivos maliciosos, path traversal

```javascript
// ❌ INSEGURO
const handleFileUpload = (file) => {
  fs.writeFileSync(file.name, file.data);
};

// ✅ SEGURO - Validação completa
const validateFile = (file, maxSize = 5 * 1024 * 1024) => {
  // Tipo
  const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!allowedMimes.includes(file.mimetype)) {
    throw new Error('Tipo de arquivo não permitido');
  }

  // Tamanho
  if (file.size > maxSize) {
    throw new Error('Arquivo muito grande');
  }

  // Nome (path traversal)
  const sanitizedName = file.name
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.\.\//g, '');

  if (sanitizedName.length === 0) {
    throw new Error('Nome de arquivo inválido');
  }

  return { ...file, name: sanitizedName };
};

// ✅ MELHOR - Gerar UUID para nome
import { v4 as uuidv4 } from 'uuid';

const handleFileUpload = (file) => {
  const validated = validateFile(file);
  const ext = validated.name.split('.').pop();
  const newName = `${uuidv4()}.${ext}`;
  fs.writeFileSync(`/uploads/${newName}`, validated.data);
  return newName;
};

// ✅ MELHOR - Magic bytes check
import FileType from 'file-type';

const validateFileContent = async (file) => {
  const fileType = await FileType.fromBuffer(file.data);

  if (!fileType || !['image/jpeg', 'image/png'].includes(fileType.mime)) {
    throw new Error('Tipo de arquivo inválido (conteúdo)');
  }

  return file;
};
```

**Checklist SAST:**
- [ ] MIME type validado
- [ ] Tamanho do arquivo limitado
- [ ] Magic bytes verificados
- [ ] Nome do arquivo sanitizado
- [ ] Path traversal testado
- [ ] Extensão de arquivo controlada

---

### 7. Validação de Autenticação/Tokens

**Ponto SAST:** Validar tokens JWT, sesões e credenciais

```javascript
// ❌ INSEGURO
const verifyToken = (token) => {
  return jwt.verify(token, process.env.SECRET); // Sem tratamento
};

// ✅ SEGURO - Com validação completa
const validateToken = (token) => {
  try {
    // Verificar tipo
    if (typeof token !== 'string' || !token.startsWith('Bearer ')) {
      throw new Error('Token inválido');
    }

    const actualToken = token.substring(7);

    // Verificar assinatura e expiração
    const decoded = jwt.verify(actualToken, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });

    // Validar claims necessários
    if (!decoded.userId || !decoded.iat) {
      throw new Error('Token incompleto');
    }

    // Validar expiração adicional
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp && decoded.exp < now) {
      throw new Error('Token expirado');
    }

    return decoded;
  } catch (error) {
    throw new Error('Token inválido: ' + error.message);
  }
};

// ✅ MELHOR - Usar biblioteca especializada
import { jwtVerify } from 'jose';

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET);

const validateTokenJose = async (token) => {
  try {
    const verified = await jwtVerify(
      token.replace('Bearer ', ''),
      SECRET,
      {
        algorithms: ['HS256'],
        issuer: 'https://example.com',
        audience: 'app'
      }
    );
    return verified.payload;
  } catch (error) {
    throw new Error('Token inválido');
  }
};
```

**Checklist SAST:**
- [ ] JWT assinatura verificada
- [ ] Expiração validada
- [ ] Claims obrigatórios verificados
- [ ] Algoritmos permitidos limitados
- [ ] Teste com tokens expirados/inválidos
- [ ] Logout invalida tokens (revogação)

---

## Sanitização e Limpeza

### HTML Escaping

```javascript
// ❌ INSEGURO - XSS vulnerability
const displayComment = (comment) => {
  document.getElementById('comments').innerHTML = comment;
};

// ✅ SEGURO - Escape para HTML
const escapeHtml = (text) => {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
};

const displayComment = (comment) => {
  const safe = escapeHtml(comment);
  document.getElementById('comments').textContent = safe;
};

// ✅ MELHOR - Usar DOMPurify
import DOMPurify from 'dompurify';

const displayComment = (comment) => {
  const safe = DOMPurify.sanitize(comment);
  document.getElementById('comments').innerHTML = safe;
};
```

### SQL Query Parameterization

```javascript
// ❌ INSEGURO - SQL Injection
const getUserById = (id) => {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
};

// ✅ SEGURO - Prepared statements
const getUserById = (id) => {
  return db.query('SELECT * FROM users WHERE id = ?', [id]);
};

// ✅ MELHOR - Com validação
const getUserById = (id) => {
  const idSchema = z.number().int().positive();
  const validId = idSchema.parse(id);
  return db.query('SELECT * FROM users WHERE id = ?', [validId]);
};
```

---

## Bibliotecas Recomendadas

### 1. **Zod** - Schema validation

```bash
npm install zod
```

```typescript
import { z } from 'zod';

const userSchema = z.object({
  email: z.string().email(),
  age: z.number().min(0).max(120),
  role: z.enum(['user', 'admin'])
});

const validateUser = (data) => userSchema.parse(data);
```

### 2. **Joi** - Alternative validation

```bash
npm install joi
```

```javascript
const schema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required()
});

const { error, value } = schema.validate(data);
```

### 3. **Validator.js** - String validation

```bash
npm install validator
```

```javascript
import validator from 'validator';

validator.isEmail(email);
validator.isURL(url);
validator.isIP(ip);
validator.isStrongPassword(password);
```

### 4. **DOMPurify** - HTML sanitization

```bash
npm install dompurify
```

```javascript
import DOMPurify from 'dompurify';

const clean = DOMPurify.sanitize(userInput);
```

### 5. **yup** - Validation with async support

```bash
npm install yup
```

```javascript
const schema = yup.object().shape({
  email: yup.string().email().required(),
  username: yup.string()
    .required()
    .test('unique', 'Email já existe', async (value) => {
      return !(await checkEmailExists(value));
    })
});
```

---

## Testes de Segurança

### Teste de Payloads Comuns

```javascript
// Arquivo: validation.test.js
describe('Validação de dados', () => {

  describe('XSS Prevention', () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '<img src=x onerror="alert(1)">',
      'javascript:alert(1)',
      '<svg onload="alert(1)">'
    ];

    test('Deve rejeitar payloads XSS', () => {
      xssPayloads.forEach(payload => {
        expect(() => validateUserBio(payload)).toThrow();
      });
    });
  });

  describe('SQL Injection', () => {
    const sqlPayloads = [
      "' OR '1'='1",
      "1; DROP TABLE users;--",
      "admin'--"
    ];

    test('Deve usar prepared statements', () => {
      // Verificar código para prepared statements
      const code = fs.readFileSync('./db.js', 'utf8');
      expect(code).toContain('?');
      expect(code).not.toContain('`${');
    });
  });

  describe('Validação de Email', () => {
    test('Deve validar emails corretos', () => {
      expect(validateEmail('user@example.com')).toBe(true);
    });

    test('Deve rejeitar emails inválidos', () => {
      const invalid = [
        'invalid',
        'test@',
        '@example.com',
        'test@.com'
      ];
      invalid.forEach(email => {
        expect(() => validateEmail(email)).toThrow();
      });
    });
  });
});
```

---

## Checklist SAST

### Para SAST Automático

Use **Semgrep** para validar:

```yaml
# semgrep.yml
rules:
  - id: no-unvalidated-input
    patterns:
      - pattern-either:
          - pattern: $MODEL.create($INPUT)
          - pattern: db.query($QUERY)
    message: "Entrada não validada detectada"
    languages: [javascript]
    severity: HIGH

  - id: no-hardcoded-secrets
    patterns:
      - pattern-either:
          - pattern: const SECRET = "$STR"
          - pattern: password: "$STR"
    message: "Secret hardcoded detectado"
    languages: [javascript]
    severity: CRITICAL

  - id: sql-injection-risk
    patterns:
      - pattern-either:
          - pattern: `SELECT * FROM users WHERE id = ${...}`
          - pattern: query(`SELECT * FROM users WHERE id = ...`)
    message: "Possível SQL Injection"
    languages: [javascript]
    severity: HIGH
```

**Executar:**
```bash
semgrep --config semgrep.yml --json
```

### Checklist Manual

- [ ] Todas as entradas validadas no backend
- [ ] Whitelists usadas para enums e valores permitidos
- [ ] Emails validados com regex robusto
- [ ] URLs validadas com whitelist de domínios
- [ ] Números validados contra NaN e ranges
- [ ] Strings escapadas para HTML
- [ ] Arquivos validados (tipo, tamanho, conteúdo)
- [ ] Tokens JWT verificados corretamente
- [ ] Prepared statements usados em queries
- [ ] Mensagens de erro não expõem informações sensíveis
- [ ] Testes com payloads maliciosos executados
- [ ] Rate limiting implementado para endpoints críticos

---

## Resumo

**Regras de Ouro:**
1. ✅ **Valide SEMPRE no backend**
2. ✅ **Use whitelists, não blacklists**
3. ✅ **Implemente prepared statements**
4. ✅ **Escape output para o contexto correto**
5. ✅ **Registre tentativas suspeitas**
6. ✅ **Use bibliotecas estabelecidas**
7. ✅ **Teste com payloads de ataque conhecidos**

