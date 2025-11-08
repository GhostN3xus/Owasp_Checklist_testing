# 🔐 Guia Completo de Validação de Dados em PHP

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

```php
<?php

// ❌ INSEGURO - Regex muito simples
$simpleEmailRegex = '/.+@.+/';

// ✅ SEGURO - Usando filter_var
function validateEmail($email) {
    // Remover espaços
    $email = trim($email);

    // Validar tamanho
    if (strlen($email) > 254 || strlen($email) < 3) {
        throw new Exception('Email inválido: tamanho');
    }

    // Validar com filter_var
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Email inválido: formato');
    }

    return strtolower($email);
}

// ✅ MELHOR - Com validação de domínio
function validateEmailWithDomain($email) {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Email inválido');
    }

    // Verificar domínio resolvível (opcional)
    $domain = substr($email, strpos($email, '@') + 1);

    if (!checkdnsrr($domain, 'MX')) {
        throw new Exception('Domínio não existe');
    }

    return $email;
}

// ✅ MELHOR - Usando Symfony Validator
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Validation;

function validateEmailSymfony($email) {
    $validator = Validation::createValidator();

    $constraint = new Assert\Email();
    $violations = $validator->validate($email, $constraint);

    if (count($violations) > 0) {
        throw new Exception($violations[0]->getMessage());
    }

    return $email;
}
?>
```

**Checklist SAST:**
- [ ] Usar filter_var com FILTER_VALIDATE_EMAIL
- [ ] Validar tamanho máximo (254 caracteres)
- [ ] Validação ocorre no backend
- [ ] Opcional: validar domínio MX

---

### 2. Validação de URLs

**Ponto SAST:** Garantir que URLs externas não causem SSRF

```php
<?php

// ❌ INSEGURO
function parseUrl($url) {
    return parse_url($url);
}

// ✅ SEGURO - Com whitelist
function validateRedirectUrl($url, $allowedDomains) {
    // Validar formato
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        throw new Exception('URL inválida');
    }

    // Parse URL
    $parsed = parse_url($url);

    // Validar protocolo
    if (!in_array($parsed['scheme'] ?? '', ['http', 'https'])) {
        throw new Exception('Protocolo não permitido');
    }

    // Validar domínio contra whitelist
    if (!in_array($parsed['host'] ?? '', $allowedDomains)) {
        throw new Exception('Domínio não permitido');
    }

    return $url;
}

// ✅ MELHOR - Prevenir SSRF
function validateUrlSsrfSafe($url) {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        throw new Exception('URL inválida');
    }

    $parsed = parse_url($url);

    // Validar protocolo
    if (!in_array($parsed['scheme'] ?? '', ['http', 'https'])) {
        throw new Exception('Protocolo deve ser http ou https');
    }

    // Resolver hostname para verificar IP privado
    $host = $parsed['host'] ?? '';
    $ip = gethostbyname($host);

    // Verificar IP privado
    $privateRanges = [
        '127.0.0.1',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',
    ];

    foreach ($privateRanges as $range) {
        if (strpos($range, '/') !== false) {
            // CIDR check
            if (ipInRange($ip, $range)) {
                throw new Exception('IP privado detectado - SSRF bloqueado');
            }
        } elseif ($ip === $range) {
            throw new Exception('IP privado detectado - SSRF bloqueado');
        }
    }

    return $url;
}

// Função auxiliar para verificar IP em range CIDR
function ipInRange($ip, $range) {
    list($subnet, $bits) = explode('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) === $subnet;
}
?>
```

**Checklist SAST:**
- [ ] Usar filter_var com FILTER_VALIDATE_URL
- [ ] Whitelist de domínios validado
- [ ] Protocolos http/https apenas
- [ ] SSRF testado e prevenido

---

### 3. Validação de Números

**Ponto SAST:** Evitar overflow e injection

```php
<?php

// ❌ INSEGURO
function parseAmount($amount) {
    return floatval($amount);
}

// ✅ SEGURO - Validação completa
function validateAmount($amount) {
    // Validar tipo
    if (!is_numeric($amount)) {
        throw new Exception('Deve ser um número');
    }

    $num = floatval($amount);

    // Validar range
    if ($num < 0 || $num > 999999.99) {
        throw new Exception('Valor fora do range permitido');
    }

    // Validar casas decimais
    if (round($num, 2) != $num) {
        throw new Exception('Máximo 2 casas decimais');
    }

    return round($num, 2);
}

// ✅ MELHOR - Usar bcmath para precisão
function validateAmountBcmath($amount) {
    if (!is_numeric($amount)) {
        throw new Exception('Valor deve ser numérico');
    }

    // Usar bcmath para precisão
    $validated = bcadd($amount, 0, 2); // 2 casas decimais

    // Validar range
    if (bccomp($validated, 0) < 0 || bccomp($validated, '999999.99') > 0) {
        throw new Exception('Valor fora do range');
    }

    return $validated;
}

// ✅ MELHOR - Usando Symfony Validator
use Symfony\Component\Validator\Constraints as Assert;

function validateAmountSymfony($amount) {
    $constraint = new Assert\Type(['type' => 'numeric']);
    $constraint2 = new Assert\Range(['min' => 0, 'max' => 999999.99]);

    // Validar com múltiplas constraints
}
?>
```

**Checklist SAST:**
- [ ] Usar is_numeric() ou filter_var
- [ ] Usar bcmath para valores monetários
- [ ] Range de valores definido
- [ ] Casas decimais controladas

---

### 4. Validação de Strings

**Ponto SAST:** Prevenir injection, XSS, path traversal

```php
<?php

// ❌ INSEGURO
function saveUserBio($bio) {
    $this->db->update(['bio' => $bio]);
}

// ✅ SEGURO - Validações específicas
function validateUserBio($bio) {
    // Tipo
    if (!is_string($bio)) {
        throw new Exception('Bio deve ser string');
    }

    // Tamanho
    if (strlen($bio) > 500) {
        throw new Exception('Bio muito longa');
    }

    if (trim($bio) === '') {
        throw new Exception('Bio não pode estar vazia');
    }

    // Caracteres perigosos
    $dangerousPatterns = [
        '/<script/i',
        '/javascript:/i',
        '/onclick/i',
        '/<iframe/i',
        '/<embed/i',
        '/<object/i'
    ];

    foreach ($dangerousPatterns as $pattern) {
        if (preg_match($pattern, $bio)) {
            throw new Exception('Bio contém conteúdo perigoso');
        }
    }

    return trim($bio);
}

// ✅ MELHOR - HTML escape
function sanitizeBio($bio) {
    $validated = validateUserBio($bio);
    return htmlspecialchars($validated, ENT_QUOTES, 'UTF-8');
}

// ✅ MELHOR - Usando HTML Purifier
require_once 'HTML/Purifier.auto.php';

function sanitizeBioHtmlPurifier($bio) {
    $config = HTMLPurifier_Config::createDefault();
    $config->set('HTML.Allowed', 'b,i,em,strong');

    $purifier = new HTMLPurifier($config);
    return $purifier->purify($bio);
}
?>
```

**Checklist SAST:**
- [ ] is_string() verificado
- [ ] Tamanho máximo definido
- [ ] Regex para caracteres perigosos
- [ ] htmlspecialchars() usado antes de exibir

---

### 5. Validação de Enums/Valores Permitidos

**Ponto SAST:** Garantir apenas valores esperados

```php
<?php

// ❌ INSEGURO
function updateStatus($status) {
    $this->db->update(['status' => $status]);
}

// ✅ SEGURO - Enum explícito
const STATUS_VALID = ['PENDING', 'APPROVED', 'REJECTED'];

function validateStatus($status) {
    if (!in_array($status, STATUS_VALID, true)) {
        throw new Exception("Status inválido: $status");
    }
    return $status;
}

// ✅ MELHOR - Usar Enum (PHP 8.1+)
enum OrderStatus: string {
    case PENDING = 'PENDING';
    case APPROVED = 'APPROVED';
    case REJECTED = 'REJECTED';
}

function updateOrderStatus($status) {
    // Type hint garante apenas valores válidos
    // Sem necessidade de validação adicional
}

// Uso:
updateOrderStatus(OrderStatus::APPROVED);

// ✅ MELHOR - Classe com constantes
class OrderStatus {
    public const PENDING = 'PENDING';
    public const APPROVED = 'APPROVED';
    public const REJECTED = 'REJECTED';

    public static function validate($status) {
        $valid = [self::PENDING, self::APPROVED, self::REJECTED];
        if (!in_array($status, $valid, true)) {
            throw new Exception("Status inválido: $status");
        }
        return $status;
    }
}
?>
```

**Checklist SAST:**
- [ ] Constantes definidas para valores permitidos
- [ ] in_array() com strict mode (true)
- [ ] Usar Enum (PHP 8.1+) quando possível
- [ ] Testes com valores inválidos

---

### 6. Validação de Arquivos

**Ponto SAST:** Prevenir upload malicioso

```php
<?php

// ❌ INSEGURO
function handleFileUpload($file) {
    move_uploaded_file($file['tmp_name'], $_SERVER['DOCUMENT_ROOT'] . $file['name']);
}

// ✅ SEGURO - Validação completa
function validateFileUpload($file, $maxSize = 5*1024*1024) {
    // Tipo MIME
    $allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];

    if (!in_array($file['type'], $allowedMimes, true)) {
        throw new Exception("Tipo não permitido: {$file['type']}");
    }

    // Tamanho
    if ($file['size'] > $maxSize) {
        throw new Exception('Arquivo muito grande');
    }

    // Validar is_uploaded_file
    if (!is_uploaded_file($file['tmp_name'])) {
        throw new Exception('Arquivo não é upload válido');
    }

    // Nome - path traversal
    $basename = basename($file['name']);

    // Rejeitar path traversal
    if (strpos($basename, '..') !== false || strpos($basename, '/') !== false) {
        throw new Exception('Nome de arquivo inválido');
    }

    // Sanitizar nome
    $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $basename);

    if (empty($safeName)) {
        throw new Exception('Nome de arquivo vazio');
    }

    return ['tmp_name' => $file['tmp_name'], 'name' => $safeName];
}

// ✅ MELHOR - Usar UUID como nome
use Ramsey\Uuid\Uuid;

function saveUploadedFile($file, $uploadDir) {
    $validated = validateFileUpload($file);

    // Gerar UUID
    $ext = pathinfo($validated['name'], PATHINFO_EXTENSION);
    $newName = Uuid::uuid4() . '.' . $ext;

    $destination = $uploadDir . DIRECTORY_SEPARATOR . $newName;

    if (!move_uploaded_file($validated['tmp_name'], $destination)) {
        throw new Exception('Falha ao salvar arquivo');
    }

    return $newName;
}

// ✅ MELHOR - Magic bytes check
function validateFileMagicBytes($tmpFile, $expectedMimes) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $tmpFile);
    finfo_close($finfo);

    if (!in_array($mimeType, $expectedMimes, true)) {
        throw new Exception("Tipo de arquivo inválido: $mimeType");
    }

    return true;
}
?>
```

**Checklist SAST:**
- [ ] Validar com is_uploaded_file()
- [ ] Verificar MIME type com finfo
- [ ] Tamanho do arquivo limitado
- [ ] Magic bytes verificados
- [ ] Nome do arquivo sanitizado
- [ ] Path traversal testado

---

### 7. Validação de Autenticação/Tokens

**Ponto SAST:** Validar JWT e sessões

```php
<?php

// ❌ INSEGURO
function verifyToken($token) {
    $decoded = json_decode(base64_decode($token));
    return $decoded;
}

// ✅ SEGURO - Com validação completa
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function validateToken($tokenString) {
    // Validar tipo
    if (!is_string($tokenString) || empty($tokenString)) {
        throw new Exception('Token inválido');
    }

    // Remover prefixo Bearer
    if (strpos($tokenString, 'Bearer ') === 0) {
        $tokenString = substr($tokenString, 7);
    }

    try {
        // Verificar assinatura e expiração
        $decoded = JWT::decode(
            $tokenString,
            new Key($_ENV['JWT_SECRET'], 'HS256')
        );

        // Validar claims obrigatórios
        if (!isset($decoded->user_id) || !isset($decoded->iat)) {
            throw new Exception('Token incompleto');
        }

        // Validar expiração adicional
        if (isset($decoded->exp) && $decoded->exp < time()) {
            throw new Exception('Token expirado');
        }

        // Verificar se token foi revogado (Redis/Cache)
        if (isTokenRevoked($tokenString)) {
            throw new Exception('Token revogado');
        }

        return $decoded;

    } catch (Exception $e) {
        throw new Exception('Token inválido: ' . $e->getMessage());
    }
}

// ✅ MELHOR - Criar token seguro
function createSecureToken($userId) {
    $issuedAt = time();
    $expire = $issuedAt + (60 * 60); // 1 hora

    $payload = [
        'iat' => $issuedAt,
        'exp' => $expire,
        'user_id' => $userId,
        'iss' => 'my-app',
        'aud' => 'my-app'
    ];

    return JWT::encode(
        $payload,
        $_ENV['JWT_SECRET'],
        'HS256'
    );
}

// ✅ MELHOR - Middleware para proteger rotas
class AuthMiddleware {
    public static function verify() {
        $headers = getallheaders();

        if (!isset($headers['Authorization'])) {
            throw new Exception('Token não fornecido', 401);
        }

        try {
            return validateToken($headers['Authorization']);
        } catch (Exception $e) {
            throw new Exception('Não autorizado: ' . $e->getMessage(), 401);
        }
    }
}

// Uso em controller
public function protectedAction() {
    $user = AuthMiddleware::verify();
    return response(['user_id' => $user->user_id]);
}
?>
```

**Checklist SAST:**
- [ ] JWT assinatura verificada
- [ ] Expiração validada
- [ ] Claims obrigatórios verificados
- [ ] Usar biblioteca Firebase/JWT ou similar
- [ ] Tokens revogados no logout
- [ ] Teste com tokens expirados/inválidos

---

## Sanitização e Limpeza

### HTML Escaping

```php
<?php

// ❌ INSEGURO - XSS vulnerability
function displayComment($comment) {
    echo "<p>$comment</p>";  // XSS!
}

// ✅ SEGURO - htmlspecialchars
function escapeHtml($text) {
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

$comment = '<script>alert("xss")</script>';
echo '<p>' . escapeHtml($comment) . '</p>';

// ✅ MELHOR - Blade template (Laravel)
// Blade escapa automaticamente:
<p>{{ $comment }}</p>  <!-- automaticamente escapado -->

// ✅ MELHOR - Twig template
// {{ comment }}  <!-- escapado automaticamente -->
{# comment #}     <!-- não escapado -->

// ✅ MELHOR - HTML Purifier
require_once 'HTML/Purifier.auto.php';

function sanitizeHtml($html) {
    $config = HTMLPurifier_Config::createDefault();
    $config->set('HTML.Allowed', 'b,i,em,strong,a[href]');

    $purifier = new HTMLPurifier($config);
    return $purifier->purify($html);
}
?>
```

### SQL Query Parameterization

```php
<?php

// ❌ INSEGURO - SQL Injection
function getUserById($id) {
    return $this->db->query("SELECT * FROM users WHERE id = $id");
}

// ✅ SEGURO - Prepared statements (PDO)
function getUserById($id) {
    $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}

// ✅ SEGURO - Named placeholders
function getUserByEmail($email) {
    $stmt = $this->db->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->execute([':email' => $email]);
    return $stmt->fetch();
}

// ✅ MELHOR - Usando ORM (Eloquent/Doctrine)
// Laravel Eloquent
$user = User::where('id', $id)->first();

// Doctrine
$user = $this->entityManager
    ->getRepository(User::class)
    ->findOneBy(['id' => $id]);
?>
```

---

## Bibliotecas Recomendadas

### 1. **Symfony Validator**

```bash
composer require symfony/validator
```

```php
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints as Assert;

$validator = Validation::createValidator();

$constraint = new Assert\Collection([
    'email' => new Assert\Email(),
    'age' => new Assert\Range(['min' => 0, 'max' => 120]),
    'role' => new Assert\Choice(['choices' => ['user', 'admin']])
]);

$violations = $validator->validate($data, $constraint);

if (count($violations) > 0) {
    foreach ($violations as $violation) {
        echo $violation->getMessage();
    }
}
```

### 2. **Respect Validation**

```bash
composer require respect/validation
```

```php
use Respect\Validation\Validator as v;

v::email()->validate('email@example.com'); // true

v::stringType()
    ->length(1, 500)
    ->validate($bio); // true/false

v::intVal()
    ->between(0, 120)
    ->validate($age); // true/false
```

### 3. **Firebase JWT**

```bash
composer require firebase/php-jwt
```

```php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$token = JWT::encode($payload, $key, 'HS256');
$decoded = JWT::decode($token, new Key($key, 'HS256'));
```

### 4. **HTML Purifier**

```bash
composer require ezyang/htmlpurifier
```

```php
require_once 'HTML/Purifier.auto.php';

$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$clean_html = $purifier->purify($dirty_html);
```

### 5. **Ramsey UUID**

```bash
composer require ramsey/uuid
```

```php
use Ramsey\Uuid\Uuid;

$uuid = Uuid::uuid4();
echo $uuid->toString(); // e.g., 550e8400-e29b-41d4-a716-446655440000
```

---

## Testes de Segurança

### Teste de Payloads Comuns

```php
<?php
// arquivo: ValidationTest.php

use PHPUnit\Framework\TestCase;

class ValidationTest extends TestCase {

    public function testXSSPayloadsAreRejected() {
        $xssPayloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror="alert(1)">',
            'javascript:alert(1)',
            '<svg onload="alert(1)">'
        ];

        foreach ($xssPayloads as $payload) {
            $this->expectException(Exception::class);
            validateUserBio($payload);
        }
    }

    public function testSQLInjectionPayloads() {
        $sqlPayloads = [
            "' OR '1'='1",
            "1; DROP TABLE users;--",
            "admin'--"
        ];

        // Verificar que código usa prepared statements
        $reflection = new ReflectionMethod(UserRepository::class, 'findById');
        $code = file_get_contents($reflection->getFileName());

        $this->assertStringContainsString('?', $code);
        $this->assertStringNotContainsString('$id', $code);
    }

    public function testValidEmailAddresses() {
        $valid = [
            'user@example.com',
            'john.doe@company.co.uk',
            'test+tag@example.com'
        ];

        foreach ($valid as $email) {
            $this->assertNotEmpty(validateEmail($email));
        }
    }

    public function testInvalidEmailAddresses() {
        $invalid = [
            'invalid',
            'test@',
            '@example.com',
            str_repeat('a', 300) . '@example.com'
        ];

        foreach ($invalid as $email) {
            $this->expectException(Exception::class);
            validateEmail($email);
        }
    }
}
?>
```

---

## Checklist SAST

### Usando PHPStan

```bash
composer require --dev phpstan/phpstan
```

```bash
phpstan analyse src/
```

### Usando Psalm

```bash
composer require --dev vimeo/psalm
```

```bash
psalm src/
```

### Checklist Manual

- [ ] Todas as entradas validadas no backend
- [ ] Whitelists usadas para enums
- [ ] filter_var() usado para emails e URLs
- [ ] bcmath para valores monetários
- [ ] htmlspecialchars() ou HTML Purifier
- [ ] is_uploaded_file() verificado
- [ ] Prepared statements em todas as queries
- [ ] Mensagens de erro não expõem informações
- [ ] JWT verificado com Firebase/JWT
- [ ] Testes com payloads maliciosos
- [ ] Rate limiting em endpoints críticos
- [ ] Logging de tentativas suspeitas

---

## Resumo

**Regras de Ouro:**
1. ✅ **Valide SEMPRE no backend**
2. ✅ **Use whitelists, não blacklists**
3. ✅ **Implemente prepared statements**
4. ✅ **Escape output com htmlspecialchars()**
5. ✅ **Registre tentativas suspeitas**
6. ✅ **Use bibliotecas estabelecidas**
7. ✅ **Teste com payloads de ataque conhecidos**

