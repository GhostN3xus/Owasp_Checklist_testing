# 🔐 Guia Completo de Validação de Dados em C#/.NET

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

```csharp
// ❌ INSEGURO - Regex muito simples
private static readonly string SimpleEmailRegex = @".+@.+";

// ✅ SEGURO - RFC 5322 simplificado
public class EmailValidator
{
    private static readonly Regex EmailPattern = new Regex(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static string ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email não pode estar vazio");

        if (email.Length > 254)
            throw new ArgumentException("Email muito longo");

        if (!EmailPattern.IsMatch(email))
            throw new ArgumentException("Email inválido");

        return email.ToLower();
    }
}

// ✅ MELHOR - System.ComponentModel.DataAnnotations
using System.ComponentModel.DataAnnotations;

public class User
{
    [EmailAddress(ErrorMessage = "Email deve ser válido")]
    [Required(ErrorMessage = "Email é obrigatório")]
    public string Email { get; set; }
}

// ✅ MELHOR - FluentValidation
using FluentValidation;

public class UserValidator : AbstractValidator<User>
{
    public UserValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email é obrigatório")
            .EmailAddress().WithMessage("Email inválido");
    }
}

// ✅ MELHOR - Usar MailAddress
public static bool IsValidEmail(string email)
{
    try
    {
        var address = new System.Net.Mail.MailAddress(email);
        return address.Address == email;
    }
    catch
    {
        return false;
    }
}
```

**Checklist SAST:**
- [ ] Usar [EmailAddress] attribute
- [ ] Tamanho máximo limitado (254 caracteres)
- [ ] Validação ocorre no backend
- [ ] Considerar usar FluentValidation

---

### 2. Validação de URLs

**Ponto SAST:** Garantir que URLs externas não causem SSRF

```csharp
// ❌ INSEGURO
public class UrlValidator
{
    public static Uri ParseUrl(string url)
    {
        return new Uri(url);
    }
}

// ✅ SEGURO - Com whitelist
public class SecureUrlValidator
{
    private static readonly HashSet<string> AllowedDomains = new()
    {
        "example.com",
        "trusted.com"
    };

    public static Uri ValidateRedirectUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new ArgumentException("URL inválida");

        // Validar protocolo
        if (uri.Scheme != "http" && uri.Scheme != "https")
            throw new ArgumentException("Protocolo não permitido");

        // Validar domínio contra whitelist
        if (!AllowedDomains.Contains(uri.Host))
            throw new ArgumentException("Domínio não permitido");

        return uri;
    }
}

// ✅ MELHOR - Prevenir SSRF
public class SsrfSafeUrlValidator
{
    public static Uri ValidateUrlSsrfSafe(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new ArgumentException("URL inválida");

        // Validar protocolo
        if (uri.Scheme != "http" && uri.Scheme != "https")
            throw new ArgumentException("Protocolo deve ser http ou https");

        // Verificar se é localhost ou IP privado
        var hostname = uri.Host;

        if (hostname == "localhost" || hostname == "127.0.0.1")
            throw new ArgumentException("Redirecionamento local não permitido");

        // Resolver hostname
        try
        {
            var addresses = System.Net.Dns.GetHostAddresses(hostname);

            foreach (var address in addresses)
            {
                // Verificar IP privado
                if (IsPrivateIpAddress(address))
                    throw new ArgumentException("IP privado detectado - SSRF bloqueado");
            }
        }
        catch (System.Net.Sockets.SocketException)
        {
            throw new ArgumentException("Hostname não pode ser resolvido");
        }

        return uri;
    }

    private static bool IsPrivateIpAddress(System.Net.IPAddress address)
    {
        if (address.IsLoopback || address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return true;

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var octets = address.GetAddressBytes();
            return octets[0] == 10 ||
                   octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 ||
                   octets[0] == 192 && octets[1] == 168;
        }

        return false;
    }
}
```

**Checklist SAST:**
- [ ] Usar Uri.TryCreate() para validação
- [ ] Whitelist de domínios validado
- [ ] Protocolos http/https apenas
- [ ] IsPrivateIpAddress() verificado

---

### 3. Validação de Números

**Ponto SAST:** Evitar overflow e injection

```csharp
// ❌ INSEGURO
public class AmountValidator
{
    public static double ParseAmount(string amount)
    {
        return double.Parse(amount);
    }
}

// ✅ SEGURO - Validação completa
public class SecureAmountValidator
{
    private const decimal MaxAmount = 999999.99m;
    private const decimal MinAmount = 0m;

    public static decimal ValidateAmount(string amount)
    {
        if (!decimal.TryParse(amount, out var num))
            throw new ArgumentException("Deve ser um número válido");

        // Validar range
        if (num < MinAmount || num > MaxAmount)
            throw new ArgumentException("Valor fora do range permitido");

        // Validar casas decimais
        var decimalPlaces = BitConverter.GetBytes(decimal.GetBits(num)[3])[2];
        if (decimalPlaces > 2)
            throw new ArgumentException("Máximo 2 casas decimais");

        return Math.Round(num, 2);
    }
}

// ✅ MELHOR - Data Annotations
using System.ComponentModel.DataAnnotations;

public class Order
{
    [Range(0.00, 999999.99, ErrorMessage = "Valor deve estar entre 0 e 999999.99")]
    public decimal Total { get; set; }
}

// ✅ MELHOR - FluentValidation
public class OrderValidator : AbstractValidator<Order>
{
    public OrderValidator()
    {
        RuleFor(x => x.Total)
            .NotNull().WithMessage("Total é obrigatório")
            .GreaterThan(0).WithMessage("Total deve ser maior que 0")
            .LessThanOrEqualTo(999999.99m).WithMessage("Total muito alto")
            .PrecisionScale(8, 2, true).WithMessage("Máximo 2 casas decimais");
    }
}
```

**Checklist SAST:**
- [ ] Usar decimal para valores monetários
- [ ] TryParse() em vez de Parse()
- [ ] [Range] attribute para validação
- [ ] Casas decimais controladas

---

### 4. Validação de Strings

**Ponto SAST:** Prevenir injection, XSS

```csharp
// ❌ INSEGURO
public class UserService
{
    public void SaveUserBio(string bio)
    {
        // Aceita qualquer valor
        _userRepository.Update(bio);
    }
}

// ✅ SEGURO - Validações específicas
public class BioValidator
{
    private const int MaxLength = 500;
    private static readonly Regex DangerousPattern = new(
        @"<script|javascript:|onclick|<iframe|<embed|<object",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static string ValidateBio(string bio)
    {
        if (string.IsNullOrWhiteSpace(bio))
            throw new ArgumentException("Bio não pode estar vazia");

        if (bio.Length > MaxLength)
            throw new ArgumentException("Bio muito longa");

        if (DangerousPattern.IsMatch(bio))
            throw new ArgumentException("Bio contém conteúdo perigoso");

        return bio.Trim();
    }
}

// ✅ MELHOR - Data Annotations
[StringLength(500, MinimumLength = 1,
    ErrorMessage = "Bio deve ter entre 1 e 500 caracteres")]
public string Bio { get; set; }

// ✅ MELHOR - FluentValidation
public class UserProfileValidator : AbstractValidator<UserProfile>
{
    public UserProfileValidator()
    {
        RuleFor(x => x.Bio)
            .NotEmpty().WithMessage("Bio não pode estar vazia")
            .MaximumLength(500).WithMessage("Bio não pode ter mais de 500 caracteres")
            .Must(b => !Regex.IsMatch(b, @"<script|javascript:", RegexOptions.IgnoreCase))
            .WithMessage("Bio contém conteúdo perigoso");
    }
}
```

**Checklist SAST:**
- [ ] String.IsNullOrWhiteSpace() verificado
- [ ] Tamanho máximo definido
- [ ] Regex para caracteres perigosos
- [ ] Usar Data Annotations

---

### 5. Validação de Enums/Valores Permitidos

**Ponto SAST:** Garantir apenas valores esperados

```csharp
// ❌ INSEGURO
public class OrderService
{
    public void UpdateStatus(string status)
    {
        // Aceita qualquer valor!
        _orderRepository.Update(status);
    }
}

// ✅ SEGURO - Enum C#
public enum OrderStatus
{
    Pending,
    Approved,
    Rejected
}

public class Order
{
    public OrderStatus Status { get; set; }
}

// ✅ MELHOR - Validar enum
public static OrderStatus ParseStatus(string status)
{
    if (!Enum.TryParse<OrderStatus>(status, ignoreCase: true, out var result))
        throw new ArgumentException($"Status inválido: {status}");

    return result;
}

// ✅ MELHOR - Model binding com validação
[HttpPost]
public IActionResult UpdateStatus([FromBody] UpdateOrderRequest request)
{
    if (!Enum.IsDefined(typeof(OrderStatus), request.Status))
        return BadRequest("Status inválido");

    // Processar
}

// ✅ MELHOR - FluentValidation
public class UpdateOrderValidator : AbstractValidator<UpdateOrderRequest>
{
    public UpdateOrderValidator()
    {
        RuleFor(x => x.Status)
            .NotNull()
            .IsInEnum().WithMessage("Status inválido");
    }
}
```

**Checklist SAST:**
- [ ] Enum C# definido
- [ ] Enum.TryParse() com validação
- [ ] IsInEnum() em FluentValidation
- [ ] Testes com valores inválidos

---

### 6. Validação de Arquivos

**Ponto SAST:** Prevenir upload malicioso

```csharp
// ❌ INSEGURO
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    var path = Path.Combine("uploads", file.FileName);
    using (var stream = new FileStream(path, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }
    return Ok();
}

// ✅ SEGURO - Validação completa
public class FileUploadValidator
{
    private static readonly HashSet<string> AllowedMimes = new()
    {
        "image/jpeg", "image/png", "application/pdf"
    };
    private const long MaxSize = 5L * 1024 * 1024; // 5MB

    public static void ValidateFile(IFormFile file)
    {
        if (file == null || file.Length == 0)
            throw new ArgumentException("Arquivo não fornecido");

        // Validar MIME type
        if (!AllowedMimes.Contains(file.ContentType))
            throw new ArgumentException($"Tipo não permitido: {file.ContentType}");

        // Validar tamanho
        if (file.Length > MaxSize)
            throw new ArgumentException("Arquivo muito grande");

        // Validar nome - path traversal
        var filename = Path.GetFileName(file.FileName);
        if (string.IsNullOrEmpty(filename) || filename.Contains(".."))
            throw new ArgumentException("Nome de arquivo inválido");
    }
}

// ✅ MELHOR - Usar UUID
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    FileUploadValidator.ValidateFile(file);

    // Gerar UUID como nome
    var ext = Path.GetExtension(file.FileName);
    var newFilename = $"{Guid.NewGuid()}{ext}";

    var uploadPath = Path.Combine(_uploadDir, newFilename);

    using (var stream = new FileStream(uploadPath, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }

    return Ok(new { filename = newFilename });
}

// ✅ MELHOR - Verificar magic bytes
using System.IO;

public static class MagicBytesValidator
{
    private static readonly Dictionary<string, byte[]> MagicNumbers = new()
    {
        { "JPEG", new byte[] { 0xFF, 0xD8, 0xFF } },
        { "PNG", new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
        { "PDF", new byte[] { 0x25, 0x50, 0x44, 0x46 } }
    };

    public static void ValidateMagicBytes(IFormFile file)
    {
        using var stream = file.OpenReadStream();
        var buffer = new byte[4];
        stream.Read(buffer, 0, buffer.Length);

        bool isValid = MagicNumbers.Values.Any(magic =>
            buffer.Take(magic.Length).SequenceEqual(magic)
        );

        if (!isValid)
            throw new ArgumentException("Tipo de arquivo inválido (conteúdo)");
    }
}
```

**Checklist SAST:**
- [ ] Validar IFormFile.Length > 0
- [ ] Verificar ContentType
- [ ] Tamanho do arquivo limitado
- [ ] Magic bytes verificados
- [ ] Nome do arquivo sanitizado
- [ ] Path.GetFileName() usado

---

### 7. Validação de Autenticação/Tokens

**Ponto SAST:** Validar JWT

```csharp
// ❌ INSEGURO
public class TokenValidator
{
    public static ClaimsPrincipal VerifyToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        return handler.ValidateToken(token, new TokenValidationParameters(), out var _);
    }
}

// ✅ SEGURO - Validação completa
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;

public class JwtTokenValidator
{
    private readonly string _secret = Environment.GetEnvironmentVariable("JWT_SECRET");

    public ClaimsPrincipal ValidateToken(string tokenString)
    {
        if (string.IsNullOrEmpty(tokenString))
            throw new ArgumentException("Token não fornecido");

        // Remover prefixo Bearer
        if (tokenString.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            tokenString = tokenString.Substring(7);

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);

            var principal = handler.ValidateToken(tokenString, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = "my-app",
                ValidateAudience = true,
                ValidAudience = "my-app",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            // Validar claims obrigatórios
            if (!principal.HasClaim(c => c.Type == "userId"))
                throw new SecurityTokenException("Token incompleto");

            return principal;
        }
        catch (SecurityTokenException ex)
        {
            throw new ArgumentException($"Token inválido: {ex.Message}");
        }
    }

    public string CreateToken(string userId)
    {
        var key = Encoding.ASCII.GetBytes(_secret);
        var handler = new JwtSecurityTokenHandler();

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("userId", userId)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = "my-app",
            Audience = "my-app",
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = handler.CreateToken(descriptor);
        return handler.WriteToken(token);
    }
}

// ✅ MELHOR - ASP.NET Core Authentication
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)),
            ValidateIssuer = true,
            ValidIssuer = "my-app",
            ValidateAudience = true,
            ValidAudience = "my-app",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

// ✅ MELHOR - Usar em controller
[Authorize]
[HttpGet("protected")]
public IActionResult Protected()
{
    var userId = User.FindFirst("userId")?.Value;
    return Ok(new { userId });
}
```

**Checklist SAST:**
- [ ] JWT ValidateLifetime = true
- [ ] ValidIssuer e ValidAudience definidos
- [ ] IssuerSigningKey verificado
- [ ] Claims obrigatórios verificados
- [ ] Usar ASP.NET Core Authentication
- [ ] Teste com tokens expirados/inválidos

---

## Sanitização e Limpeza

### HTML Escaping

```csharp
// ❌ INSEGURO
public string DisplayComment(string comment)
{
    return $"<p>{comment}</p>";  // XSS!
}

// ✅ SEGURO - WebUtility
using System.Web;

public string EscapeHtml(string text)
{
    return WebUtility.HtmlEncode(text);
}

// ✅ MELHOR - AngleSharp
using AngleSharp;

public string SanitizeHtml(string html)
{
    var sanitizer = new HtmlSanitizer();
    return sanitizer.Sanitize(html);
}

// ✅ MELHOR - Razor Pages/MVC
// Por padrão, Razor Pages escapa HTML:
<p>@Model.Comment</p>  <!-- escapado automaticamente -->
<p>@Html.Raw(Model.Comment)</p>  <!-- não escapado, cuidado! -->
```

### SQL Query Parameterization

```csharp
// ❌ INSEGURO - SQL Injection
public User GetUserById(int id)
{
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand($"SELECT * FROM users WHERE id = {id}", connection);
    // SQL Injection!
    return command.ExecuteReader();
}

// ✅ SEGURO - Parameterized queries
public User GetUserById(int id)
{
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand("SELECT * FROM users WHERE id = @id", connection);
    command.Parameters.AddWithValue("@id", id);

    connection.Open();
    using var reader = command.ExecuteReader();
    // Processar resultado
}

// ✅ MELHOR - Entity Framework Core
public User GetUserById(int id)
{
    return _context.Users.FirstOrDefault(u => u.Id == id);
}

// ✅ MELHOR - Dapper
public User GetUserById(int id)
{
    using var connection = new SqlConnection(_connectionString);
    return connection.QueryFirstOrDefault<User>(
        "SELECT * FROM users WHERE id = @id",
        new { id }
    );
}
```

---

## Bibliotecas Recomendadas

### 1. **FluentValidation**

```bash
dotnet add package FluentValidation
```

```csharp
public class UserValidator : AbstractValidator<User>
{
    public UserValidator()
    {
        RuleFor(x => x.Email).EmailAddress();
        RuleFor(x => x.Age).InclusiveBetween(0, 120);
    }
}
```

### 2. **System.ComponentModel.DataAnnotations**

```csharp
[EmailAddress]
[StringLength(500)]
public string Email { get; set; }
```

### 3. **AngleSharp**

```bash
dotnet add package AngleSharp
```

```csharp
var sanitizer = new HtmlSanitizer();
var clean = sanitizer.Sanitize(dirtyHtml);
```

### 4. **System.IdentityModel.Tokens.Jwt**

```bash
dotnet add package System.IdentityModel.Tokens.Jwt
```

---

## Testes de Segurança

```csharp
[TestClass]
public class ValidationSecurityTests
{
    [TestMethod]
    public void TestXSSPayloadsRejected()
    {
        var xssPayloads = new[]
        {
            "<script>alert('xss')</script>",
            "<img src=x onerror='alert(1)'>",
            "javascript:alert(1)"
        };

        foreach (var payload in xssPayloads)
        {
            Assert.ThrowsException<ArgumentException>(() => BioValidator.ValidateBio(payload));
        }
    }

    [TestMethod]
    public void TestEmailValidation()
    {
        Assert.IsNotNull(EmailValidator.ValidateEmail("user@example.com"));
        Assert.ThrowsException<ArgumentException>(() => EmailValidator.ValidateEmail("invalid"));
    }

    [DataTestMethod]
    [DataRow("-10")]
    [DataRow("1000000")]
    public void TestInvalidAmounts(string amount)
    {
        Assert.ThrowsException<ArgumentException>(() => AmountValidator.ValidateAmount(amount));
    }
}
```

---

## Checklist SAST

### Usando SonarAnalyzer

```bash
dotnet add package SonarAnalyzer.CSharp
```

### Checklist Manual

- [ ] Data Annotations em todas as classes
- [ ] FluentValidation para regras complexas
- [ ] Enum para valores permitidos
- [ ] Decimal para valores monetários
- [ ] WebUtility.HtmlEncode() para HTML
- [ ] Parameterized queries com Entity Framework
- [ ] JWT ValidateLifetime = true
- [ ] Testes com payloads maliciosos
- [ ] Rate limiting em endpoints críticos
- [ ] Logging de tentativas suspeitas

---

## Resumo

**Regras de Ouro:**
1. ✅ **Valide SEMPRE no backend**
2. ✅ **Use Data Annotations e FluentValidation**
3. ✅ **Entity Framework para prepared statements**
4. ✅ **WebUtility.HtmlEncode() para escaping**
5. ✅ **Registre tentativas suspeitas**
6. ✅ **Use enum para valores permitidos**
7. ✅ **Teste com payloads de ataque conhecidos**

