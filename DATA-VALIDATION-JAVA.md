# 🔐 Guia Completo de Validação de Dados em Java

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

```java
// ❌ INSEGURO - Regex muito simples
private static final String SIMPLE_EMAIL = ".*@.*";

// ✅ SEGURO - RFC 5322 simplificado
public class EmailValidator {
    private static final String EMAIL_PATTERN =
        "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";

    private static final Pattern pattern = Pattern.compile(EMAIL_PATTERN);

    public static String validateEmail(String email) throws ValidationException {
        if (email == null || email.isEmpty()) {
            throw new ValidationException("Email não pode estar vazio");
        }

        if (email.length() > 254) {
            throw new ValidationException("Email muito longo");
        }

        if (!pattern.matcher(email).matches()) {
            throw new ValidationException("Email inválido: formato");
        }

        return email.toLowerCase();
    }
}

// ✅ MELHOR - Jakarta Bean Validation (antiga javax.validation)
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class User {
    @Email(message = "Email deve ser válido")
    @NotBlank(message = "Email não pode estar vazio")
    private String email;

    // getter e setter
}

// ✅ MELHOR - Apache Commons Validator
import org.apache.commons.validator.routines.EmailValidator;

public class EmailUtil {
    private static final EmailValidator validator = EmailValidator.getInstance();

    public static void validateEmail(String email) throws ValidationException {
        if (!validator.isValid(email)) {
            throw new ValidationException("Email inválido");
        }
    }
}

// ✅ MELHOR - Spring Validator
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class UserValidator implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        User user = (User) target;

        ValidationUtils.rejectIfEmptyOrWhitespace(
            errors, "email", "email.required");

        if (!EmailValidator.getInstance().isValid(user.getEmail())) {
            errors.rejectValue("email", "email.invalid");
        }
    }
}
```

**Checklist SAST:**
- [ ] Email validado com regex robusto ou jakarta.validation
- [ ] Tamanho máximo limitado (254 caracteres)
- [ ] Validação ocorre no backend
- [ ] Usar anotações @Email em classes de modelo

---

### 2. Validação de URLs

**Ponto SAST:** Garantir que URLs externas não causem SSRF

```java
// ❌ INSEGURO
public class UrlValidator {
    public static URL parseUrl(String url) throws MalformedURLException {
        return new URL(url);
    }
}

// ✅ SEGURO - Com whitelist
public class SecureUrlValidator {
    private static final List<String> ALLOWED_DOMAINS = Arrays.asList(
        "example.com",
        "trusted.com"
    );

    public static URL validateRedirectUrl(String url) throws ValidationException {
        try {
            URL parsedUrl = new URL(url);

            // Validar protocolo
            if (!Arrays.asList("http", "https").contains(parsedUrl.getProtocol())) {
                throw new ValidationException("Protocolo não permitido");
            }

            // Validar domínio contra whitelist
            if (!ALLOWED_DOMAINS.contains(parsedUrl.getHost())) {
                throw new ValidationException("Domínio não permitido");
            }

            return parsedUrl;
        } catch (MalformedURLException e) {
            throw new ValidationException("URL inválida: " + e.getMessage());
        }
    }
}

// ✅ MELHOR - Prevenir SSRF
public class SsrfSafeUrlValidator {

    public static URL validateUrlSsrfSafe(String url) throws ValidationException {
        try {
            URL parsedUrl = new URL(url);

            // Validar protocolo
            String protocol = parsedUrl.getProtocol();
            if (!Arrays.asList("http", "https").contains(protocol)) {
                throw new ValidationException("Protocolo deve ser http ou https");
            }

            // Resolver hostname para verificar IP privado
            String host = parsedUrl.getHost();
            InetAddress address = InetAddress.getByName(host);
            String ip = address.getHostAddress();

            // Verificar IP privado
            if (address.isLoopbackAddress() ||
                address.isPrivateAddress() ||
                address.isLinkLocalAddress()) {
                throw new ValidationException("IP privado detectado - SSRF bloqueado");
            }

            return parsedUrl;
        } catch (MalformedURLException | UnknownHostException e) {
            throw new ValidationException("URL inválida: " + e.getMessage());
        }
    }
}
```

**Checklist SAST:**
- [ ] URLs validadas com whitelist de domínios
- [ ] Protocolos permitidos (https://, http://)
- [ ] InetAddress.isPrivateAddress() verificado
- [ ] SSRF testado e prevenido

---

### 3. Validação de Números

**Ponto SAST:** Evitar overflow e injection

```java
// ❌ INSEGURO
public class AmountValidator {
    public static double parseAmount(String amount) {
        return Double.parseDouble(amount);
    }
}

// ✅ SEGURO - Validação completa
public class SecureAmountValidator {
    private static final BigDecimal MAX_AMOUNT = new BigDecimal("999999.99");
    private static final BigDecimal MIN_AMOUNT = BigDecimal.ZERO;

    public static BigDecimal validateAmount(String amount) throws ValidationException {
        try {
            BigDecimal num = new BigDecimal(amount);

            // Validar range
            if (num.compareTo(MIN_AMOUNT) < 0 || num.compareTo(MAX_AMOUNT) > 0) {
                throw new ValidationException("Valor fora do range permitido");
            }

            // Validar casas decimais
            if (num.scale() > 2) {
                throw new ValidationException("Máximo 2 casas decimais");
            }

            return num.setScale(2, RoundingMode.HALF_UP);
        } catch (NumberFormatException e) {
            throw new ValidationException("Montante inválido: " + e.getMessage());
        }
    }
}

// ✅ MELHOR - Jakarta Bean Validation
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;

public class Order {
    @DecimalMin("0.00")
    @DecimalMax("999999.99")
    @Digits(integer = 6, fraction = 2)
    private BigDecimal total;
}

// ✅ MELHOR - Spring Data @Range
import org.springframework.data.domain.Range;

public class PaymentService {
    public void processPayment(@Range(min = 0, max = 999999.99) BigDecimal amount) {
        // Processamento seguro
    }
}
```

**Checklist SAST:**
- [ ] Usar BigDecimal para valores monetários
- [ ] Validar com try-catch NumberFormatException
- [ ] Range de valores definido
- [ ] Casas decimais controladas

---

### 4. Validação de Strings

**Ponto SAST:** Prevenir injection, XSS

```java
// ❌ INSEGURO
public class UserService {
    public void saveUserBio(String bio) {
        // Aceita qualquer valor
        userRepository.update(bio);
    }
}

// ✅ SEGURO - Validações específicas
public class BioValidator {
    private static final int MAX_LENGTH = 500;
    private static final Pattern DANGEROUS_PATTERN =
        Pattern.compile("<script|javascript:|onclick|<iframe|<embed|<object", Pattern.CASE_INSENSITIVE);

    public static String validateBio(String bio) throws ValidationException {
        // Validar tipo e nulo
        if (bio == null || bio.trim().isEmpty()) {
            throw new ValidationException("Bio não pode estar vazia");
        }

        // Validar tamanho
        if (bio.length() > MAX_LENGTH) {
            throw new ValidationException("Bio muito longa");
        }

        // Validar caracteres perigosos
        if (DANGEROUS_PATTERN.matcher(bio).find()) {
            throw new ValidationException("Bio contém conteúdo perigoso");
        }

        return bio.trim();
    }
}

// ✅ MELHOR - Jakarta Bean Validation
public class UserProfile {
    @NotBlank(message = "Bio não pode estar vazia")
    @Size(max = 500, message = "Bio não pode ter mais de 500 caracteres")
    private String bio;
}

// ✅ MELHOR - OWASP ESAPI para sanitização
import org.owasp.esapi.ESAPI;

public class BioSanitizer {
    public static String sanitizeBio(String bio) throws ValidationException {
        String validated = BioValidator.validateBio(bio);

        // Escapar para HTML context
        String escaped = ESAPI.encoder().encodeForHTML(validated);

        return escaped;
    }
}
```

**Checklist SAST:**
- [ ] Tamanho máximo definido
- [ ] Caracteres especiais validados com regex
- [ ] Usar OWASP ESAPI para escaping
- [ ] Testes com payloads maliciosos

---

### 5. Validação de Enums/Valores Permitidos

**Ponto SAST:** Garantir apenas valores esperados

```java
// ❌ INSEGURO
public class OrderService {
    public void updateStatus(String status) {
        // Aceita qualquer valor!
        orderRepository.update(status);
    }
}

// ✅ SEGURO - Enum Java
public enum OrderStatus {
    PENDING("PENDING"),
    APPROVED("APPROVED"),
    REJECTED("REJECTED");

    private final String value;

    OrderStatus(String value) {
        this.value = value;
    }

    public static OrderStatus fromString(String value) throws ValidationException {
        for (OrderStatus status : OrderStatus.values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        throw new ValidationException("Status inválido: " + value);
    }
}

// Uso:
public void updateStatus(String statusString) throws ValidationException {
    OrderStatus status = OrderStatus.fromString(statusString);
    orderRepository.update(status);
}

// ✅ MELHOR - Jakarta Bean Validation com enum
public class Order {
    @NotNull
    private OrderStatus status;

    // getter e setter
}

// ✅ MELHOR - Spring MVC converter
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class StringToOrderStatusConverter implements Converter<String, OrderStatus> {
    @Override
    public OrderStatus convert(String source) {
        return OrderStatus.fromString(source);
    }
}
```

**Checklist SAST:**
- [ ] Enum Java definido
- [ ] Validação antes de usar valor
- [ ] Testes com valores inválidos
- [ ] Conversão tratada com exceção

---

### 6. Validação de Arquivos

**Ponto SAST:** Prevenir upload malicioso

```java
// ❌ INSEGURO
@PostMapping("/upload")
public void uploadFile(@RequestParam MultipartFile file) throws IOException {
    file.transferTo(new File("/uploads/" + file.getOriginalFilename()));
}

// ✅ SEGURO - Validação completa
public class FileUploadValidator {
    private static final List<String> ALLOWED_MIMES = Arrays.asList(
        "image/jpeg", "image/png", "application/pdf"
    );
    private static final long MAX_SIZE = 5L * 1024 * 1024; // 5MB

    public static void validateFile(MultipartFile file) throws ValidationException {
        // Validar nulo
        if (file == null || file.isEmpty()) {
            throw new ValidationException("Arquivo não fornecido");
        }

        // Validar MIME type
        if (!ALLOWED_MIMES.contains(file.getContentType())) {
            throw new ValidationException("Tipo não permitido: " + file.getContentType());
        }

        // Validar tamanho
        if (file.getSize() > MAX_SIZE) {
            throw new ValidationException("Arquivo muito grande");
        }

        // Validar nome - path traversal
        String filename = file.getOriginalFilename();
        if (filename == null || filename.contains("..") || filename.contains("/")) {
            throw new ValidationException("Nome de arquivo inválido");
        }
    }
}

// ✅ MELHOR - Usar UUID
import java.util.UUID;
import java.nio.file.Files;
import java.nio.file.Paths;

@PostMapping("/upload")
public String uploadFile(@RequestParam MultipartFile file,
                        @Value("${upload.dir}") String uploadDir) throws Exception {
    FileUploadValidator.validateFile(file);

    // Gerar UUID como nome
    String ext = getFileExtension(file.getOriginalFilename());
    String newFilename = UUID.randomUUID() + "." + ext;

    // Salvar em diretório seguro
    Files.copy(
        file.getInputStream(),
        Paths.get(uploadDir, newFilename)
    );

    return newFilename;
}

// ✅ MELHOR - Verificar magic bytes
import org.apache.tika.Tika;

public class MagicBytesValidator {
    private static final Tika tika = new Tika();

    public static void validateMagicBytes(byte[] fileContent) throws ValidationException {
        String detectedMime = tika.detect(fileContent);

        if (!ALLOWED_MIMES.contains(detectedMime)) {
            throw new ValidationException("Tipo inválido (conteúdo): " + detectedMime);
        }
    }
}
```

**Checklist SAST:**
- [ ] Validar com MultipartFile.isEmpty()
- [ ] Verificar MIME type
- [ ] Tamanho do arquivo limitado
- [ ] Magic bytes verificados com Tika
- [ ] Nome do arquivo sanitizado
- [ ] Path traversal testado

---

### 7. Validação de Autenticação/Tokens

**Ponto SAST:** Validar JWT

```java
// ❌ INSEGURO
public class TokenValidator {
    public static Claims verifyToken(String token) {
        return Jwts.parserBuilder()
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
}

// ✅ SEGURO - Validação completa
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

public class JwtTokenValidator {
    private static final String SECRET = System.getenv("JWT_SECRET");
    private static final long EXPIRATION_TIME = 3600000; // 1 hora

    public static Claims validateToken(String tokenString) throws JwtException {
        // Validar tipo
        if (tokenString == null || tokenString.isEmpty()) {
            throw new JwtException("Token não fornecido");
        }

        // Remover prefixo Bearer
        if (tokenString.startsWith("Bearer ")) {
            tokenString = tokenString.substring(7);
        }

        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(SECRET.getBytes()))
                .build()
                .parseClaimsJws(tokenString)
                .getBody();

            // Validar claims obrigatórios
            if (claims.get("userId") == null || claims.getIssuedAt() == null) {
                throw new JwtException("Token incompleto");
            }

            return claims;
        } catch (ExpiredJwtException e) {
            throw new JwtException("Token expirado");
        } catch (SignatureException e) {
            throw new JwtException("Assinatura inválida");
        } catch (JwtException e) {
            throw new JwtException("Token inválido: " + e.getMessage());
        }
    }

    public static String createToken(String userId) {
        return Jwts.builder()
            .setSubject(userId)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .setIssuer("my-app")
            .setAudience("my-app")
            .signWith(Keys.hmacShaKeyFor(SECRET.getBytes()), SignatureAlgorithm.HS256)
            .compact();
    }
}

// ✅ MELHOR - Spring Security com JWT
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);

        if (token != null) {
            try {
                Claims claims = JwtTokenValidator.validateToken(token);
                String userId = claims.getSubject();

                // Criar autenticação segura
                Authentication authentication = new JwtAuthentication(userId);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}

// ✅ MELHOR - Spring Security configuração
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers("/login", "/register").permitAll()
                .anyRequest().authenticated()
            .and()
            .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

**Checklist SAST:**
- [ ] JWT assinatura verificada com chave secreta
- [ ] Expiração validada automaticamente pelo parser
- [ ] Claims obrigatórios verificados
- [ ] Usar biblioteca jjwt ou Spring Security
- [ ] Tokens revogados no logout (Redis)
- [ ] Teste com tokens expirados/inválidos

---

## Sanitização e Limpeza

### HTML Escaping

```java
// ❌ INSEGURO
public class CommentService {
    public void displayComment(String comment) {
        // Retorna HTML não escapado - XSS!
        return "<p>" + comment + "</p>";
    }
}

// ✅ SEGURO - HTML escape com Apache Commons
import org.apache.commons.text.StringEscapeUtils;

public String escapeHtml(String text) {
    return StringEscapeUtils.escapeHtml4(text);
}

// ✅ MELHOR - OWASP ESAPI
import org.owasp.esapi.ESAPI;

public String escapeHtmlEsapi(String text) {
    return ESAPI.encoder().encodeForHTML(text);
}

// ✅ MELHOR - Spring Template (Thymeleaf)
// Thymeleaf escapa por padrão:
<p th:text="${comment}"></p>  <!-- escapado automaticamente -->
<p th:utext="${comment}"></p> <!-- não escapado, cuidado! -->

// ✅ MELHOR - JSP com c:out
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<p><c:out value="${comment}"/></p>
```

### SQL Query Parameterization

```java
// ❌ INSEGURO - SQL Injection
public User getUserById(Long id) {
    String query = "SELECT * FROM users WHERE id = " + id;
    return jdbcTemplate.queryForObject(query, new UserRowMapper());
}

// ✅ SEGURO - JdbcTemplate com parameterização
public User getUserById(Long id) {
    String query = "SELECT * FROM users WHERE id = ?";
    return jdbcTemplate.queryForObject(query, new Object[]{id}, new UserRowMapper());
}

// ✅ MELHOR - JPA/Hibernate
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}

// Uso automático de prepared statements
User user = userRepository.findByEmail(userInput).orElseThrow();

// ✅ MELHOR - QueryDSL
User user = queryFactory
    .selectFrom(QUser.user)
    .where(QUser.user.id.eq(id))
    .fetchOne();
```

---

## Bibliotecas Recomendadas

### 1. **Jakarta Bean Validation (javax.validation)**

```xml
<dependency>
    <groupId>jakarta.validation</groupId>
    <artifactId>jakarta.validation-api</artifactId>
    <version>3.0.0</version>
</dependency>
<dependency>
    <groupId>org.hibernate.validator</groupId>
    <artifactId>hibernate-validator</artifactId>
    <version>8.0.0.Final</version>
</dependency>
```

### 2. **JJWT (JWT)**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
```

### 3. **Apache Commons Validator**

```xml
<dependency>
    <groupId>commons-validator</groupId>
    <artifactId>commons-validator</artifactId>
    <version>1.7</version>
</dependency>
```

### 4. **OWASP ESAPI**

```xml
<dependency>
    <groupId>org.owasp.esapi</groupId>
    <artifactId>esapi</artifactId>
    <version>2.5.2.1</version>
</dependency>
```

### 5. **Apache Tika (File Detection)**

```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.8.1</version>
</dependency>
```

---

## Testes de Segurança

```java
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class ValidationSecurityTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "<script>alert('xss')</script>",
        "<img src=x onerror='alert(1)'>",
        "javascript:alert(1)",
        "<svg onload='alert(1)'>"
    })
    public void testXSSPayloadsRejected(String payload) {
        assertThrows(ValidationException.class, () -> BioValidator.validateBio(payload));
    }

    @Test
    public void testEmailValidation() {
        assertTrue(EmailValidator.isValid("user@example.com"));
        assertFalse(EmailValidator.isValid("invalid"));
        assertFalse(EmailValidator.isValid("test@"));
    }

    @Test
    public void testAmountValidation() {
        BigDecimal amount = AmountValidator.validateAmount("10.50");
        assertEquals(new BigDecimal("10.50"), amount);

        assertThrows(ValidationException.class, () -> AmountValidator.validateAmount("-10"));
    }
}
```

---

## Checklist SAST

### Usando SpotBugs

```bash
mvn spotbugs:check
```

### Usando SonarQube

```bash
mvn sonar:sonar
```

### Checklist Manual

- [ ] Jakarta Bean Validation em todas as classes de entrada
- [ ] Enums Java para valores permitidos
- [ ] BigDecimal para valores monetários
- [ ] JPA/Hibernate para prepared statements
- [ ] OWASP ESAPI para escaping
- [ ] JWT verificado com chave secreta
- [ ] Testes com payloads maliciosos
- [ ] Rate limiting em endpoints críticos
- [ ] Logging de tentativas suspeitas

---

## Resumo

**Regras de Ouro:**
1. ✅ **Valide SEMPRE no backend**
2. ✅ **Use Jakarta Bean Validation**
3. ✅ **Implemente JPA prepared statements**
4. ✅ **Escape output com OWASP ESAPI**
5. ✅ **Registre tentativas suspeitas**
6. ✅ **Use enum para valores permitidos**
7. ✅ **Teste com payloads de ataque conhecidos**

