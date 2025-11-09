# Authentication, OAuth, OIDC, and SAML Security

## Overview

Modern authentication flows involve complex protocols and cryptographic operations. This guide covers best practices for securing these mechanisms.

## Authentication Fundamentals

### 1. Password Security

**Best Practices:**
- Minimum 12 characters, mix of cases, numbers, symbols
- Use bcrypt, scrypt, PBKDF2, or Argon2 for hashing
- Never store plaintext passwords
- Implement rate limiting on login attempts (e.g., 5 failures = 15min lockout)
- Use salts (minimum 128 bits) unique per password

**Testing Checklist:**
```
[] Password hashing algorithm verified (not MD5, SHA1, SHA256)
[] Salt length >= 128 bits
[] Hash iterations > 100,000 (PBKDF2) or equivalent
[] No password hints or recovery questions visible
[] Login brute force protection active
[] Account lockout threshold reasonable (5-10 attempts)
```

### 2. Session Management

**Secure Token Generation:**
- Use cryptographically secure random generators (not `Math.random()`)
- Minimum 128 bits of entropy
- Store in secure, HTTP-only, SameSite cookies
- Regenerate session IDs after login
- Implement session timeouts (15-30 minutes for sensitive)
- Invalidate on logout

**Code Example (Node.js):**
```javascript
const crypto = require('crypto');

function generateSessionToken() {
  // 32 bytes = 256 bits of entropy
  return crypto.randomBytes(32).toString('hex');
}

// Set cookie
res.cookie('session_id', token, {
  httpOnly: true,        // Prevent JavaScript access
  secure: true,          // HTTPS only
  sameSite: 'Strict',    // CSRF protection
  maxAge: 30 * 60 * 1000 // 30 minutes
});
```

### 3. Multi-Factor Authentication (MFA)

**Supported Mechanisms:**
1. **Time-based OTP (TOTP)**: Google Authenticator, Authy
2. **HMAC-based OTP (HOTP)**: Counter-based tokens
3. **Push notifications**: Approve on registered device
4. **SMS codes**: Fallback only (not primary)
5. **Hardware keys**: FIDO2/WebAuthn (recommended)

**Implementation Checklist:**
```
[] MFA enrollment enforced for admin accounts
[] Rate limiting on MFA verification (5 attempts/minute)
[] Recovery codes generated and secured
[] MFA not bypassable with session hijacking
[] Backup MFA methods available
[] MFA setup protected by strong auth
```

---

## OAuth 2.0

### Authorization Flow (Best Practice: Authorization Code + PKCE)

```
1. User clicks "Login with Provider"
2. App generates state and code_challenge
3. User redirected to provider login
4. Provider requests consent
5. User approves, provider redirects to callback with code
6. App exchanges code + code_verifier for tokens (backend)
7. User authenticated, tokens issued
```

### PKCE (Proof Key for Code Exchange)

**Why:** Prevents code interception on mobile/desktop apps

**Implementation:**
```javascript
// Step 1: Generate PKCE
const crypto = require('crypto');

function generatePKCE() {
  const codeVerifier = crypto.randomBytes(32).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return { codeVerifier, codeChallenge };
}

// Step 2: Redirect with code_challenge
const { codeVerifier, codeChallenge } = generatePKCE();
session.codeVerifier = codeVerifier; // Store securely

const authURL = `https://provider.com/oauth/authorize?` +
  `client_id=${CLIENT_ID}&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256&` +
  `redirect_uri=${REDIRECT_URI}`;

// Step 3: Exchange with code_verifier
const tokenResponse = await fetch('https://provider.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    code: authorizationCode,
    code_verifier: session.codeVerifier,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET, // Keep on backend!
    grant_type: 'authorization_code'
  })
});
```

### OAuth Security Checklist

```
[] State parameter unique per request, validated on callback
[] PKCE implemented (code_challenge, code_verifier)
[] Redirect URIs whitelisted (exact match, HTTPS only)
[] Client secret never exposed (backend only)
[] Token expiry < 1 hour (short-lived access tokens)
[] Refresh token rotation enforced
[] Refresh tokens stored securely (HttpOnly, encrypted)
[] Token revocation implemented
[] Scope limitations enforced (minimal permissions)
[] No sensitive data in access token claims
[] Token endpoint requires authentication (TLS 1.2+)
```

---

## OpenID Connect (OIDC)

OpenID Connect = OAuth 2.0 + ID Token (JWT)

### Key Differences from OAuth

| Feature | OAuth 2.0 | OIDC |
|---------|----------|------|
| Primary Use | Authorization | Authentication + Authorization |
| Token Returned | Access Token | Access Token + ID Token (JWT) |
| User Info | Query separate endpoint | Claims in ID Token |
| User Identity | Not guaranteed | Guaranteed (signed) |
| Logout | No standard | ID Token contains `aud/exp/iss` |

### ID Token Validation

```javascript
const jwt = require('jsonwebtoken');

function validateIDToken(token, expectedAudience, expectedIssuer) {
  try {
    const decoded = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256', 'RS384', 'RS512'], // Asymmetric only!
      audience: expectedAudience,
      issuer: expectedIssuer,
      ignoreExpiration: false // MUST check exp!
    });

    // Verify required claims
    if (!decoded.sub || !decoded.aud || !decoded.iss || !decoded.exp) {
      throw new Error('Missing required claims');
    }

    // Verify exp (issued <= now < expiry + clock skew)
    const now = Math.floor(Date.now() / 1000);
    const clockSkew = 60; // seconds
    if (decoded.exp + clockSkew < now) {
      throw new Error('Token expired');
    }

    return decoded;
  } catch (error) {
    throw new Error(`Token validation failed: ${error.message}`);
  }
}

// Usage
const idToken = response.id_token;
const claims = validateIDToken(idToken, CLIENT_ID, 'https://issuer.com');
```

### OIDC Checklist

```
[] ID Token signature verified with issuer's public key
[] Algorithm whitelist enforced (RS256/384/512, no HS256 unless explicit)
[] aud (audience) matches client_id
[] iss (issuer) matches expected issuer
[] exp (expiration) validated
[] iat (issued at) not in future (clock skew <= 60s)
[] sub (subject) matches user ID
[] nonce parameter used and validated (prevents replay)
[] Refresh tokens not reused (rotation enforced)
[] ID Token not sent in URL (POST only, fragments if SPA)
```

---

## SAML 2.0

### Service Provider (SP) vs Identity Provider (IdP)

```
User → SP (Your App) → IdP (e.g., Okta/Azure AD)
         ↓
      Assertion (XML, signed, encrypted)
```

### Assertion Validation Checklist

```
[] XML signature valid (verify against IdP certificate)
[] Assertion encryption verified (if encrypted)
[] Assertion not replayed (check NotOnOrAfter, NotBefore)
[] Recipient matches SP ACS URL
[] NameID matches expected format
[] Audience restriction verified
[] Conditions checked (NotBefore, NotOnOrAfter)
[] AuthnStatement present
[] SessionIndex validated
```

### SAML Example (Python with OneLogin)

```python
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

def verify_saml_response(saml_settings, saml_data):
    auth = OneLogin_Saml2_Auth(saml_settings)
    auth.process_response()

    if not auth.is_authenticated():
        raise Exception("SAML assertion invalid or expired")

    errors = auth.get_last_error_reason()
    if errors:
        raise Exception(f"SAML errors: {errors}")

    # Validate key assertions
    assert auth.get_last_assertion_xml() is not None
    assert auth.get_attributes() is not None

    user_id = auth.get_nameid()
    user_email = auth.get_attributes().get('email', [None])[0]

    return {
        'id': user_id,
        'email': user_email,
        'authenticated': True
    }
```

---

## JWT (JSON Web Tokens)

### Secure JWT Practices

**Header Claims:**
```json
{
  "alg": "RS256",  // NOT "none", NOT HS256 in critical apps
  "typ": "JWT",
  "kid": "rsa-key-1"  // Key ID for key rotation
}
```

**Payload Claims:**
```json
{
  "sub": "user-123",
  "aud": ["app1", "app2"],
  "iss": "https://auth.example.com",
  "exp": 1699500000,
  "iat": 1699496400,
  "nbf": 1699496400,
  "jti": "unique-token-id"  // Prevent replay
}
```

**Validation Code:**
```javascript
const jwt = require('jsonwebtoken');

function validateJWT(token, publicKey, config) {
  try {
    return jwt.verify(token, publicKey, {
      algorithms: ['RS256', 'RS384', 'RS512'], // Asymmetric
      audience: config.expectedAudience,
      issuer: config.expectedIssuer,
      clockTimestamp: Math.floor(Date.now() / 1000),
      ignoreExpiration: false
    });
  } catch (error) {
    console.error('JWT validation failed:', error.message);
    throw new Error('Invalid token');
  }
}
```

### Checklist

```
[] Algorithm whitelist enforced (no "none", no HS256 for critical)
[] Signature verification with public key
[] exp (expiration) validated
[] iat (issued at) not in future
[] aud (audience) matches app
[] iss (issuer) matches expected
[] jti (unique ID) checked against blocklist (logout)
[] Private key stored securely (AWS Secrets Manager, etc.)
[] Key rotation implemented (new keys can be used, old maintained for grace period)
[] Token claims minimal (PII only if encrypted)
[] Token not sent in URL (cookies or Authorization header)
```

---

## Key Rotation and Token Management

### Asymmetric Key Rotation (OIDC/SAML)

```javascript
async function rotateKeys() {
  // 1. Generate new key pair
  const newKeyPair = await crypto.generateKeyPair('rsa', {
    modulusLength: 2048
  });

  // 2. Keep old key for grace period (24 hours)
  // Store in JWKS endpoint with "use": "old"

  // 3. Use new key for all new tokens
  // Mark in JWKS with "use": "sig"

  // 4. After grace period, remove old key

  return newKeyPair;
}

// JWKS endpoint exposes public keys
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({
    keys: [
      {
        kty: 'RSA',
        kid: 'key-2024-01',
        use: 'sig',
        alg: 'RS256',
        n: currentKeyModulus,
        e: 'AQAB'
      },
      {
        kty: 'RSA',
        kid: 'key-2023-12',
        use: 'old',
        alg: 'RS256',
        n: oldKeyModulus,
        e: 'AQAB'
      }
    ]
  });
});
```

---

## Testing Commands

### OAuth/OIDC Testing with cURL

```bash
# 1. Get authorization code
curl -X GET "https://provider.com/oauth/authorize" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "response_type=code" \
  -d "scope=openid%20profile%20email" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "state=random-state-123" \
  -d "nonce=random-nonce-456"

# 2. Exchange code for tokens
curl -X POST "https://provider.com/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE_HERE",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_uri": "http://localhost:3000/callback"
  }'

# 3. Validate ID Token with jwt.io or locally
curl -X POST "http://localhost:3000/validate-token" \
  -H "Content-Type: application/json" \
  -d '{"token": "JWT_HERE"}'
```

### SAML Testing with samltool.io

```bash
# Online SAML validator (public)
# https://www.samltool.com/validate_saml.php

# Local testing with xmlsec1
xmlsec1 --verify --id-attr:ID AssertionID response.xml
```

---

## References

- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7234 - OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7519 - JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519)
- [SAML 2.0](https://wiki.oasis-open.org/security/FrontPage)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
