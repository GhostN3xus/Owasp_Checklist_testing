# Contributing to OWASP Checklist Testing

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please read and follow our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Issues

1. **Check existing issues** before reporting duplicates
2. **Use issue templates** (provided in GitHub)
3. **Include**:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment (Node version, OS, etc.)
   - Logs/screenshots if applicable

### Suggesting Enhancements

1. **Use feature request template**
2. **Explain the use case**
3. **Provide examples** or mockups if relevant
4. **Consider security implications**

### Submitting Code Changes

#### Prerequisites

- Node.js 18+ LTS
- npm 9+
- Git configured with your name and email
- Fork of the repository

#### Setup Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Owasp_Checklist_testing.git
cd Owasp_Checklist_testing

# Add upstream remote
git remote add upstream https://github.com/GhostN3xus/Owasp_Checklist_testing.git

# Install dependencies
npm install

# Create feature branch
git checkout -b feat/your-feature-name
```

#### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feat/add-new-checklist
   # or
   git checkout -b fix/security-issue
   ```

2. **Make changes**
   - Keep commits atomic and focused
   - Write descriptive commit messages
   - Follow the code style

3. **Test your changes**
   ```bash
   npm run test:unit     # Unit tests
   npm run test:e2e      # E2E tests
   npm run lint          # Check code style
   npm run format        # Auto-format code
   ```

4. **Update documentation**
   - Update README.md if needed
   - Add/update inline code comments
   - Document new APIs

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: Add new security checklist module"
   ```

6. **Push to your fork**
   ```bash
   git push origin feat/your-feature-name
   ```

7. **Create a Pull Request**
   - Use the PR template
   - Link related issues
   - Describe your changes clearly
   - Request reviewers

## Code Style Guide

### JavaScript/Node.js

```javascript
// ✓ Good
const encryptData = (plaintext, password) => {
  if (!plaintext || !password) {
    throw new Error('Invalid arguments');
  }
  return crypto.encrypt(plaintext, password);
};

// ✗ Bad
function encryptData(a,b){return crypto.encrypt(a,b);}
```

### File Organization

```
module-name.js
├── Imports
├── Constants
├── Helper functions
├── Main exports
└── Default export
```

### Comments

```javascript
/**
 * Encrypt data using AES-256-GCM
 * @param {Buffer|string} plaintext - Data to encrypt
 * @param {string} password - Encryption password
 * @returns {Object} - { salt, iv, ciphertext, authTag }
 */
export function encrypt(plaintext, password) {
  // Implementation
}
```

### Naming Conventions

- **Variables/Functions**: `camelCase`
- **Classes/Constructors**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private functions**: `_privateFunction` or in modules with `#`

## Commit Message Format

Follow conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (no logic change)
- `refactor`: Code refactoring
- `test`: Tests
- `chore`: Build, dependencies, etc.
- `security`: Security improvements

### Examples

```
feat(export): Add PDF report generation

- Implement HTML-to-PDF template conversion
- Add project statistics to cover page
- Include evidence attachments in report

Closes #42

feat(crypto): Upgrade PBKDF2 iterations from 100k to 200k

fix(ui): Correct CVSS score calculation for environmental metrics

Fixes #128

docs(readme): Add installation instructions for Docker
```

## Testing Requirements

### Unit Tests

- Test file: `src/module.test.js`
- Framework: Vitest
- Coverage: Aim for >80%

```javascript
import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '../server/crypto/aesgcm.js';

describe('AES-GCM Encryption', () => {
  it('should encrypt and decrypt data', () => {
    const plaintext = 'sensitive data';
    const password = 'test-password-123';

    const encrypted = encrypt(plaintext, password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe(plaintext);
  });

  it('should fail with wrong password', () => {
    const encrypted = encrypt('data', 'password1');

    expect(() => {
      decrypt(encrypted, 'wrong-password');
    }).toThrow();
  });
});
```

### E2E Tests

- Test file: `tests/feature.spec.js`
- Framework: Playwright
- Scenarios: User workflows

```javascript
import { test, expect } from '@playwright/test';

test.describe('Project Creation', () => {
  test('should create encrypted project', async ({ page }) => {
    await page.goto('http://localhost:3000');

    await page.fill('input[name="projectName"]', 'Test Project');
    await page.fill('input[name="password"]', 'secure-password-123');

    await page.click('button[type="submit"]');

    await expect(page.locator('text=Project created')).toBeVisible();
  });
});
```

## Documentation

### README Updates

- Add your feature to the features list
- Include setup/usage instructions
- Add examples or screenshots

### Internal Documentation

- Code comments for complex logic
- JSDoc for all exported functions
- Architecture decisions in `docs/`

## Pull Request Process

1. **Ensure tests pass**
   ```bash
   npm run test:unit
   npm run test:e2e
   npm run lint
   ```

2. **Update documentation** (README, comments, etc.)

3. **Create clear PR title and description**

4. **Request review** from maintainers

5. **Address feedback** with follow-up commits

6. **Merge when approved** (squash recommended)

## Branch Naming

- `feat/feature-name` - New features
- `fix/bug-name` - Bug fixes
- `docs/update-name` - Documentation
- `refactor/scope` - Refactoring
- `test/feature-coverage` - Tests

## Release Process

Maintainers handle releases:

1. Create release branch from `main`
2. Update version in package.json
3. Update CHANGELOG.md
4. Create release tag
5. Deploy to npm (if applicable)

## Security Considerations

- Never commit secrets or credentials
- Use environment variables for sensitive data
- Run `npm audit` before committing
- Follow OWASP secure coding practices
- Review potential security impacts

## Questions?

- Open a discussion in GitHub Discussions
- Check existing issues and documentation
- Ask in a new issue with the `question` label

## License

By contributing, you agree that your contributions will be licensed under the ISC License.

---

**Thank you for contributing to AppSec security!** 🛡️

For detailed information, see:
- [SECURITY.md](SECURITY.md) - Security policy
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards
- [License](LICENSE) - ISC License
