# 🔧 Troubleshooting Guide

This guide covers common issues and their solutions when working with OWASP Checklist Platform.

---

## 📋 Table of Contents

- [Installation Issues](#installation-issues)
- [Database Issues](#database-issues)
- [Docker Issues](#docker-issues)
- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Authentication Issues](#authentication-issues)
- [Export Issues](#export-issues)
- [Performance Issues](#performance-issues)

---

## Installation Issues

### ❌ `pnpm: command not found`

**Problem:** pnpm is not installed on your system.

**Solution:**
```bash
npm install -g pnpm
# or
curl -fsSL https://get.pnpm.io/install.sh | sh -
```

---

### ❌ `Node.js version too old`

**Problem:** Project requires Node.js 20+ but older version is installed.

**Solution:**
```bash
# Using nvm
nvm install 20
nvm use 20

# Or download from https://nodejs.org/
```

---

### ❌ `EACCES: permission denied`

**Problem:** Insufficient permissions during installation.

**Solution:**
```bash
# Fix npm permissions (don't use sudo with npm)
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH=~/.npm-global/bin:$PATH
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc

# Or use sudo only for global installs
sudo npm install -g pnpm
```

---

## Database Issues

### ❌ `Environment variable not found: DATABASE_URL`

**Problem:** Missing `.env` file or DATABASE_URL variable.

**Solution:**
```bash
# Copy example env file
cp .env.example .env

# Or manually create .env with:
DATABASE_URL="file:./prisma/sqlite/sqlite.db"
NEXTAUTH_SECRET="your-secret-here"
NEXTAUTH_URL="http://localhost:3000"
```

---

### ❌ `Error: Cannot find module '@prisma/client'`

**Problem:** Prisma Client not generated after migration.

**Solution:**
```bash
pnpm -C prisma exec prisma generate
```

---

### ❌ `P1003: Database does not exist`

**Problem:** Database file not created yet.

**Solution:**
```bash
# Create directory and run migrations
mkdir -p prisma/sqlite
export DATABASE_URL="file:./prisma/sqlite/sqlite.db"
pnpm -C prisma exec prisma migrate dev --name init
```

---

### ❌ `Prisma migrate failed`

**Problem:** Migration conflicts or corrupted migrations.

**Solution:**
```bash
# Reset database (WARNING: destroys all data)
./scripts/reset.sh

# Or manually
rm -rf prisma/migrations prisma/sqlite
mkdir -p prisma/sqlite
export DATABASE_URL="file:./prisma/sqlite/sqlite.db"
pnpm -C prisma exec prisma migrate dev --name init
pnpm run seed
```

---

### ❌ `Database is locked`

**Problem:** SQLite database file is locked by another process.

**Solution:**
```bash
# Stop all Node processes
pkill node

# Or restart the dev server
pnpm dev
```

---

## Docker Issues

### ❌ `Cannot connect to the Docker daemon`

**Problem:** Docker is not running or user lacks permissions.

**Solution:**
```bash
# Start Docker
sudo systemctl start docker

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Logout and login again

# Or use Docker Desktop (macOS/Windows)
```

---

### ❌ `Error response from daemon: Conflict`

**Problem:** Container with same name already exists.

**Solution:**
```bash
# Stop and remove existing containers
docker compose -f docker/docker-compose.yml down

# Remove all stopped containers
docker container prune -f
```

---

### ❌ `Port 3000 is already in use`

**Problem:** Another service is using port 3000.

**Solution:**
```bash
# Find process using port 3000
lsof -ti:3000 | xargs kill -9

# Or change port in docker-compose.yml
ports:
  - "3001:3000"  # Maps host 3001 to container 3000
```

---

### ❌ `Build failed in Docker`

**Problem:** Missing dependencies or network issues during Docker build.

**Solution:**
```bash
# Build with no cache
docker compose -f docker/docker-compose.yml build --no-cache

# Or increase timeout
export DOCKER_BUILDKIT=1
export COMPOSE_HTTP_TIMEOUT=200
docker compose -f docker/docker-compose.yml up --build
```

---

## Build Issues

### ❌ `Type error: Cannot find module`

**Problem:** Missing or incorrect TypeScript types.

**Solution:**
```bash
# Reinstall dependencies
rm -rf node_modules pnpm-lock.yaml
pnpm install

# Generate Prisma Client
pnpm -C prisma exec prisma generate
```

---

### ❌ `Module not found: Can't resolve '@/lib/...'`

**Problem:** Path alias not configured correctly.

**Solution:**
Check `tsconfig.json` has:
```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./apps/web/*"]
    }
  }
}
```

---

### ❌ `Build fails with 'out of memory'`

**Problem:** Insufficient memory for Next.js build.

**Solution:**
```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=4096"
pnpm build

# Or add to package.json
"build": "NODE_OPTIONS='--max-old-space-size=4096' next build"
```

---

## Runtime Issues

### ❌ `Error: ECONNREFUSED`

**Problem:** Cannot connect to database or external service.

**Solution:**
- Check if database file exists: `ls -la prisma/sqlite/`
- Verify DATABASE_URL in `.env`
- Restart dev server: `pnpm dev`

---

### ❌ `NextAuth session not persisting`

**Problem:** NEXTAUTH_SECRET not set or changed.

**Solution:**
```bash
# Generate secure secret
openssl rand -base64 32

# Add to .env
NEXTAUTH_SECRET="your-generated-secret-here"

# Restart server
pnpm dev
```

---

### ❌ `API returns 401 Unauthorized`

**Problem:** User not authenticated or session expired.

**Solution:**
- Clear browser cookies and login again
- Check NEXTAUTH_URL matches your domain
- Verify JWT token hasn't expired

---

### ❌ `API returns 403 Forbidden`

**Problem:** User doesn't have required permissions.

**Solution:**
- Check user role in database
- Verify RBAC permissions in `/apps/web/lib/rbac.ts`
- Elevate user to ADMIN if needed:
```sql
-- Using SQLite CLI
sqlite3 prisma/sqlite/sqlite.db
UPDATE users SET role = 'ADMIN' WHERE email = 'user@example.com';
```

---

## Authentication Issues

### ❌ `Invalid credentials on login`

**Problem:** Wrong password or user doesn't exist.

**Solution:**
```bash
# Reset database and create default admin
./scripts/reset.sh

# Default credentials:
# Email: admin@local
# Password: admin123!
```

---

### ❌ `bcrypt error: data and hash must be strings`

**Problem:** Password hash corrupted or empty.

**Solution:**
Run seed again to create users with proper hashes:
```bash
pnpm run seed
```

---

## Export Issues

### ❌ `PDF export fails with Playwright error`

**Problem:** Chromium not installed or not found.

**Solution:**
```bash
# Install Playwright browsers
pnpm -C apps/web exec playwright install chromium

# Or install dependencies
pnpm -C apps/web exec playwright install-deps
```

---

### ❌ `Export returns 404`

**Problem:** Assessment not found or wrong ID.

**Solution:**
- Verify assessment ID in database
- Check API request body format
- Ensure user has export permissions

---

### ❌ `CSV contains garbled characters`

**Problem:** Character encoding issue.

**Solution:**
Open CSV with UTF-8 encoding:
- Excel: Data → From Text → UTF-8
- Google Sheets: File → Import → UTF-8

---

## Performance Issues

### ❌ `Slow database queries`

**Problem:** Large dataset without indexes.

**Solution:**
```bash
# Analyze queries
pnpm -C prisma exec prisma studio

# Add indexes in schema.prisma
@@index([createdAt])
@@index([status])
```

---

### ❌ `High memory usage`

**Problem:** Memory leak or large dataset.

**Solution:**
- Implement pagination for large lists
- Clear browser cache and cookies
- Restart Node.js server
- Check for memory leaks with:
```bash
node --inspect apps/web/.next/standalone/server.js
```

---

### ❌ `Slow PDF generation`

**Problem:** Playwright taking too long.

**Solution:**
- Reduce assessment size (export in batches)
- Increase timeout in `apps/web/lib/pdf.ts`
- Use CSV/JSON export instead for large reports

---

## Common Commands

### Reset Everything
```bash
# Nuclear option - fresh start
rm -rf node_modules pnpm-lock.yaml prisma/sqlite prisma/migrations .next
pnpm install
./scripts/setup.sh
```

### Check Logs
```bash
# View application logs
docker compose -f docker/docker-compose.yml logs -f web

# Or in development
pnpm dev | pnpm exec pino-pretty
```

### Database Operations
```bash
# Open Prisma Studio (GUI)
pnpm -C prisma exec prisma studio

# View raw database
sqlite3 prisma/sqlite/sqlite.db
.tables
SELECT * FROM users;
```

### Verify Installation
```bash
# Check versions
node --version    # Should be 20+
pnpm --version    # Should be 8+
docker --version  # Optional but recommended

# Test build
pnpm build

# Run tests
pnpm test
pnpm test:e2e
```

---

## Still Having Issues?

1. **Search GitHub Issues:** https://github.com/GhostN3xus/Owasp_Checklist_testing/issues
2. **Check logs:** Enable debug logging with `LOG_LEVEL=debug pnpm dev`
3. **Create new issue:** Include error message, steps to reproduce, environment details

---

## Environment Info Template

When reporting issues, include:

```
OS: [Windows 10/Ubuntu 22.04/macOS 14]
Node.js: [20.x.x]
pnpm: [8.x.x]
Docker: [24.x.x] (if applicable)

Error message:
[paste full error here]

Steps to reproduce:
1.
2.
3.

Expected behavior:
[what should happen]

Actual behavior:
[what actually happens]
```

---

**Last updated:** 2025-01-11
