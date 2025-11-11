# 🔧 Troubleshooting & FAQ

## 🐳 Docker Issues

### "Container exited with error"
```bash
# Ver logs detalhados
docker compose -f docker/docker-compose.yml logs -f web

# Limpar tudo e recomeçar
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up --build
```

### "Port 3000 already in use"
```bash
# Matar processo na porta 3000
lsof -ti:3000 | xargs kill -9

# Ou use outra porta
docker compose -f docker/docker-compose.yml up -e "PORT=3001"
```

### "Database lock error"
```bash
# Remover arquivo de database corrompido
rm -f prisma/sqlite/sqlite.db

# Reiniciar Docker
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up --build
```

---

## 💻 Local Development Issues

### "pnpm not found"
```bash
# Instalar pnpm globalmente
npm install -g pnpm@10.20.0

# Ou usar npm diretamente
npm install
```

### "Prisma generate failed"
```bash
# Reinstalar Prisma
pnpm -C prisma exec prisma generate

# Se ainda não funcionar
rm -rf node_modules
pnpm install
pnpm -C prisma exec prisma generate
```

### "Database migration error"
```bash
# Ver status das migrations
pnpm -C prisma exec prisma migrate status

# Resetar database (CUIDADO: deleta tudo!)
pnpm -C prisma exec prisma migrate reset

# Ou criar nova migration
pnpm -C prisma exec prisma migrate dev --name init
```

### "Seed script fails"
```bash
# Criar diretório de SQLite
mkdir -p prisma/sqlite

# Rodar seed manualmente
pnpm -C prisma exec prisma db seed

# Ver logs
pnpm -C prisma exec prisma db seed -- --verbose
```

---

## 🌐 Login Issues

### "Login returns 401"
1. Verify credentials: `admin@local` / `admin123!`
2. Check if database seeded: `SELECT * FROM users;`
3. Clear browser cache and cookies
4. Try incognito/private mode

### "NEXTAUTH_SECRET not set"
```bash
# Add to .env
NEXTAUTH_SECRET="random-secret-string-here"
NEXTAUTH_URL="http://localhost:3000"
```

---

## 🗄️ Database Issues

### "SQLite file not found"
```bash
# Ensure directory exists
mkdir -p prisma/sqlite

# Create empty database
touch prisma/sqlite/sqlite.db

# Run migrations
pnpm -C prisma exec prisma migrate deploy
```

### "Foreign key constraint failed"
1. Check if Assessment references valid Project
2. Check if ChecklistItem references valid Checklist
3. Run `prisma db seed` to populate data

---

## 📦 Build Issues

### "Build failed: Module not found"
```bash
# Clear build cache
rm -rf .next apps/web/.next

# Reinstall dependencies
pnpm install

# Rebuild
pnpm build
```

### "Type errors in TypeScript"
```bash
# Check for unused variables (if strict mode enabled)
# Disable strict checks temporarily in tsconfig.json:
# "noUnusedLocals": false
# "noUnusedParameters": false

# Or fix the issues
npm run lint -- --fix
```

---

## 🔍 Performance Tips

### Slow Docker startup?
- Ensure Docker has enough CPU/Memory allocated
- Check: `docker stats`
- Increase Docker resources in settings

### Slow Next.js build?
- Clear cache: `rm -rf .next`
- Use SSD for better I/O
- Check RAM availability

### Database slow?
- SQLite is for development; use Postgres for production
- Change `DATABASE_URL` to Postgres connection string
- Run migrations: `pnpm migrate`

---

## 📋 Common Commands

### Development
```bash
pnpm dev              # Start dev server
pnpm build            # Build for production
pnpm start            # Start production server
pnpm test             # Run tests
pnpm lint             # Run linter
pnpm format           # Format code
```

### Database
```bash
pnpm -C prisma exec prisma studio           # Open DB GUI
pnpm -C prisma exec prisma migrate dev      # Create migration
pnpm -C prisma exec prisma migrate deploy   # Run migrations
pnpm -C prisma exec prisma db seed          # Seed data
```

### Docker
```bash
docker compose -f docker/docker-compose.yml up --build   # Start
docker compose -f docker/docker-compose.yml down         # Stop
docker compose -f docker/docker-compose.yml logs -f      # Logs
docker compose -f docker/docker-compose.yml ps           # Status
```

---

## 🆘 Still Having Issues?

1. **Check logs**: `docker compose logs` or console output
2. **Verify environment**: `echo $DATABASE_URL`
3. **Test connectivity**: `curl http://localhost:3000/api/v1/checklists`
4. **Check requirements**: Node 20+, Docker 20+, pnpm 10+
5. **Search docs**: Check README.md and inline code comments
6. **Report bug**: Create issue on GitHub with error logs

---

## ✅ Verification Checklist

- [ ] Docker running: `docker --version`
- [ ] Node/pnpm installed: `node -v`, `pnpm -v`
- [ ] `.env` file exists with `NEXTAUTH_SECRET`
- [ ] Database directory created: `ls -la prisma/sqlite`
- [ ] Dependencies installed: `pnpm install`
- [ ] Can access http://localhost:3000
- [ ] Can login with `admin@local` / `admin123!`
- [ ] API responding: `curl http://localhost:3000/api/v1/checklists`
