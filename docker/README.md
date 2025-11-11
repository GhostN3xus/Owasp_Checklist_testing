# Docker Setup for OWASP Checklist Platform

Este diretório contém a configuração Docker para a plataforma OWASP Checklist.

## Arquivos

- `Dockerfile.web` - Dockerfile multi-stage otimizado para produção
- `docker-compose.yml` - Orquestração dos serviços

## Pré-requisitos

- Docker Engine 20.10+
- Docker Compose V2

## Como usar

### 1. Build e inicialização rápida

```bash
# Na raiz do projeto
docker compose -f docker/docker-compose.yml up --build
```

### 2. Build apenas da imagem

```bash
docker build -f docker/Dockerfile.web -t owasp-checklist:latest .
```

### 3. Parar os serviços

```bash
docker compose -f docker/docker-compose.yml down
```

### 4. Remover volumes (limpar banco de dados)

```bash
docker compose -f docker/docker-compose.yml down -v
```

## Configuração

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
NEXTAUTH_SECRET=sua-chave-secreta-aqui-mínimo-32-caracteres
NEXTAUTH_URL=http://localhost:3000
PUBLIC_BASE_URL=http://localhost:3000
DATABASE_URL=file:./prisma/sqlite/sqlite.db
```

Para gerar um NEXTAUTH_SECRET seguro:

```bash
openssl rand -base64 32
```

## Estrutura do Docker

O Dockerfile usa uma abordagem multi-stage para otimização:

1. **deps** - Instala dependências do monorepo pnpm
2. **builder** - Compila a aplicação Next.js com output standalone
3. **runner** - Imagem final otimizada apenas com arquivos necessários

## Serviços

### web

- Aplicação Next.js principal
- Porta: 3000
- Healthcheck: `/api/health`
- Usuário: nextjs (non-root)

### init

- Executa migrações Prisma e seed do banco
- Roda uma vez no início
- Cria o banco SQLite se não existir

## Volumes

- `sqlite_data` - Banco de dados SQLite persistente
- `exports_data` - Exportações de relatórios

## Troubleshooting

### Erro de permissão no banco

```bash
# Limpar volumes e reiniciar
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up --build
```

### Build lento

O Dockerfile usa cache em layers. Se quiser forçar rebuild completo:

```bash
docker compose -f docker/docker-compose.yml build --no-cache
```

### Ver logs

```bash
# Todos os serviços
docker compose -f docker/docker-compose.yml logs -f

# Apenas web
docker compose -f docker/docker-compose.yml logs -f web

# Apenas init
docker compose -f docker/docker-compose.yml logs init
```

## Produção

Para deploy em produção:

1. Configure variáveis de ambiente adequadas
2. Use um banco de dados PostgreSQL ao invés de SQLite
3. Configure reverse proxy (nginx/traefik) com SSL
4. Ajuste recursos (CPU/Memory) conforme necessário

Exemplo com PostgreSQL:

```yaml
environment:
  DATABASE_URL: postgresql://user:password@postgres:5432/owaspdb
```

## Segurança

O container:

- Roda como usuário non-root (nextjs:1001)
- Usa dumb-init para gerenciamento correto de processos
- Apenas expõe porta 3000
- Imagem Alpine Linux minimalista
- Headers de segurança configurados no Next.js

## Desenvolvimento

Para desenvolvimento local, recomenda-se usar:

```bash
pnpm install
pnpm run dev
```

O Docker é otimizado para produção.
