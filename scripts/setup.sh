#!/bin/bash
set -e

echo "🚀 Setting up OWASP Checklist Platform..."

# Create directories
mkdir -p prisma/sqlite

# Install dependencies if not already done
if [ ! -d "node_modules" ]; then
  echo "📦 Installing dependencies..."
  pnpm install
fi

# Generate Prisma client
echo "🔧 Generating Prisma client..."
pnpm -C prisma exec prisma generate

# Run migrations
echo "🗄️  Running database migrations..."
pnpm -C prisma exec prisma migrate deploy

# Run seed
echo "🌱 Seeding database with OWASP checklists..."
pnpm -C prisma exec prisma db seed

# Build Next.js
echo "🔨 Building Next.js application..."
pnpm -C apps/web build

echo "✅ Setup completed successfully!"
echo ""
echo "📍 Default credentials:"
echo "   Email: admin@local"
echo "   Password: admin123!"
echo ""
echo "🚀 Start development server:"
echo "   pnpm dev"
echo ""
echo "🌐 Open http://localhost:3000"
