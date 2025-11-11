#!/bin/bash

# OWASP Checklist Setup Script
# This script sets up the development environment

set -e  # Exit on error

echo "🚀 OWASP Checklist Setup Script"
echo "================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Node.js is installed
print_info "Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js 20+ first."
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    print_error "Node.js version 20+ is required. Current version: $(node --version)"
    exit 1
fi
print_success "Node.js $(node --version) detected"

# Check if pnpm is installed
print_info "Checking pnpm installation..."
if ! command -v pnpm &> /dev/null; then
    print_warning "pnpm is not installed. Installing pnpm..."
    npm install -g pnpm
    print_success "pnpm installed successfully"
else
    print_success "pnpm $(pnpm --version) detected"
fi

# Create .env file if it doesn't exist
print_info "Setting up environment variables..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        print_success "Created .env file from .env.example"
        print_warning "Please update .env with your configuration"
    else
        print_error ".env.example not found"
        exit 1
    fi
else
    print_success ".env file already exists"
fi

# Install dependencies
print_info "Installing dependencies..."
pnpm install
print_success "Dependencies installed"

# Create SQLite directory
print_info "Creating database directory..."
mkdir -p prisma/sqlite
print_success "Database directory created"

# Run Prisma migrations
print_info "Running database migrations..."
export DATABASE_URL="file:./prisma/sqlite/sqlite.db"
pnpm -C prisma exec prisma migrate deploy
print_success "Database migrations completed"

# Generate Prisma Client
print_info "Generating Prisma Client..."
pnpm -C prisma exec prisma generate
print_success "Prisma Client generated"

# Run seed
print_info "Seeding database..."
pnpm run seed
print_success "Database seeded"

echo ""
echo "================================"
print_success "Setup completed successfully!"
echo ""
print_info "Next steps:"
echo "  1. Review and update .env file with your configuration"
echo "  2. Run 'pnpm dev' to start the development server"
echo "  3. Open http://localhost:3000 in your browser"
echo ""
print_info "Default credentials:"
echo "  Email: admin@local"
echo "  Password: admin123!"
echo ""
print_warning "Remember to change the default password in production!"
echo ""
