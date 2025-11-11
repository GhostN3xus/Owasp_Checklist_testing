#!/bin/bash

# OWASP Checklist Reset Script
# This script resets the database and re-seeds it

set -e  # Exit on error

echo "🔄 OWASP Checklist Reset Script"
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

# Confirm reset
print_warning "This will delete all data in the database!"
read -p "Are you sure you want to continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Reset cancelled"
    exit 0
fi

# Remove SQLite database
print_info "Removing database..."
rm -rf prisma/sqlite
mkdir -p prisma/sqlite
print_success "Database removed"

# Remove migrations folder
print_info "Removing migrations..."
rm -rf prisma/migrations
print_success "Migrations removed"

# Run migrations
print_info "Creating fresh database..."
export DATABASE_URL="file:./prisma/sqlite/sqlite.db"
pnpm -C prisma exec prisma migrate dev --name init --skip-seed
print_success "Database created"

# Run seed
print_info "Seeding database..."
pnpm run seed
print_success "Database seeded"

echo ""
print_success "Reset completed successfully!"
echo ""
print_info "Default credentials:"
echo "  Email: admin@local"
echo "  Password: admin123!"
echo ""
