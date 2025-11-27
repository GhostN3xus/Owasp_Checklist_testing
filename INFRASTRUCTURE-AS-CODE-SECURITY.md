# 🏗️ Infrastructure as Code (IaC) Security - Guia Didático Completo

## Terraform, CloudFormation, Ansible - Do Zero ao Expert

---

## 📖 Índice

1. [O que é IaC?](#oque-iac)
2. [Por que IaC é importante?](#por-que)
3. [Terraform Security - Completo](#terraform)
4. [CloudFormation Security](#cloudformation)
5. [Ansible Security](#ansible)
6. [Ferramentas de Scanning](#ferramentas)
7. [Casos de Ataque Reais](#casos-reais)

---

## O que é IaC? {#oque-iac}

### 📌 Conceito Simples

IaC (Infrastructure as Code) significa **escrever código para criar infraestrutura**.

```
ANTES (Manual, arriscado):
┌──────────────────────────┐
│ 1. Logar no AWS Console  │
│ 2. Clicar em "EC2"       │
│ 3. Clicar "Launch"       │
│ 4. Selecionar opções     │
│ 5. Clicar botões         │
│ 6. Esperar...            │
│ Resultado: Máquina criada│
│ Problema: Não repetível! │
└──────────────────────────┘

DEPOIS (IaC, automático):
┌──────────────────────────┐
│ resource "aws_instance"  │
│ {                        │
│   ami = "ami-0c02fb66"  │
│   instance_type = "t2..." │
│   ...                    │
│ }                        │
│ $ terraform apply        │
│ Resultado: Automático!   │
│ Vantagem: Repetível,     │
│ versionado, auditável    │
└──────────────────────────┘
```

### 🔧 Ferramentas IaC Principais

| Ferramenta | Provedor | Foco | Linguagem |
|-----------|----------|------|-----------|
| **Terraform** | Multi-cloud (AWS, Azure, GCP) | Infrastructure | HCL |
| **CloudFormation** | AWS only | Infrastructure | JSON/YAML |
| **ARM Templates** | Azure only | Infrastructure | JSON |
| **Ansible** | Multi-cloud | Configuration | YAML |
| **Puppet** | Multi-cloud | Configuration | DSL |
| **Chef** | Multi-cloud | Configuration | Ruby |

---

## Por que IaC é importante? {#por-que}

### 🎯 Benefícios (e Riscos de Segurança)

```
✓ BENEFÍCIO 1: Automação
  └─ Criar 100 servidores: 1 comando
  └─ RISCO: Erros em escala (1 erro = 100 afetados)

✓ BENEFÍCIO 2: Rastreabilidade (Git)
  └─ Histórico de todas as mudanças
  └─ RISCO: Secrets em Git podem vazar

✓ BENEFÍCIO 3: Consistência
  └─ Mesmo setup em dev/staging/prod
  └─ RISCO: Vulnerabilidade em dev = prod também

✓ BENEFÍCIO 4: Reversão Rápida
  └─ Revertir para versão anterior
  └─ RISCO: Pode restaurar com dados antigos

✓ BENEFÍCIO 5: Escalabilidade
  └─ Crescer rapidamente
  └─ RISCO: Crescer com vulnerabilidades
```

---

## Terraform Security - Completo {#terraform}

### 📌 O que é Terraform?

```
Terraform = Ferramenta open-source para definir infraestrutura em código

Arquivo: main.tf
┌──────────────────────┐
│ provider "aws" {     │
│   region = "us-east"│
│ }                    │
│                      │
│ resource "aws_..." { │
│   ...                │
│ }                    │
└──────────────────────┘

Comandos:
$ terraform init       # Download plugins
$ terraform plan       # Ver mudanças
$ terraform apply      # Aplicar mudanças
$ terraform destroy    # Deletar tudo
```

---

## PASSO A PASSO: Criar EC2 Segura com Terraform

### Passo 1: Estrutura de Arquivos

```bash
projeto/
├── main.tf               # Recursos principais
├── variables.tf          # Variáveis de entrada
├── outputs.tf            # Saídas
├── terraform.tfvars      # Valores das variáveis
├── .gitignore            # Git ignore secrets
├── backend.tf            # Backend remoto (S3)
└── modules/              # Módulos reutilizáveis
    └── security/
        └── security_group.tf
```

### Passo 2: Criar main.tf - VPC Segura

```hcl
# main.tf - Exemplo completo de infraestrutura segura

# 1. Provider
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # IMPORTANTE: Backend remoto para colaboração
  backend "s3" {
    bucket         = "meu-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true              # ✓ Criptografar state
    dynamodb_table = "terraform-lock"  # ✓ Evitar race conditions
  }
}

provider "aws" {
  region = var.aws_region

  # Tags padrão em todos os recursos
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      CreatedAt   = timestamp()
    }
  }
}

# 2. VPC (rede isolada)
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "vpc-${var.environment}"
  }
}

# 3. Security Group (firewall)
resource "aws_security_group" "web" {
  name_prefix = "sg-web-"
  vpc_id      = aws_vpc.main.id

  # ✓ Apenas HTTPS entrada
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ✓ HTTP redireciona para HTTPS
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ❌ NÃO: SSH de qualquer lugar
  # ingress {
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]  # PÉSSIMO!
  # }

  # ✓ SIM: SSH apenas de IP específico (bastion)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.bastion_ip]  # IP do bastion
  }

  # ✓ Saída: Apenas necessário (não all)
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Bloquear tudo mais
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["127.0.0.1/32"]  # Bloqueia tudo
  }

  tags = {
    Name = "sg-web"
  }
}

# 4. Subnet pública
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true  # ✓ IP público automático

  tags = {
    Name = "subnet-public"
  }
}

# 5. Subnet privada
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "subnet-private"
  }
}

# 6. Internet Gateway (saída para internet)
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "igw-main"
  }
}

# 7. NAT Gateway (para subnet privada acessar internet)
resource "aws_eip" "nat" {
  domain = "vpc"

  depends_on = [aws_internet_gateway.main]

  tags = {
    Name = "eip-nat"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  depends_on = [aws_internet_gateway.main]

  tags = {
    Name = "nat-gateway"
  }
}

# 8. Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = aws_internet_gateway.main.id
  }

  tags = {
    Name = "rt-public"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "rt-private"
  }
}

# 9. IAM Role para EC2 (Least Privilege)
resource "aws_iam_role" "ec2_role" {
  name = "ec2-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# ✓ Política: Apenas CloudWatch e S3 leitura
resource "aws_iam_role_policy" "ec2_policy" {
  name = "ec2-app-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::meu-bucket-app/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-app-profile"
  role = aws_iam_role.ec2_role.name
}

# 10. EC2 Instance (Aplicação Web)
resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
  monitoring                  = true  # ✓ CloudWatch detalhado

  # ✓ Criptografar volume raiz
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = aws_kms_key.ebs.arn
  }

  # ✓ User data para setup inicial (SEGURO)
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    app_repo = var.app_repository
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # ✓ IMDSv2 obrigatório
    http_put_response_hop_limit = 1
  }

  monitoring = true

  tags = {
    Name = "web-server-${var.environment}"
  }
}

# 11. KMS Key para criptografia
resource "aws_kms_key" "ebs" {
  description             = "KMS key para criptografia EBS"
  deletion_window_in_days = 10
  enable_key_rotation     = true  # ✓ Rotação automática

  tags = {
    Name = "kms-ebs"
  }
}

# Data sources
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Ubuntu

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}
```

### Passo 3: Arquivo variables.tf

```hcl
# variables.tf - Definir variáveis de entrada

variable "aws_region" {
  description = "Região AWS"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Ambiente (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment deve ser dev, staging ou prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR da VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR subnet pública"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR subnet privada"
  type        = string
  default     = "10.0.2.0/24"
}

variable "instance_type" {
  description = "Tipo de instância EC2"
  type        = string
  default     = "t2.micro"
}

variable "bastion_ip" {
  description = "IP do bastion para SSH"
  type        = string
  sensitive   = true  # ✓ Não mostrar em outputs
}

variable "app_repository" {
  description = "Repositório da aplicação (GitHub, etc)"
  type        = string
  sensitive   = true
}
```

### Passo 4: Arquivo terraform.tfvars

```hcl
# terraform.tfvars - Valores das variáveis
# ⚠️ NUNCA commitar este arquivo em Git!

aws_region           = "us-east-1"
environment          = "prod"
vpc_cidr             = "10.0.0.0/16"
public_subnet_cidr   = "10.0.1.0/24"
private_subnet_cidr  = "10.0.2.0/24"
instance_type        = "t2.small"
bastion_ip           = "203.0.113.50/32"  # IP fixo permitido
app_repository       = "https://github.com/company/app.git"
```

### Passo 5: .gitignore - Proteger Secrets

```bash
# .gitignore - Nunca commitar arquivos sensíveis

# Terraform
*.tfstate
*.tfstate.*
.terraform/
.terraform.lock.hcl
*.tfvars
!*.tfvars.example

# Secrets
.env
.env.local
.env.*.local
secrets/
*.pem
*.key

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Outputs sensíveis
outputs.json
```

### Passo 6: Executar Terraform (Passo a Passo)

```bash
# PASSO 1: Inicializar Terraform
$ terraform init
# Output:
# - Download AWS provider
# - Criar .terraform/ directory
# - Configurar S3 backend

# PASSO 2: Validar sintaxe
$ terraform validate
# Output:
# - Success: Configuration is valid

# PASSO 3: Ver que será criado
$ terraform plan -out=tfplan
# Output:
# + aws_vpc.main
# + aws_security_group.web
# + aws_subnet.public
# + aws_subnet.private
# + aws_internet_gateway.main
# + aws_nat_gateway.main
# + aws_instance.web
# Plan: 11 to add, 0 to change, 0 to destroy

# PASSO 4: Revisar plan (CRÍTICO!)
# Verificar:
# - Security groups corretos?
# - CIDR blocks corretos?
# - IAM policies least privilege?
# - Criptografia habilitada?

# PASSO 5: Aplicar mudanças
$ terraform apply tfplan
# Output:
# aws_vpc.main: Creating...
# aws_vpc.main: Creation complete
# ... etc

# PASSO 6: Salvar outputs
$ terraform output -json > outputs.json

# PASSO 7: Verificar em produção
$ aws ec2 describe-instances --region us-east-1

# PASSO 8: Se erro, voltar atrás
$ terraform destroy
# Responder: yes
# Tudo deletado
```

---

## 🔒 Terraform Security Best Practices

### Checklist de Segurança

```
PRÉ-DEPLOYMENT:

[ ] Backend
    [ ] S3 bucket com versionamento
    [ ] Criptografia S3 habilitada
    [ ] Acesso restrito (IAM policy)
    [ ] DynamoDB lock table
    [ ] Logging S3 ativado

[ ] State File
    [ ] Nunca commitado em Git
    [ ] .gitignore configurado
    [ ] Acesso restrito (IAM)
    [ ] Criptografia em repouso

[ ] Secrets
    [ ] Nenhum secret em código
    [ ] Usar AWS Secrets Manager
    [ ] Usar variáveis sensíveis (sensitive = true)
    [ ] Rotar credentials regularmente

[ ] IAM
    [ ] Least privilege principle
    [ ] Roles específicos por função
    [ ] Audit logging habilitado
    [ ] MFA para produção

[ ] Networking
    [ ] VPC isolada
    [ ] Subnets públicas/privadas separadas
    [ ] NAT gateway para saída privada
    [ ] Security groups restritivos
    [ ] NACLs configurados

[ ] Compute
    [ ] IMDSv2 obrigatório
    [ ] Volumes criptografados
    [ ] Monitoring habilitado
    [ ] Auto-scaling configurado

[ ] Compliance
    [ ] Tags em todos recursos
    [ ] Versão Terraform especificada
    [ ] Renovação de certificados
    [ ] Backup habilitado

PÓS-DEPLOYMENT:

[ ] Verificar recuros criados
[ ] Testar conectividade
[ ] Validar segurança groups
[ ] Verificar IAM permissions
[ ] Setup monitoramento
[ ] Documentar mudanças
```

---

## 🛠️ Ferramentas de Scanning IaC {#ferramentas}

### 1. Checkov (GRÁTIS, Recomendado)

```bash
# Instalação
pip install checkov

# Scan de arquivo Terraform
checkov -f main.tf

# Scan de diretório completo
checkov -d . --framework terraform

# Saída:
# Passed checks: 45
# Failed checks: 12
# Skipped checks: 3

# Ver checks específicas
checkov -f main.tf --check CKV_AWS_1

# Gerar relatório
checkov -f main.tf -o json > checkov_report.json

# Filtrar por severidade
checkov -f main.tf --framework terraform --severity HIGH CRITICAL
```

### 2. TFLint (Terraform Lint)

```bash
# Instalação
brew install tflint

# Scan
tflint . --format json

# Validar AWS best practices
tflint --init  # Baixar rules AWS
tflint .

# Saída:
# aws_instance.web: Missing tags in resource
# aws_security_group.web: Allow all traffic in ingress
```

### 3. Terraform Scan (Snyk)

```bash
# Instalação
npm install -g snyk

# Scan Terraform
snyk iac test main.tf

# Saída:
# Security issues found:
# High: Unrestricted SSH access (0.0.0.0/0)
```

### 4. TFSecScan

```bash
# Instalação
pip install tfsec

# Scan
tfsec . --format json

# Saída:
# aws_security_group.web:
#   Rule violations: 1
#   - Allowing unrestricted ingress access to port 22
```

---

## 📋 Exemplo Completo: Análise com Falhas de Segurança

### ❌ main.tf - Com Vulnerabilidades

```hcl
# ❌ PÉSSIMO - NÃO USAR COMO REFERÊNCIA

resource "aws_security_group" "web" {
  # ❌ Permite SSH de qualquer lugar!
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ❌ Permite todos os protocolos
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  # ❌ Sem criptografia!
  storage_encrypted = false

  # ❌ Sem backup automático
  backup_retention_period = 0

  # ❌ Acesso público (muito perigoso para BD)
  publicly_accessible = true

  # ❌ Master username/password em plaintext
  username = "admin"
  password = "Password123!"  # VAZADO!
}

resource "aws_s3_bucket" "app" {
  # ❌ Bucket público (todos podem ler!)
  acl = "public-read"

  # ❌ Sem criptografia
  # (precisa adicionar server_side_encryption_configuration)
}

resource "aws_instance" "web" {
  # ❌ Sem criptografia de volumes
  # (não foi especificado encrypted = true)

  # ❌ Sem IAM role (credenciais em user-data?)
  user_data = base64encode(<<-EOF
              #!/bin/bash
              export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"  # VAZADO!
              export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI..."  # VAZADO!
              EOF
  )
}

# ❌ Não há backend S3
# ❌ Não há validação de variáveis
# ❌ Não há tagging
# ❌ State file será local (compartilhável!)
```

### ✓ Análise com Ferramentas

```bash
$ checkov -f main.tf

# Resultado:
# Check: "Ensure all data stored in the S3 is encrypted"
#   FAILED for resource: aws_s3_bucket.app
#   Fix: Add server_side_encryption_configuration

# Check: "Ensure security group rules do not allow ingress from 0.0.0.0:0 to port 22"
#   FAILED for resource: aws_security_group.web
#   Fix: Restrict SSH access

# Check: "Ensure DB instance encryption is enabled"
#   FAILED for resource: aws_db_instance.main
#   Fix: Set storage_encrypted = true

# 12 checks failed, 3 passed
```

---

## 🎯 Passo a Passo Completo: Deployar Aplicação Segura

### FASE 1: Preparação (30 minutos)

```bash
# 1. Criar diretório
mkdir terraform-app && cd terraform-app

# 2. Criar estrutura
touch main.tf variables.tf outputs.tf terraform.tfvars .gitignore

# 3. Editar .gitignore (copiar acima)

# 4. Editar variables.tf (copiar acima)

# 5. Editar main.tf (copiar acima, sem vulnerabilidades)

# 6. Editar terraform.tfvars (copiar acima)

# 7. Inicializar Git
git init
git add .gitignore main.tf variables.tf outputs.tf
git add .terraform.lock.hcl  # Importante para versionamento
git commit -m "Initial terraform configuration"

# 8. Criar repositório remoto em GitHub

git remote add origin https://github.com/seu-user/terraform-app.git
git push -u origin main
```

### FASE 2: Validação (30 minutos)

```bash
# 1. Instalar ferramentas
pip install checkov
brew install tfsec
npm install -g snyk

# 2. Validar sintaxe
terraform validate

# 3. Scan com Checkov
checkov -f main.tf --framework terraform

# 4. Scan com Tfsec
tfsec .

# 5. Scan com Snyk
snyk iac test main.tf

# 6. Revisar outputs
checkov -f main.tf -o json > report.json
```

### FASE 3: Planning (20 minutos)

```bash
# 1. Assumir credenciais AWS
export AWS_PROFILE=production
export AWS_REGION=us-east-1

# 2. Terraform init
terraform init

# 3. Terraform plan
terraform plan -out=tfplan

# 4. REVISAR O PLAN COMPLETO
cat tfplan | grep -E "aws_security_group|aws_instance|aws_vpc"

# 5. Verificar conta AWS
aws sts get-caller-identity

# 6. Verificar limites
aws service-quotas list-service-quotas --service-code ec2
```

### FASE 4: Approval (Reunião - 30 minutos)

```
Apresentar ao time:
1. Mostrar terraform plan
2. Mostrar security scan results
3. Explicar cada recurso criado
4. Obter aprovação escrita (email)
5. Documentar decision log
```

### FASE 5: Deployment (15 minutos)

```bash
# 1. ÚLTIMO CHECK
terraform plan | tail -20

# 2. APLICAR (com cuidado!)
terraform apply tfplan

# Output esperado:
# Apply complete! Resources: 11 added
# Outputs:
#   instance_public_ip = "54.123.45.67"
#   vpc_id = "vpc-0123456789abcdef"

# 3. Salvar outputs
terraform output -json > deployment_outputs.json

# 4. Verificar em AWS
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[PublicIpAddress,State.Name]'
```

### FASE 6: Validação Pós-Deploy (30 minutos)

```bash
# 1. SSH (via bastion)
ssh -J bastion@10.0.0.1 ubuntu@10.0.1.50

# 2. Verificar segurança
curl -v https://54.123.45.67  # HTTPS deve funcionar

# 3. Verificar logs
aws logs tail /aws/ec2/web-server --follow

# 4. Verificar monitoramento
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-0123456789 \
  --start-time 2025-01-01T00:00:00Z \
  --end-time 2025-01-01T01:00:00Z \
  --period 300 \
  --statistics Average

# 5. Documentar em wiki/confluence
# - Data de deployment
# - Versão Terraform
# - Recursos criados
# - Contato responsável
```

---

## 📚 Comandos Terraform Essenciais

| Comando | Função | Quando usar |
|---------|--------|-----------|
| `terraform init` | Inicializar | Primeira vez |
| `terraform validate` | Validar sintaxe | Antes de plan |
| `terraform plan` | Ver mudanças | Sempre antes apply |
| `terraform apply` | Aplicar mudanças | Deployment |
| `terraform destroy` | Deletar tudo | Cleanup/Dev |
| `terraform state list` | Listar recursos | Auditoria |
| `terraform state show` | Ver detalhes | Debug |
| `terraform import` | Importar recurso | Migração |
| `terraform refresh` | Sincronizar | Após mudanças manuais |
| `terraform output` | Ver outputs | Recuperar valores |

---

## 🚨 Casos de Ataque Reais {#casos-reais}

### Caso 1: State File Vazado no Git

```bash
# ❌ O que aconteceu:
# 1. Desenvolvedor commitou terraform.tfstate
# 2. State continha secrets (RDS password, AWS keys)
# 3. Código foi para repositório público no GitHub
# 4. Bot de scanning detectou secrets

# Resultado: Conta AWS comprometida

# ✓ Prevenção:
# 1. Sempre use .gitignore
# 2. Usar secret scanning (GitHub, Snyk)
# 3. Rotar credentials imediatamente
# 4. Usar AWS Secrets Manager em vez de plaintext
```

### Caso 2: Security Group muito Aberto

```hcl
# ❌ O que aconteceu:
resource "aws_security_group" "database" {
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Qualquer um pode acessar!
  }
}

# Resultado: Banco de dados exposto, dados vazados

# ✓ Correto:
resource "aws_security_group" "database" {
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]  # Só da app
  }
}
```

### Caso 3: Scaling Automático com Bug

```hcl
# ❌ O que aconteceu:
resource "aws_autoscaling_group" "app" {
  max_size = 100
  # Terraform tem bug, cria 1000 instâncias por acidente
  # Conta fica $100.000 em minutos!

  # Resultado: AWS bill shock

# ✓ Proteção:
  # 1. Cost alerts em CloudWatch
  # 2. Terraform limits em max_size
  # 3. Code review obrigatório para ASG
  # 4. Testes em staging primeiro
}
```

---

## 📊 Checklist Final - IaC Segura

```
ANTES DE COMMITAR:

[ ] .gitignore
    [ ] *.tfstate
    [ ] *.tfvars
    [ ] *.key, *.pem
    [ ] .env

[ ] Código Terraform
    [ ] Sem hardcoded secrets
    [ ] Variáveis sensíveis marcadas
    [ ] Backend S3 configurado
    [ ] Validações em variáveis

[ ] Segurança
    [ ] Security groups restritivos
    [ ] IAM least privilege
    [ ] Criptografia habilitada (EBS, RDS, S3)
    [ ] Logging ativado

[ ] Scanning
    [ ] Checkov passed
    [ ] Tfsec passed
    [ ] Snyk iac test passed
    [ ] Sem HIGH/CRITICAL issues

[ ] Documentação
    [ ] Comentários em código
    [ ] README.md
    [ ] Changelog
    [ ] Runbooks

[ ] Testes
    [ ] terraform plan OK
    [ ] terraform validate OK
    [ ] Terraform format correct
    [ ] Outputs corretos

PÓS-DEPLOYMENT:

[ ] Verificar recursos criados
[ ] Testar conectividade
[ ] Validar segurança
[ ] Setup alertas
[ ] Documentar em wiki
```

---

<div align="center">

**⭐ IaC é código, aplique segurança de software!**

**Terraform plan = revisão de código (sempre revisar!)**

**Secrets nunca em Git, sempre em Secret Manager**

**Automatizar segurança = Scanning em CI/CD**

</div>
