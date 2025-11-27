# 🔬 Montar Laboratório de Testes de Segurança

## Guia Completo para Iniciantes - Setup Local e Seguro

---

## 📖 Índice

1. [Por que um Laboratório?](#por-que)
2. [Requisitos de Hardware](#hardware)
3. [Setup Local (Single PC)](#setup-local)
4. [Setup com VirtualBox](#virtualbox)
5. [Aplicações Vulneráveis Práticas](#apps-vulneraveis)
6. [Plataformas Online Recomendadas](#plataformas-online)
7. [Estrutura do Lab](#estrutura)

---

## Por que um Laboratório? {#por-que}

### 📌 Razões

```
✓ Praticar sem medo de quebrar coisa real
✓ Testar exploits com segurança
✓ Aprender em ambiente controlado
✓ Documentar procedimentos
✓ Prepara para testes reais (pentests)
✓ Construir portfolio
```

### ⚠️ Regras Éticas

```
✓ LEGAL     → Seus próprios VMs, plataformas autorizadas
✗ ILEGAL    → Testar em redes/apps que não sua
✓ MORAL     → Divulgar responsavelmente, ajudar
✗ IMORAL    → Vender exploits, prejudicar pessoas
```

---

## Requisitos de Hardware {#hardware}

### Mínimo para Começar

```
Mínimo:
├─ CPU: Dual core 2GHz+
├─ RAM: 8GB (4GB para host, 4GB para VMs)
├─ Disco: 200GB SSD (50GB host, 150GB VMs)
└─ Rede: Conexão Internet

Recomendado:
├─ CPU: 6+ cores
├─ RAM: 16GB+
├─ Disco: 500GB+ SSD
└─ Rede: Gigabit + VPN (opcional)

Ideal (Professional):
├─ CPU: 8+ cores
├─ RAM: 32GB+
├─ Disco: 1TB+ SSD NVMe
├─ GPU: RTX 3060+ (para hashcracking)
└─ Rede: 10G + Segura
```

---

## Setup Local (Single PC) {#setup-local}

### 📌 Prós e Contras

**Prós:**
- Custo zero
- Simples de usar
- Bom para começar

**Contras:**
- Menos isolado
- Performance limitada
- Difícil criar múltiplas máquinas

### 🔧 Opção 1: Docker (Recomendado para Web)

**Instalar Docker:**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose

# Iniciar daemon
sudo systemctl start docker

# Testar
docker --version
docker run hello-world
```

**Aplicação Vulnerável com Docker:**

```yaml
# docker-compose.yml
version: '3.8'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"
    environment:
      - MYSQL_ROOT_PASSWORD=root
    networks:
      - lab

  bwapp:
    image: raesene/bwapp
    ports:
      - "8080:80"
    networks:
      - lab

  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
    networks:
      - lab

networks:
  lab:
    driver: bridge
```

**Rodar:**

```bash
docker-compose up -d
# DVWA: http://localhost
# BWAPP: http://localhost:8080
# Juice Shop: http://localhost:3000
```

### 🔧 Opção 2: Máquinas Virtuais (VirtualBox)

Mais avançado, melhor isolamento.

---

## Setup com VirtualBox {#virtualbox}

### 1️⃣ Instalar VirtualBox

```bash
# Ubuntu/Debian
sudo apt install virtualbox virtualbox-ext-pack

# Windows
# Baixar de https://www.virtualbox.org/

# macOS
brew install virtualbox
```

### 2️⃣ Criar Rede Isolada

```
Configuração VirtualBox:
1. File → Preferences → Network
2. Criar nova rede:
   ├─ Nome: TestLab
   ├─ Modo: Internal Network
   └─ DHCP: ON

Isso isola o lab do resto da rede
```

### 3️⃣ Criar Máquina Alvo (Vulnerable)

**VM 1: DVWA em Ubuntu**

```bash
1. Criar nova VM
   ├─ Name: DVWA
   ├─ Type: Linux
   ├─ Version: Ubuntu 20.04
   ├─ RAM: 2GB
   ├─ Disk: 20GB
   └─ Network: TestLab internal

2. Instalar Ubuntu (escolha minimal)

3. Instalar DVWA:
   sudo apt update
   sudo apt install -y apache2 mysql-server php php-mysql php-gd

4. Clonar DVWA:
   cd /var/www/html
   sudo git clone https://github.com/digininja/DVWA.git

5. Configurar:
   sudo chown -R www-data:www-data DVWA/
   cd DVWA/config
   cp config.inc.php.dist config.inc.php

6. Criar BD:
   mysql -u root -p
   > CREATE DATABASE dvwa;
   > GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';

7. Acessar:
   http://IP_DA_VM/DVWA
   admin / password
```

### 4️⃣ Criar Máquina Ataque (Kali)

**VM 2: Kali Linux (Attacker)**

```bash
1. Baixar Kali VM pronta: https://www.kali.org/get-kali/
   (Já vem com todas as ferramentas)

2. Importar em VirtualBox

3. Network: Conectar à mesma TestLab

4. Pronto para usar!
   root / kali (ou sua senha customizada)
```

### 5️⃣ Snapshot (Salvar Estado)

**Criar pontos de restauração:**

```
VirtualBox → Selecionar VM → Take Snapshot

Nomes úteis:
├─ Base (instalação limpa)
├─ DVWA-Setup (com DVWA instalado)
├─ After-First-Attack (após primeiro teste)
└─ Before-Cleanup (antes de limpar logs)

Restaurar:
Máquina → Snapshots → Restaurar
```

---

## Aplicações Vulneráveis Práticas {#apps-vulneraveis}

### 📋 Ranking por Dificuldade

**INICIANTE:**

1. **DVWA (Damn Vulnerable Web App)**
   - Site: https://github.com/digininja/DVWA
   - Foco: OWASP Top 10 básico
   - Tempo: 4-8 horas
   - Recomendação: ⭐⭐⭐⭐⭐

2. **WebGoat (OWASP)**
   - Site: https://github.com/WebGoat/WebGoat
   - Foco: Lições interativas
   - Tempo: 8-12 horas
   - Recomendação: ⭐⭐⭐⭐⭐

3. **BWAPP (Buggy Web App)**
   - Site: http://www.itsecgames.com/
   - Foco: 100+ vulnerabilidades
   - Tempo: 12+ horas
   - Recomendação: ⭐⭐⭐⭐

**INTERMEDIÁRIO:**

4. **OWASP Juice Shop**
   - Site: https://github.com/juice-shop/juice-shop
   - Foco: Aplicação moderna (Node.js)
   - Tempo: 20+ horas
   - Recomendação: ⭐⭐⭐⭐⭐

5. **Hack.me**
   - Site: https://hack.me/
   - Foco: Vulnerabilidades reais
   - Tempo: Variável
   - Recomendação: ⭐⭐⭐⭐

6. **Mutillidae II**
   - Site: https://www.owasp.org/index.php/Mutillidae_2
   - Foco: 28+ categorias de vulnerabilidades
   - Tempo: 20+ horas
   - Recomendação: ⭐⭐⭐⭐

**AVANÇADO:**

7. **WebGoat 8.x (versão nova)**
   - Foco: Segurança em profundidade
   - Recomendação: ⭐⭐⭐⭐

8. **PortSwigger Web Security Academy**
   - Site: https://portswigger.net/web-security
   - Foco: Especializado por tópico
   - Recomendação: ⭐⭐⭐⭐⭐

---

## Plataformas Online Recomendadas {#plataformas-online}

### 🎓 Aprendizado Prático (CTF)

**GRÁTIS:**

```
1. TryHackMe
   https://tryhackme.com/
   ├─ Máquinas pré-prontas
   ├─ Cursos interativos
   ├─ Dificuldade: Iniciante → Avançado
   └─ Recomendação: ⭐⭐⭐⭐⭐

2. HackTheBox
   https://www.hackthebox.com/
   ├─ Máquinas reais
   ├─ Comunidade ativa
   ├─ Mais desafiador que TryHackMe
   └─ Recomendação: ⭐⭐⭐⭐⭐

3. OWASP WebGoat
   https://github.com/WebGoat/WebGoat
   ├─ Lições de segurança web
   ├─ Muito bom para fundamentals
   └─ Recomendação: ⭐⭐⭐⭐⭐

4. PortSwigger Academy
   https://portswigger.net/web-security
   ├─ Tutoriais de segurança web
   ├─ Labs práticos
   ├─ GRATUITO completo
   └─ Recomendação: ⭐⭐⭐⭐⭐

5. PentesterLab
   https://pentesterlab.com/
   ├─ Exercícios pen-testing
   ├─ PRO é pago ($200/ano)
   ├─ Grátis limitado
   └─ Recomendação: ⭐⭐⭐⭐

6. Overthewire Wargames
   https://overthewire.org/wargames/
   ├─ Desafios de terminal
   ├─ Grátis online
   └─ Recomendação: ⭐⭐⭐⭐

7. root-me
   https://www.root-me.org/
   ├─ 500+ desafios
   ├─ Categorias várias
   └─ Recomendação: ⭐⭐⭐⭐
```

**PAGOS (com desconto):**

```
1. Offensive Security PWK/OSCP
   https://www.offensive-security.com/pwk-oscp/
   ├─ Certificação reconhecida
   ├─ $1,198 por 30 dias de lab
   ├─ Muito completo
   └─ Vale o investimento

2. eLearnSecurity
   https://www.elearnsecurity.com/
   ├─ eJPT (grátis!), eWPT, eWPTX
   ├─ Cursos + certificação
   └─ Boa relação custo-benefício
```

---

## Estrutura Recomendada do Lab {#estrutura}

### 🏗️ Arquitetura

```
LAB NETWORK (Isolada da Internet)
│
├─ [ROUTER VM]
│  └─ IP: 192.168.100.1
│  └─ DHCP: 192.168.100.100-200
│
├─ [ALVO 1: DVWA]
│  └─ IP: 192.168.100.10
│  └─ SO: Ubuntu 20.04 + Apache + MySQL
│  └─ Vulnerabilidades: OWASP Top 10
│
├─ [ALVO 2: Juice Shop]
│  └─ IP: 192.168.100.11
│  └─ SO: Ubuntu 20.04 + Node.js
│  └─ Vulnerabilidades: App moderna
│
├─ [ALVO 3: Windows Server]
│  └─ IP: 192.168.100.20
│  └─ SO: Windows Server 2019
│  └─ Vulnerabilidades: AD, MSSQL
│
└─ [ATACANTE: Kali]
   └─ IP: 192.168.100.50
   └─ SO: Kali Linux
   └─ Ferramentas: Burp, Nmap, Metasploit, etc.

(Tudo isolado = Host ↔ TestLab Network ↔ Atacante+Alvos)
```

### 📋 Checklist Setup

```
Iniciante (1-2 dias):
[ ] VirtualBox instalado
[ ] DVWA rodando em Docker ou VM
[ ] Acessar DVWA no navegador
[ ] Fazer login (admin/password)
[ ] Testar primeira vulnerabilidade (Injection)

Intermediário (1 semana):
[ ] Kali Linux VM criada
[ ] Nmap escanear DVWA
[ ] Burp Suite Community configurado
[ ] Interceptar requisições HTTP
[ ] Testar SQL Injection manualmente
[ ] Testar XSS
[ ] Executar Nuclei contra target

Avançado (2-4 semanas):
[ ] Juice Shop rodando
[ ] WebGoat rodando
[ ] Windows Server como target
[ ] Active Directory vulnerável (Vulnlab)
[ ] Lateral movement prático
[ ] Privilege escalation prático
[ ] Relatórios documentados
```

---

## 🛠️ Ferramentas Essenciais Lab

### Instalação em Kali

```bash
# Já vem instalado:
kali-linux-core  # Ferramentas principais

# Instalações adicionais recomendadas:
sudo apt update
sudo apt install -y burp-suite-community
sudo apt install -y nuclei
sudo apt install -y chisel
sudo apt install -y bloodhound
```

### Organização Local

```
~/lab/
├── apps/
│   ├── dvwa/
│   ├── juice-shop/
│   └── bwapp/
├── notes/
│   ├── findings.md
│   └── checklists.md
├── tools/
│   ├── scripts/
│   └── configs/
└── reports/
    ├── pentest-report-template.docx
    └── completed-reports/
```

---

## 📊 Plano de Prática Recomendado

### Semana 1: Fundações
```
Dia 1-2: DVWA Setup + Acesso básico
Dia 3-4: SQLi + XSS manual
Dia 5-6: Burp Suite + Intruder
Dia 7: Documentar findings
```

### Semana 2-3: Técnicas Intermediárias
```
DVWA:
  ├─ CSRF
  ├─ Authentication bypass
  ├─ File upload
  └─ Remote Code Execution

Documentar cada um com screenshots
```

### Semana 4: Aplicação Real
```
Juice Shop:
  ├─ Reconhecimento
  ├─ Scanning
  ├─ Exploração
  └─ Relatório profissional
```

### Mês 2: Plataformas Online
```
TryHackMe:
  ├─ Web Security paths
  ├─ Penetration Testing
  └─ Linux Security

HackTheBox:
  └─ Máquinas fáceis (Retired)
```

---

## ⚙️ Troubleshooting Comum

### Problema: VM muito lenta

**Solução:**
```bash
1. Aumentar CPU cores (VM settings)
2. Aumentar RAM (mínimo 2GB por VM)
3. Usar SSD em vez de HDD
4. Desabilitar efeitos visuais (VM)
5. Fechar outras aplicações no host
```

### Problema: VMs não conseguem se comunicar

**Solução:**
```bash
1. Verificar rede: VirtualBox → Preferences → Network
2. Ambas em "Internal Network" com mesmo nome
3. Dar IP fixed: sudo nano /etc/netplan/00-installer-config.yaml
4. Testear: ping entre VMs
```

### Problema: Port já em uso (Docker)

**Solução:**
```bash
# Ver portas em uso
lsof -i -P -n | grep LISTEN

# Mudar porta no docker-compose.yml
ports:
  - "8000:80"  # 8000 em vez de 80
```

---

## 📚 Referências

- [TryHackMe Learning Path](https://tryhackme.com/welcome)
- [HackTheBox Starting Point](https://www.hackthebox.com/home/start)
- [DVWA GitHub](https://github.com/digininja/DVWA)
- [Juice Shop](https://github.com/juice-shop/juice-shop)

---

<div align="center">

**⭐ Praticar é a melhor forma de aprender segurança**

**Comece simples, aumente a dificuldade gradualmente**

**Documente tudo para construir seu portfolio**

</div>
