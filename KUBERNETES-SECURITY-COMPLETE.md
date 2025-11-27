# ☸️ Kubernetes Security - Guia Completo do Zero ao Expert

## Segurança em Containers e Orquestração - Passo a Passo

---

## 📖 Índice

1. [O que é Kubernetes?](#oque-k8s)
2. [Arquitetura de Segurança K8s](#arquitetura)
3. [Segurança em Cada Camada](#camadas)
4. [Passo a Passo: Cluster Seguro](#passo-a-passo)
5. [RBAC - Controle de Acesso](#rbac)
6. [Network Policies](#network)
7. [Pod Security](#pod-security)
8. [Scanning e Monitoramento](#scanning)
9. [Casos de Ataque](#casos)

---

## O que é Kubernetes? {#oque-k8s}

### 📌 Explicação Simples

Kubernetes (K8s) é um **orquestrador de containers** que:
- Executa containers automaticamente
- Gerencia recursos
- Escala aplicações
- Executa atualizações sem downtime
- Recupera de falhas

```
ANTES (Manual):
┌─────────────────────┐
│ 1. SSH em servidor  │
│ 2. docker run app   │
│ 3. Abrir porta 8080 │
│ 4. Configurar DNS   │
│ 5. Setup monitoring │
│ 6. ... manualmente  │
└─────────────────────┘

DEPOIS (Kubernetes):
┌──────────────────────────┐
│ kubectl apply -f app.yaml│
│ Tudo automaticamente!    │
│ - Container rodando      │
│ - DNS configurado        │
│ - Monitoring setup       │
│ - Auto-scaling ativado   │
│ - Updates automáticas    │
└──────────────────────────┘
```

### 🔧 Conceitos Principais

```
CLUSTER (todo sistema K8s)
    ├─ CONTROL PLANE (cérebro)
    │  ├─ API Server (porta 6443)
    │  ├─ ETCD (BD de estado)
    │  ├─ Scheduler (aloca pods)
    │  └─ Controller Manager (mantém estado)
    │
    └─ NODES (trabalhadores)
       ├─ Node 1 (kubelet + docker)
       ├─ Node 2 (kubelet + docker)
       └─ Node 3 (kubelet + docker)

RECURSOS K8s:
    ├─ POD (container em execução)
    ├─ SERVICE (acesso ao pod)
    ├─ DEPLOYMENT (múltiplos pods, updates)
    ├─ NAMESPACE (isolamento lógico)
    ├─ RBAC (permissões)
    ├─ NETWORK POLICY (firewall)
    └─ SECRET (dados sensíveis)
```

---

## Arquitetura de Segurança K8s {#arquitetura}

### 🔒 Camadas de Segurança

```
LAYER 1: HOST SECURITY
    ├─ OS hardening
    ├─ Kernel patches
    ├─ Firewall
    └─ SSH configurado

LAYER 2: CLUSTER SECURITY
    ├─ API Server autenticação
    ├─ ETCD criptografado
    ├─ Kubelet hardening
    └─ Component isolation

LAYER 3: CONTAINER SECURITY
    ├─ Image scanning
    ├─ Runtime policies
    ├─ Resource limits
    └─ Read-only filesystem

LAYER 4: APPLICATION SECURITY
    ├─ RBAC (Role-based access)
    ├─ Network policies
    ├─ Pod security policies
    └─ Secrets management

LAYER 5: NETWORK SECURITY
    ├─ Network segmentation
    ├─ Ingress firewall
    ├─ Egress filtering
    └─ mTLS (mutual TLS)
```

---

## Segurança em Cada Camada {#camadas}

### LAYER 1: Image Security

#### ❌ Imagem Insegura

```dockerfile
# ❌ NÃO FAZER ISSO!

FROM ubuntu:latest  # ❌ latest é mutable
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    openssh-server  # ❌ Não precisa!

RUN npm install -g  # ❌ Todas dependências
RUN pip install -r requirements.txt  # ❌ Sem versioning

EXPOSE 22  # ❌ SSH em container!
RUN echo "root:password" | chpasswd  # ❌ Senha hardcoded!

COPY . /app
WORKDIR /app
CMD ["npm", "start"]  # ❌ Executa como root!
```

#### ✓ Imagem Segura

```dockerfile
# ✓ FAZER ASSIM!

# Multi-stage build (menor tamanho)
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production  # ✓ Versionado

COPY . .
RUN npm run build

# Final stage (production)
FROM node:18-alpine

# ✓ Não executa como root
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules

# ✓ Read-only filesystem (exceto /tmp)
RUN chmod -R 555 /app

# ✓ Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {if (r.statusCode !== 200) throw new Error()})"

# ✓ Executa como usuário não-root
USER appuser:appgroup

EXPOSE 3000
CMD ["node", "dist/index.js"]
```

#### 🔍 Scanning de Imagem

```bash
#!/bin/bash

# Antes de deployar, escanear:

# 1. Trivy (recomendado)
trivy image myapp:1.0
# Output:
# Vulnerabilities found: 45
#   CRITICAL: 5
#   HIGH: 12
#   MEDIUM: 28

# 2. Snyk
snyk container test myapp:1.0

# 3. Clair
clairctl report myapp:1.0

# Falha se encontrar CRITICAL/HIGH
if [ $? -ne 0 ]; then
  echo "Image scan failed"
  exit 1
fi

# Só depois fazer push
docker push myapp:1.0
```

---

### LAYER 2: Cluster Hardening

#### 🔐 API Server Seguro

```yaml
# api-server configuration (kubeadm)

apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
apiServer:
  extraArgs:
    # ✓ Autenticação obrigatória
    --authorization-mode=RBAC,Node
    --audit-log-path=/var/log/audit/audit.log
    --audit-log-maxage=30

    # ✓ TLS para API
    --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    --tls-private-key-file=/etc/kubernetes/pki/apiserver.key

    # ✓ Disable insecure APIs
    --service-account-lookup=true
    --service-account-issuer=https://kubernetes.default.svc.cluster.local

    # ✓ Strong encryption
    --encryption-provider-config=/etc/kubernetes/enc/encryption.yaml

    # ✓ RBAC enabled
    --enable-rbac=true

etcd:
  extraArgs:
    # ✓ Criptografar dados em repouso
    --cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

    # ✓ Cliente auth
    --client-auto-tls=false
    --cert-file=/etc/kubernetes/pki/etcd/server.crt
    --key-file=/etc/kubernetes/pki/etcd/server.key

kubeletConfiguration:
  # ✓ Disable anonymous requests
  anonymous:
    enabled: false

  # ✓ Enforce authorization
  authorization:
    mode: Webhook

  # ✓ ReadOnlyPort desabilitada
  readOnlyPort: 0
```

#### 🔐 RBAC - Controle de Acesso

Veja seção RBAC completa abaixo.

---

### LAYER 3: Pod Security

#### ❌ Pod Inseguro

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: unsafe-pod

spec:
  containers:
  - name: app
    image: ubuntu:latest  # ❌ Sem versão

    # ❌ Executa como root!
    # securityContext: omitido

    # ❌ Sem limites de CPU/memória
    # resources: omitido

    # ❌ Monta volume do host
    volumeMounts:
    - name: host-root
      mountPath: /host

    # ❌ Sem network policy
    # nenhuma restrição de rede

  # ❌ Monta volume do host (/dev)
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory

  hostNetwork: true  # ❌ Usa rede do host
  hostPID: true      # ❌ Acesso a PIDs do host
  hostIPC: true      # ❌ Acesso a IPC do host
```

#### ✓ Pod Seguro

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod

spec:
  # ✓ Namespace específico (não default)
  namespace: production

  # ✓ Service account específica
  serviceAccountName: app-sa
  automountServiceAccountToken: false  # Desabilitar se não necessário

  # ✓ Security context para pod
  securityContext:
    runAsNonRoot: true       # Não executa como root
    runAsUser: 1001          # UID específico
    runAsGroup: 3000         # GID específico
    fsGroup: 2000            # Volume GID
    seccompProfile:
      type: RuntimeDefault   # Seccomp profile

  containers:
  - name: app
    image: myapp:1.0  # ✓ Tag específica (não latest)

    # ✓ Security context para container
    securityContext:
      allowPrivilegeEscalation: false      # Não elevar privilégios
      readOnlyRootFilesystem: true          # Filesystem read-only
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]  # Remove todas capabilities
        add: ["NET_BIND_SERVICE"]  # Adiciona apenas necessário

    # ✓ Resource limits (previne DoS)
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "500m"

    # ✓ Liveness probe (reinicia se travado)
    livenessProbe:
      httpGet:
        path: /health
        port: 3000
      initialDelaySeconds: 30
      periodSeconds: 10

    # ✓ Readiness probe (remove do load balancer se não pronto)
    readinessProbe:
      httpGet:
        path: /ready
        port: 3000
      initialDelaySeconds: 5
      periodSeconds: 5

    # ✓ Volume mounts seguros (read-only)
    volumeMounts:
    - name: config
      mountPath: /etc/config
      readOnly: true
    - name: tmp
      mountPath: /tmp

  # ✓ Volumes seguros (não host path)
  volumes:
  - name: config
    configMap:
      name: app-config
      defaultMode: 0400  # Read-only

  - name: tmp
    emptyDir:
      medium: Memory  # Usar RAM (ephemeral)
```

---

## Passo a Passo: Cluster Seguro {#passo-a-passo}

### PASSO 1: Criar Cluster Seguro (20 minutos)

```bash
#!/bin/bash
# setup-secure-k8s.sh

# Opção 1: Usar managed K8s (recomendado)
# AWS EKS, Google GKE, Azure AKS

# Opção 2: Usar kubeadm para self-hosted

# Pré-requisitos
echo "[*] Instalando kubeadm, kubelet, kubectl"

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl
curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg

echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubeadm=1.28.0-00 kubelet=1.28.0-00 kubectl=1.28.0-00
sudo apt-mark hold kubeadm kubelet kubectl  # Evitar upgrade automático

# Inicializar cluster
sudo kubeadm init \
  --kubernetes-version=1.28.0 \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=0.0.0.0 \
  --upload-certs

# Setup kubeconfig
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Verificar
kubectl cluster-info
kubectl get nodes
```

### PASSO 2: Instalar Network Plugin Seguro (10 minutos)

```bash
#!/bin/bash

# CNI (Container Network Interface) plugin
# Opções: Calico, Cilium, Weave

# Instalar Calico (recomendado para segurança)
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml

# Verificar
kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kale o-system --timeout=300s

# Testar conectividade
kubectl run test --image=nginx
kubectl exec test -- curl https://kubernetes.default.svc.cluster.local
```

### PASSO 3: Configurar RBAC (30 minutos)

```bash
#!/bin/bash

# Exemplo: Developer tem acesso apenas a namespace "dev"

# 1. Criar namespace
kubectl create namespace dev
kubectl create namespace prod

# 2. Criar service account para developer
kubectl create serviceaccount dev-user -n dev

# 3. Criar role com permissões limitadas
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-role
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "pods/exec"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
EOF

# 4. Bind role ao service account
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-rolebinding
  namespace: dev
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dev-role
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
EOF

# 5. Gerar kubeconfig para dev-user
# (Veja seção RBAC para detalhes)
```

### PASSO 4: Network Policies (20 minutos)

```bash
#!/bin/bash

# Criar network policy
# Por padrão, K8s permite todo tráfego
# Network policies implementam firewall

cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
  namespace: prod

spec:
  # ✓ Aplica a pods com label "app: myapp"
  podSelector:
    matchLabels:
      app: myapp

  # ✓ Especifica tipos de políticas
  policyTypes:
  - Ingress    # Entrada
  - Egress     # Saída

  # ✓ Regras de entrada (Ingress)
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx  # Apenas do ingress-nginx
    - podSelector:
        matchLabels:
          app: frontend        # Apenas do pod frontend
    ports:
    - protocol: TCP
      port: 3000              # Apenas porta 3000

  # ✓ Regras de saída (Egress)
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53                # DNS
    - protocol: UDP
      port: 53

  - to:
    - podSelector:
        matchLabels:
          app: database       # Database
    ports:
    - protocol: TCP
      port: 5432             # PostgreSQL

  # ✓ Negar tudo mais
  - to:
    - podSelector: {}
EOF

# Verificar policies
kubectl get networkpolicies -n prod
kubectl describe networkpolicy app-network-policy -n prod
```

---

## RBAC - Controle de Acesso {#rbac}

### 📌 Conceito Simples

RBAC = Role-Based Access Control

```
Role → Define QUAIS ações
RoleBinding → Define QUEM pode fazer
ServiceAccount → Quem é "WHO" (usuário/app)

Exemplo:
┌─────────────────────────────┐
│ Role (Developer)             │
│ - can: get, list, create     │
│ - resources: pods            │
│ - namespace: dev             │
└─────────────────────────────┘
        ↓ RoleBinding
┌─────────────────────────────┐
│ ServiceAccount: dev-user     │
│ Namespace: dev              │
└─────────────────────────────┘

Resultado: dev-user pode fazer essas ações em pods no namespace dev
```

### 🔧 Tipos de Roles

```
1. Role (escopo namespace)
   - Permissões limitadas a namespace específico

2. ClusterRole (escopo cluster)
   - Permissões em todo o cluster

3. RoleBinding (bind Role a usuário/service account)
   - No mesmo namespace

4. ClusterRoleBinding (bind ClusterRole)
   - Em todo o cluster
```

### ✓ Exemplo: 3 Usuários com Permissões Diferentes

```bash
#!/bin/bash

# USER 1: Admin (acesso a tudo)
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin  # ✓ Built-in
subjects:
- kind: User
  name: alice@company.com
  apiGroup: rbac.authorization.k8s.io
EOF

# USER 2: Developer (acesso a dev namespace)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: dev
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-role
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: dev
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: developer-role
subjects:
- kind: User
  name: bob@company.com
  apiGroup: rbac.authorization.k8s.io
EOF

# USER 3: Reader (apenas read-only em prod)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader-role
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: reader-binding
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: reader-role
subjects:
- kind: User
  name: charlie@company.com
  apiGroup: rbac.authorization.k8s.io
EOF
```

---

## Network Policies {#network}

### 📌 Firewall em Kubernetes

Network Policies funcionam como firewall entre pods.

```
DEFAULT: Tráfego permitido entre TODOS os pods

Com Network Policy:
┌─────────┐    Bloqueado    ┌─────────┐
│ Pod A   │ ❌───────────▶ │ Pod C   │
└─────────┘                 └─────────┘
      │                            △
      │ Permitido (Ingress Rule)  │
      └─────────────────────┬────┘
                           │
                      ┌─────────┐
                      │ Pod B   │
                      └─────────┘
```

### ✓ Exemplo Completo: 3 Apps com Políticas

```yaml
# app-frontend (Port 80)
---
apiVersion: v1
kind: Pod
metadata:
  name: frontend
  namespace: prod
  labels:
    app: frontend
spec:
  containers:
  - name: frontend
    image: nginx:latest
    ports:
    - containerPort: 80

# app-backend (Port 3000)
---
apiVersion: v1
kind: Pod
metadata:
  name: backend
  namespace: prod
  labels:
    app: backend
spec:
  containers:
  - name: backend
    image: myapp:1.0
    ports:
    - containerPort: 3000

# database (Port 5432)
---
apiVersion: v1
kind: Pod
metadata:
  name: database
  namespace: prod
  labels:
    app: database
spec:
  containers:
  - name: postgres
    image: postgres:15
    ports:
    - containerPort: 5432

# NETWORK POLICIES

# 1. Frontend policy - permitir internet, bloquear tudo mais
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  - Egress

  ingress:
  - from:
    - namespaceSelector: {}  # Permitir de qualquer lugar
    ports:
    - protocol: TCP
      port: 80

  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend  # Saída apenas para backend
    ports:
    - protocol: TCP
      port: 3000

# 2. Backend policy - frontend → backend, backend → database
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  - Egress

  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend  # Entrada apenas de frontend
    ports:
    - protocol: TCP
      port: 3000

  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database  # Saída apenas para database
    ports:
    - protocol: TCP
      port: 5432

  - to:  # DNS necessário
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53

# 3. Database policy - apenas backend pode acessar
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-policy
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress

  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend  # Entrada apenas de backend
    ports:
    - protocol: TCP
      port: 5432
```

---

## Pod Security {#pod-security}

### 📋 Pod Security Standards

Kubernetes oferece 3 níveis de segurança:

```
UNRESTRICTED (padrão - inseguro)
├─ Permite containers privilegiados
├─ Permite volume do host
└─ Permite escalação de privilégio

RESTRICTED (recomendado)
├─ Bloqueia containers privilegiados
├─ Força non-root
├─ Read-only filesystem
└─ Sem capabilities

BASELINE (meio-termo)
├─ Bloqueia o pior
├─ Mas permite alguns riscos
└─ Apenas para compatibilidade
```

### ✓ Enforçar Pod Security Policy

```bash
#!/bin/bash

# Habilitar Pod Security Standards

# 1. No admission controller
kubectl apply -f - <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-key>
  - identity: {}
EOF

# 2. Pod Security Policy (deprecated, usar Pod Security Standards)
cat <<EOF | kubectl apply -f -
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted-psp

spec:
  privileged: false
  allowPrivilegeEscalation: false

  requiredDropCapabilities:
  - ALL

  volumes:
  - configMap
  - downwardAPI
  - emptyDir
  - persistentVolumeClaim
  - secret
  - projected

  hostNetwork: false
  hostIPC: false
  hostPID: false

  runAsUser:
    rule: MustRunAsNonRoot

  seLinux:
    rule: MustRunAs

  supplementalGroups:
    rule: RunAsAny

  fsGroup:
    rule: RunAsAny

  readOnlyRootFilesystem: false
EOF

# 3. Ativar PodSecurityPolicy admission controller
# (kubeadm init com --enable-admission-plugins=PodSecurityPolicy)
```

---

## Scanning e Monitoramento {#scanning}

### 🔍 Ferramentas de Segurança

```bash
#!/bin/bash

# 1. kube-bench (CIS Kubernetes Benchmark)
docker run --pid host aquasec/kube-bench:latest run --targets node

# 2. kube-hunter (Buscar fraquezas)
docker run -v /var/run/docker.sock:/var/run/docker.sock aquasec/kube-hunter

# 3. Falco (Runtime monitoring)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco

# 4. Trivy (Image scanning)
trivy image myapp:1.0

# 5. OPA/Gatekeeper (Policy enforcement)
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.10/deploy/gatekeeper.yaml

# 6. kubesec (Security risk analysis)
kubesec scan pod.yaml
```

### 📊 Exemplo: Rodar Kube-bench

```bash
#!/bin/bash

# Instalação
docker pull aquasec/kube-bench:latest

# Executar
docker run --pid host \
  -v /etc:/etc:ro \
  -v /lib:/lib:ro \
  -v /sys:/sys:ro \
  -v /var:/var:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/kube-bench:latest \
  run \
  --targets node,policies

# Output:
# [PASS] 4.1.1 Ensure that the kubeconfig file permissions are set to 600 or more restrictive
# [FAIL] 4.1.5 Ensure that the kubelet --read-only-port is set to 0
# [WARN] 4.2.6 Ensure that a latency threshold is set for kubelet requests

# Corrigir failures
# Edit /etc/kubernetes/kubelet.conf e remover readOnlyPort
```

---

## Casos de Ataque {#casos}

### Caso 1: Container Escape

```yaml
# ❌ Container comprometido conseguiu:
# 1. Executar como root
# 2. Montar volume do host
# 3. Acessar /etc/shadow
# 4. Crackear senhas
# 5. Escalar para host

# Container:
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod

spec:
  containers:
  - name: app
    image: ubuntu:latest

    # ❌ Executa como root
    # ❌ Sem security context

    # ❌ Monta /etc do host
    volumeMounts:
    - name: host-etc
      mountPath: /host/etc

  volumes:
  - name: host-etc
    hostPath:
      path: /etc
      type: Directory

# ✓ Proteção:
# 1. Executar como non-root
# 2. Read-only filesystem
# 3. Sem mount de host
# 4. Drop ALL capabilities
# 5. Network policy
```

### Caso 2: RBAC Misconfiguration

```bash
# ❌ O que aconteceu:
# 1. ServiceAccount foi criada com cluster-admin
# 2. Pod de attacker recebeu essa SA
# 3. Conseguiu criar novos pods/deletar tudo

# ✓ Proteção:
# 1. Least privilege: dar APENAS o mínimo
# 2. Use namespace isolation
# 3. Regular RBAC audits
# 4. ServiceAccount token mounting disable
```

---

## 📋 Checklist Final - Kubernetes Seguro

```
CLUSTER SETUP:
[ ] K8s versão atualizada (última stable)
[ ] Control plane isolado
[ ] ETCD criptografado
[ ] API server TLS habilitado
[ ] RBAC ativado
[ ] Audit logging habilitado
[ ] Secrets criptografados em repouso

NETWORKING:
[ ] Network policies implementadas
[ ] Ingress com TLS
[ ] Service mesh (Istio/Linkerd) opcional
[ ] Egress filtering
[ ] mTLS entre pods

WORKLOADS:
[ ] Imagens scaneadas (Trivy, Snyk)
[ ] Sem latest tags
[ ] Security context definido
[ ] Resources limits/requests
[ ] Health checks (liveness, readiness)
[ ] Read-only filesystem
[ ] Non-root user
[ ] Drop unnecessary capabilities

RBAC:
[ ] Roles específicas criadas
[ ] Service accounts não compartilhadas
[ ] ClusterAdmin apenas para admins
[ ] Audit de permissions
[ ] Regular access reviews

MONITORING:
[ ] Kube-bench passou
[ ] Kube-hunter executado
[ ] Falco monitorando
[ ] Alerts configurados
[ ] Logs centralizados

COMPLIANCE:
[ ] CIS Kubernetes Benchmark (80%+)
[ ] Pod security standards enforçadas
[ ] Secrets management (Sealed Secrets, etc)
[ ] Backup/restore funcionando
```

---

<div align="center">

**⭐ Kubernetes Security = Defesa em profundidade**

**Camadas: Host → Cluster → Container → App → Network**

**Menos privilégios = Mais segurança**

**Automatizar segurança = Scanning em CI/CD**

**Do iniciante ao expert: Praticar em minikube/kind primeiro**

</div>
