# Guia Prático de CSPM com Prowler

Este guia oferece um passo a passo detalhado para configurar e usar o Prowler, uma ferramenta de *Cloud Security Posture Management (CSPM)*, para auditar ambientes AWS, Google Cloud e Azure.

## 1. O que é o Prowler?

Prowler é uma ferramenta de segurança de linha de comando, open-source, que avalia, audita e fortalece a segurança de ambientes em nuvem. Ele executa centenas de verificações com base em benchmarks como CIS, GDPR, HIPAA, e as melhores práticas de segurança de cada provedor.

## 2. Instalação

O Prowler requer Python 3.9+ e o CLI do provedor de nuvem que você deseja auditar (AWS CLI, Azure CLI, gcloud CLI).

```bash
# Instalar via pip (recomendado)
pip install prowler

# Verificar a instalação
prowler -v
```

## 3. Configuração de Credenciais

O Prowler usa as credenciais configuradas no ambiente do seu terminal.

### AWS

Certifique-se de que suas credenciais da AWS estão configuradas. O Prowler usará a mesma autenticação que o AWS CLI.

```bash
aws configure
# AWS Access Key ID [****************...]: SEU_ACCESS_KEY
# AWS Secret Access Key [****************...]: SEU_SECRET_KEY
# Default region name [us-east-1]: SUA_REGIAO
# Default output format [json]: json

# Verifique sua identidade
aws sts get-caller-identity
```

### Google Cloud (GCP)

Autentique-se com a gcloud CLI.

```bash
gcloud auth login
gcloud auth application-default login

# Defina o projeto padrão
gcloud config set project SEU_PROJETO_ID
```

### Azure

Autentique-se com a Azure CLI.

```bash
az login

# Liste as assinaturas e defina a padrão
az account list
az account set --subscription "SUA_ASSINATURA_ID"
```

## 4. Executando Auditorias com Prowler

O Prowler gera relatórios em HTML, JSON e CSV, que são salvos no diretório `output/`.

### AWS

Execute uma auditoria completa na sua conta AWS.

```bash
prowler aws
```

**Exemplo de Comando Específico:**

Para verificar apenas os benchmarks CIS e gerar um relatório HTML:

```bash
prowler aws --compliance cis_1.5_aws
```

### Google Cloud (GCP)

Execute uma auditoria completa no seu projeto GCP.

```bash
prowler gcp
```

**Exemplo de Comando Específico:**

Para verificar um serviço específico, como o Cloud Storage:

```bash
prowler gcp --services storage
```

### Azure

Execute uma auditoria completa na sua assinatura do Azure.

```bash
prowler azure
```

**Exemplo de Comando Específico:**

Para verificar um grupo de conformidade específico, como o CIS:

```bash
prowler azure --compliance cis_1.5_azure
```

## 5. Analisando os Resultados

Após a execução, o Prowler gera um relatório detalhado. O formato HTML é o mais amigável para análise.

**Estrutura do Relatório:**

- **Dashboard:** Um resumo com a porcentagem de aprovação, total de verificações e descobertas críticas.
- **Findings:** Uma lista de todas as verificações, classificadas por status:
  - `PASS`: O recurso está em conformidade.
  - `FAIL`: O recurso não está em conformidade e requer atenção.
  - `MANUAL`: A verificação requer análise manual.
- **Detalhes do Finding:** Cada item com falha (`FAIL`) inclui:
  - **Severity:** A criticidade do achado (Critical, High, Medium, Low).
  - **Description:** O que foi verificado.
  - **Recommendation:** Como corrigir o problema.
  - **Resource ID:** O recurso exato que falhou na verificação.

**Exemplo de Análise:**

1. **Abra o relatório HTML:** `output/prowler-aws-123456789012-....html`
2. **Filtre por `FAIL`:** Concentre-se primeiro nas descobertas com falha.
3. **Priorize por Severidade:** Comece corrigindo os itens `Critical` e `High`. Por exemplo, um bucket S3 público (`s3_bucket_public_access`) é uma vulnerabilidade crítica.
4. **Siga as Recomendações:** O Prowler fornece um guia claro para a correção, muitas vezes com links para a documentação oficial.

## 6. Guia Prático com Scout Suite

Scout Suite é outra ferramenta poderosa que gera relatórios visuais e detalhados sobre a postura de segurança em múltiplos provedores de nuvem.

### Instalação do Scout Suite

```bash
pip install scoutsuite
```

### Executando o Scout Suite

**AWS**
```bash
scout aws
```

**Google Cloud (GCP)**
```bash
scout gcp --project-id SEU_PROJETO_ID
```

**Azure**
```bash
scout azure --subscription-id SUA_ASSINATURA_ID
```

### Análise do Relatório do Scout Suite

O Scout Suite gera um relatório HTML local, abrindo-o automaticamente no navegador. O relatório é interativo e apresenta:

- **Dashboard:** Uma visão geral com pontuações de risco por serviço.
- **Findings:** Descobertas detalhadas, categorizadas por serviço (ex: IAM, S3, EC2).
- **Attack Path Analysis:** Mostra como uma vulnerabilidade pode ser explorada em combinação com outras, ajudando a priorizar correções.
