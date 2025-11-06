export const cloudSecurityChecklist = {
  id: "cloud-security",
  name: "Cloud Security",
  description: "Checklist de segurança para provedores de nuvem (AWS, Azure, GCP), incluindo verificação de chaves vazadas.",
  sections: [
    {
      id: "aws",
      title: "AWS Security",
      summary: "Práticas recomendadas para proteger ambientes na Amazon Web Services.",
      items: [
        {
          id: "aws-iam",
          title: "IAM com Menor Privilégio",
          description: "Garanta que usuários e roles tenham apenas as permissões estritamente necessárias.",
          guide: {
            overview: "Revise políticas do IAM para evitar permissões excessivas (*:*), aplique MFA e rotação de chaves.",
            impact: "Contas comprometidas com privilégios excessivos podem levar ao comprometimento total do ambiente.",
            detection: ["Use o AWS IAM Access Analyzer para identificar recursos compartilhados externamente.", "Verifique o último uso de credenciais e desative chaves não utilizadas."],
            tools: ["AWS CLI", "Prowler", "ScoutSuite"],
            commands: [
              "aws iam list-policies --scope Local | jq '.Policies[] | select(.AttachmentCount > 0)'",
              "aws iam get-account-password-policy",
              "prowler aws -c iam_user_hardware_mfa_enabled"
            ],
            mitigation: ["Implemente roles temporárias com STS.", "Use Service Control Policies (SCPs) em AWS Organizations.", "Automatize a desativação de chaves de acesso antigas."],
            evidence: ["Relatório do IAM Access Analyzer.", "Política de senhas configurada.", "Configuração de MFA para usuários root e privilegiados."],
            references: ["AWS Security Best Practices", "CIS AWS Foundations Benchmark"]
          }
        },
        {
          id: "aws-s3",
          title: "Segurança de Buckets S3",
          description: "Verifique se buckets S3 não estão públicos e se a criptografia está ativada.",
          guide: {
            overview: "Ative o Block Public Access, criptografia em trânsito (TLS) e em repouso (SSE-S3/KMS).",
            impact: "Buckets S3 públicos podem expor dados sensíveis, resultando em vazamentos massivos.",
            detection: ["Use o AWS S3 Storage Lens para visibilidade.", "Verifique as políticas de bucket e ACLs."],
            tools: ["AWS CLI", "S3 Inspector"],
            commands: [
              "aws s3api get-public-access-block --bucket <bucket-name>",
              "aws s3api get-bucket-encryption --bucket <bucket-name>"
            ],
            mitigation: ["Ative o Block Public Access em nível de conta.", "Use políticas de bucket para restringir o acesso por IP ou VPC.", "Habilite o versionamento para recuperação de dados."],
            evidence: ["Configuração do Block Public Access ativa.", "Política de criptografia padrão habilitada.", "Políticas de bucket restritivas."],
            references: ["AWS S3 Security Best Practices"]
          }
        },
        {
          id: "aws-leaked-keys",
          title: "Verificação de Chaves Vazadas",
          description: "Monitore e responda a possíveis vazamentos de chaves de acesso da AWS.",
          guide: {
            overview: "Utilize ferramentas de varredura em repositórios de código e implemente monitoramento contínuo.",
            impact: "Chaves vazadas podem ser usadas por invasores para acessar e controlar recursos na sua conta AWS.",
            detection: ["Monitore o AWS Trusted Advisor e o Health Dashboard para alertas da AWS.", "Use ferramentas como Git-secrets ou TruffleHog em pipelines de CI/CD."],
            tools: ["TruffleHog", "Git-secrets", "AWS CLI"],
            commands: [
              "trufflehog filesystem /path/to/repo --since-commit HEAD~10",
              "aws iam list-access-keys --user-name <user>"
            ],
            mitigation: ["Rotacione imediatamente qualquer chave suspeita.", "Use roles do IAM em vez de chaves de acesso sempre que possível, especialmente em instâncias EC2.", "Eduque as equipes sobre o risco de comitar segredos."],
            evidence: ["Relatório de varredura de segredos sem findings.", "Procedimento de resposta a incidentes para chaves vazadas.", "Log de rotação de chaves."],
            references: ["Responding to compromised AWS credentials"]
          }
        }
      ]
    },
    {
      id: "azure",
      title: "Azure Security",
      summary: "Práticas recomendadas para proteger ambientes no Microsoft Azure.",
      items: [
        {
          id: "azure-ad",
          title: "Azure AD e RBAC",
          description: "Aplique o princípio do menor privilégio usando o Role-Based Access Control (RBAC) do Azure.",
          guide: {
            overview: "Atribua roles específicas em escopos definidos (assinatura, grupo de recursos) e evite a role de Owner.",
            impact: "Controles de acesso fracos podem permitir que usuários não autorizados acessem ou modifiquem recursos críticos.",
            detection: ["Use o Azure AD Access Reviews para auditar permissões.", "Monitore as atribuições de roles privilegiadas."],
            tools: ["Azure CLI", "Azure Portal"],
            commands: [
              "az role assignment list --all --include-classic-administrators",
              "az ad user list --query '[].{userPrincipalName:userPrincipalName, assignedRoles:assignedAppRoles[].displayName}'"
            ],
            mitigation: ["Use o Privileged Identity Management (PIM) para acesso just-in-time.", "Ative o MFA para todos os usuários, especialmente administradores.", "Crie roles customizadas quando necessário."],
            evidence: ["Relatório de Access Reviews.", "Configuração do PIM para roles críticas.", "Política de Acesso Condicional exigindo MFA."],
            references: ["Azure security best practices and patterns"]
          }
        },
        {
          id: "azure-network",
          title: "Segurança de Rede",
          description: "Configure Network Security Groups (NSGs) e firewalls para controlar o tráfego.",
          guide: {
            overview: "Restrinja o tráfego de entrada e saída para o mínimo necessário. Use o Azure Firewall para proteção centralizada.",
            impact: "Redes mal configuradas podem expor máquinas virtuais e serviços a ataques da internet.",
            detection: ["Use o Azure Security Center para visualizar a topologia de rede.", "Audite as regras de NSG para portas abertas (ex: RDP, SSH)."],
            tools: ["Azure CLI", "Azure Monitor"],
            commands: [
              "az network nsg rule list --resource-group <rg> --nsg-name <nsg-name>",
              "az network watcher show-topology --resource-group <rg>"
            ],
            mitigation: ["Use uma política de 'deny by default'.", "Implemente o Azure Private Link para acessar serviços PaaS de forma privada.", "Utilize o Azure DDoS Protection."],
            evidence: ["Regras de NSG restritivas.", "Diagrama de rede mostrando segmentação.", "Configuração do Azure Firewall."],
            references: ["Azure network security best practices"]
          }
        },
        {
          id: "azure-leaked-keys",
          title: "Verificação de Chaves Vazadas",
          description: "Monitore e responda a possíveis vazamentos de credenciais do Azure.",
          guide: {
            overview: "Integre a varredura de segredos em seu ciclo de desenvolvimento e monitore os logs de auditoria do Azure AD.",
            impact: "Credenciais vazadas (chaves de automação, senhas) permitem acesso não autorizado e movimentação lateral.",
            detection: ["Ative o Microsoft Defender for Cloud para detecção de ameaças.", "Use ferramentas de varredura de código em busca de segredos."],
            tools: ["TruffleHog", "Azure CLI"],
            commands: [
              "trufflehog git https://github.com/your-org/your-repo.git",
              "az ad signed-in-user show"
            ],
            mitigation: ["Rotacione imediatamente quaisquer credenciais comprometidas.", "Use Managed Identities para serviços do Azure em vez de armazenar segredos no código.", "Implemente políticas de Acesso Condicional para bloquear logins de locais suspeitos."],
            evidence: ["Pipeline de CI/CD com etapa de varredura de segredos.", "Uso de Managed Identities em vez de connection strings.", "Alertas de segurança configurados no Defender for Cloud."],
            references: ["Handle a potential security incident in Azure"]
          }
        }
      ]
    },
    {
      id: "gcp",
      title: "GCP Security",
      summary: "Práticas recomendadas para proteger ambientes no Google Cloud Platform.",
      items: [
        {
          id: "gcp-iam",
          title: "Cloud IAM e Hierarquia de Recursos",
          description: "Estruture os recursos em pastas e projetos e aplique políticas de IAM com menor privilégio.",
          guide: {
            overview: "Use grupos para gerenciar permissões, evite roles primitivas (owner, editor) e prefira roles predefinidas ou customizadas.",
            impact: "A má gestão do IAM pode levar à escalada de privilégios e ao acesso indevido a dados.",
            detection: ["Use o IAM Recommender para identificar permissões excessivas.", "Audite as políticas de IAM em cada nível da hierarquia."],
            tools: ["gcloud CLI", "Security Command Center"],
            commands: [
              "gcloud projects get-iam-policy <project-id>",
              "gcloud asset search-all-iam-policies --scope=organizations/<org-id> --query='policy:roles/owner'"
            ],
            mitigation: ["Use a role de 'Project Creator' para controlar a criação de projetos.", "Implemente o VPC Service Controls para criar perímetros de segurança de dados.", "Siga o guia de práticas recomendadas de IAM do Google."],
            evidence: ["Hierarquia de recursos bem definida.", "Relatório do IAM Recommender com ações tomadas.", "Políticas de IAM que usam roles específicas."],
            references: ["Google Cloud security best practices checklist"]
          }
        },
        {
          id: "gcp-network",
          title: "Segurança de Rede VPC",
          description: "Configure regras de firewall da VPC e segmente suas redes.",
          guide: {
            overview: "Use o princípio do menor privilégio para regras de firewall, negando todo o tráfego por padrão. Use tags para aplicar regras a grupos de instâncias.",
            impact: "Redes abertas podem expor instâncias e serviços a ataques externos e internos.",
            detection: ["Revise as regras de firewall para portas abertas para o mundo (0.0.0.0/0).", "Use o Network Intelligence Center para visualizar a topologia."],
            tools: ["gcloud CLI", "Cloud Armor"],
            commands: [
              "gcloud compute firewall-rules list",
              "gcloud compute instances describe <instance-name> --zone=<zone> | grep networkIP"
            ],
            mitigation: ["Crie sub-redes para isolar diferentes ambientes (produção, desenvolvimento).", "Use o Cloud Armor para proteção contra DDoS e ataques a aplicações web.", "Configure o Private Google Access para permitir que instâncias sem IP externo acessem as APIs do Google."],
            evidence: ["Regras de firewall restritivas.", "Topologia de rede mostrando segmentação.", "Políticas do Cloud Armor configuradas."],
            references: ["VPC network security best practices"]
          }
        },
        {
          id: "gcp-leaked-keys",
          title: "Verificação de Chaves Vazadas",
          description: "Monitore e responda a vazamentos de chaves de contas de serviço e outras credenciais do GCP.",
          guide: {
            overview: "Realize varreduras contínuas em repositórios de código e use o Security Command Center para detectar anomalias.",
            impact: "Chaves de contas de serviço vazadas podem conceder a um invasor acesso significativo aos seus recursos do GCP.",
            detection: ["Ative o Event Threat Detection no Security Command Center.", "Integre ferramentas de varredura de segredos em seu workflow de desenvolvimento."],
            tools: ["TruffleHog", "gcloud CLI"],
            commands: [
              "trufflehog git file:///path/to/your/local/repo",
              "gcloud iam service-accounts keys list --iam-account=<sa-email>"
            ],
            mitigation: ["Rotacione imediatamente qualquer chave comprometida.", "Prefira anexar contas de serviço a recursos (ex: instâncias de VM) em vez de baixar chaves JSON.", "Use o Secret Manager para armazenar e gerenciar segredos."],
            evidence: ["Resultados de varreduras de segredos sem achados críticos.", "Uso de contas de serviço vinculadas a recursos.", "Logs de auditoria mostrando a rotação de chaves."],
            references: ["Managing service account keys"]
          }
        }
      ]
    }
  ]
};
