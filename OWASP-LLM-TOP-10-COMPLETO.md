# 🤖 OWASP LLM Top 10 – Guia Completo

Checklist detalhado para aplicações que utilizam modelos de linguagem (LLMs), chatbots e agentes autônomos.

## LLM01 – Prompt Injection

- Fortaleça prompts de sistema com regras explícitas e validação pós-resposta.
- Utilize filtros heurísticos/ML para bloquear instruções maliciosas.
- Monitore conversas para detectar desvio de comportamento.

## LLM02 – Exfiltração de Dados Sensíveis

- Limite dados sensíveis no contexto enviado ao modelo.
- Mascarar PII antes do processamento e aplicar controles de acesso granulares.
- Registre eventos e revise logs com alertas automatizados.

## LLM03 – Output Injection

- Sanitize respostas antes de encaminhar para clientes ou outros sistemas.
- Utilize whitelists/blacklists para remover JavaScript ou comandos shell inesperados.
- Para integrações com navegadores, aplique Content Security Policy restritiva.

## LLM04 – Prompt Leakage

- Evite expor prompts de sistema ao usuário final.
- Rotacione chaves, tokens e segredos inseridos nos prompts.
- Empregue *canary tokens* para identificar vazamentos.

## LLM05 – Supply Chain / Dependências

- Verifique integridade de modelos, datasets e plugins via assinaturas digitais.
- Utilize repositórios confiáveis e mantenha SBOM de modelos e dependências.
- Revise licenças e atualizações periódicas.

## LLM06 – Model Theft

- Restrinja downloads do modelo com autenticação forte.
- Monitore padrões de acesso (taxa, volume, localidade).
- Implemente watermarking e técnicas de *fingerprinting*.

## LLM07 – Insegurança em Plugins

- Revise código de plugins/conectores antes de habilitar.
- Limite permissões e escopo das integrações (principle of least privilege).
- Aplique sandboxing e isolamento de execução.

## LLM08 – Insecure Output Handling

- Valide e codifique respostas antes de armazenar ou exibir.
- Evite executar comandos ou códigos diretamente a partir das respostas.
- Utilize formatos estruturados (JSON Schema) e validação estrita.

## LLM09 – Deepfake / Impersonation

- Empregue checagem de autenticidade (assinaturas, MFA) para respostas críticas.
- Detecte vozes, imagens e textos gerados com heurísticas ou serviços anti deepfake.
- Comunique riscos aos usuários finais.

## LLM10 – Resiliência e Disponibilidade

- Configure limites de requisições, quotas e fallback entre modelos.
- Monitore uso de GPU/CPU e escalone horizontalmente.
- Mantenha plano de contingência para indisponibilidade de provedores externos.

### Controles complementares

- **Threat Modeling:** execute sessões periódicas envolvendo time de IA e segurança.
- **Red Teaming:** simule ataques de prompt e cadeia de suprimentos.
- **Observabilidade:** logging estruturado, métricas de latência e taxa de erro.
- **Políticas:** defina políticas de uso aceitável e treinamentos para usuários internos.

> Utilize este guia como base para construir controles específicos no `data.js` e incorporar novos cenários ao dashboard.
