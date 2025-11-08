# AppSec Checklist & Guide – Design & Conteúdo

Este documento consolida o design system, a estratégia de conteúdo técnico e o workflow de bug-hunting utilizados no AppSec Checklist & Guide. Ele serve como referência rápida para implementar novas interfaces, expandir checklists e manter consistência entre dashboard, modais e relatório PDF.

---

## 1. Princípios de Design

### 1.1 Identidade visual
- **Paleta primária:** `#0E1F2F` (fundo), `#00C6FF` (acento), `#3DDC97` (sucesso), `#F8F9FA` (texto claro) e `#D1D5DB` (texto de contraste).
- **Tipografia:** Família `Inter` com pesos 400–800. Utilize `1rem` como base e variações para títulos (`1.5rem`, `2rem`).
- **Espaçamento:** grade modular de 4px (tokens `--spacing-1` até `--spacing-10`).
- **Componentes reutilizáveis:** cards vitrificados, métricas em grade, radial progress, timeline do workflow, tabelas e modais.
- **Acessibilidade:** contraste mínimo 4.5:1, foco com `box-shadow`, navegação por teclado e impressão otimizada (media query `@media print`).

### 1.2 Tokens e SCSS
- O arquivo [`design/system/appsec-design-system.scss`](../design/system/appsec-design-system.scss) define cores, tipografia, espaçamento, mixins e componentes base (`.card`, `.metric-card`, `.btn-*`).
- Utilize o mixin `focus-ring` para inputs focados e `glass-panel` para painéis translúcidos.
- Tags de severidade (`.tag-critical`, `.tag-high`, etc.) padronizam cores para evitar inconsistências entre dashboard e relatório.

### 1.3 Layouts chave
- **Dashboard:** grade de duas colunas (sidebar fixa + conteúdo). Métricas, progresso radial e insights acima do checklist ativo.
- **Checklist item:** três colunas (status/atributos, notas, evidências). Cada item contém campos para status, gravidade, fase do workflow, responsável, prioridade e narrativa da evidência.
- **Modal de guia:** seções estruturadas (Resumo técnico, Impacto & riscos, Como identificar, Ferramentas/Comandos, Mitigações, Evidências, Referências) renderizadas dinamicamente.
- **Relatório PDF:** capa com metadados, resumo executivo, distribuição por severidade/workflow e tabelas com colunas `Item | Status | Concluído | Notas/Evidências/Prioridade`.

---

## 2. Workflow de Bug-Hunting Integrado

### 2.1 Etapas oficiais
1. **Recon & Asset Discovery:** descoberta via `crt.sh`, ASN, CSPM, varredura de portas, monitoramento de certificados.
2. **Testar & Fuzzing:** automatize SAST/DAST, fuzzing de parâmetros, testes de corrida, WAF evasion e exploração combinada.
3. **Verificar Controles:** análise de autenticação, autorização, rate-limit bypass, lógica de negócio, chain exploitation e integração com SIEM.
4. **Reportar & Evidenciar:** preencher narrativa, anexar PoC, logs, payload, impacto, requisitos regulatórios violados.
5. **Mitigar & Validar:** validar correções, retestar, atualizar playbooks e métricas de tempo médio para correção.

### 2.2 Mapeamento com o checklist
- Cada item possui campo “Fase” (`recon`, `testing`, `access`, `report`, `mitigate`). Use-o para alimentar métricas na timeline lateral.
- Filtros por fase e responsável ajudam a planejar rodadas de teste (ex.: recon → entrega para time API → reteste na sprint seguinte).
- Itens críticos de cadeia de exploração (combinar falhas) são destacados nos insights automáticos do dashboard.

### 2.3 Templates de evidência
- **Checklist interno:** screenshot/vídeo, logs, payload & resposta, impacto. Todos os campos marcam o mínimo necessário para triagem/c-level.
- **Narrativa:** descreva cenário, passos para reproduzir, impacto, recomendação. Campo disponível em cada item e exportado no PDF.
- **Anexos:** upload via `/api/upload`, listados automaticamente. Use nomes descritivos (`a01-idor-response.json`).

---

## 3. Conteúdo Técnico por Domínio

Cada item do checklist deve trazer os blocos a seguir (utilize o objeto `guide` em `data.mjs`):

| Bloco                | Descrição                                                                                      |
|----------------------|--------------------------------------------------------------------------------------------------|
| Resumo técnico       | Contextualiza o controle testado, ameaça mapeada e comportamento esperado.                      |
| Impacto & riscos     | Impacto para negócio/compliance, exploração provável, cadeias associadas.                       |
| Como identificar     | Passos práticos, fuzzing, observações de logs, correlação com telemetria.                        |
| Ferramentas/Comandos | Ferramentas recomendadas e comandos ready-to-run (curl, nmap, k6, nuclei, etc.).                |
| Mitigações           | Padrões de correção, hardening, automação de regression testing.                                |
| Evidências sugeridas | Provas aceitas pela triagem: captura, logs, payload, diff de código, métricas.                  |
| Referências          | OWASP, NIST, RFCs, blogposts confiáveis, runbooks internos.                                     |

### 3.1 Cobertura mínima
- **OWASP Web/API:** autenticação, sessão, controle de acesso, injeção, XSS, SSRF, rate-limit, mass assignment, lógica de negócio.
- **PTES:** reconhecimento, enumeração (DNS, ASN, certificados), weaponization, exploração, pós-exploração, relatório.
- **SAST/DAST:** pipeline CI/CD, gates de qualidade, análise incremental, supressão de falsos positivos.
- **Hardening/Infra:** baseline CIS, IAM, logging, segurança de containers, WAF/CDN, CSPM.
- **Cloud Native e Supply Chain:** SBOM, assinaturas, controle de dependências, rotações de segredos, segurança de build pipeline.
- **Mobile:** jailbreak/root detection, armazenamento seguro, transporte, automação (MobSF), mitigação anti-tamper.

### 3.2 Itens avançados sugeridos
- Descoberta de ativos via certificate transparency e ASN.
- Chain exploitation entre vulnerabilidades aparentemente baixas.
- Race conditions, bypass de rate-limit, colisão de UUID.
- Evasão de WAF, payloads polimórficos, automação anti-bot.
- Supply-chain: validação de assinaturas, monitoramento de dependências, segurança de pipelines GitOps.

---

## 4. Métricas & Exportação

- **Dashboard:** métricas totais (itens, concluídos, falhas, evidências), percentuais no radial chart, progresso por categoria e insights (top riscos, gaps, chains).
- **Workflow counts:** número de itens por fase alimenta a timeline lateral e o relatório PDF.
- **Filtros:** status, responsável e fase. O botão “Exportar Seleção” usa filtros atuais e a seção ativa para gerar relatório parcial.
- **Relatório PDF:** capa + resumo executivo + tabelas. Função `generateFullReport` (`reportTemplate.mjs`) constrói documento com CSS pronto para impressão.
- **Template estático:** [`templates/appsec-report-template.html`](../templates/appsec-report-template.html) serve para customização ou integração com serviços de PDF server-side.

---

## 5. Expandindo o Guia

### 5.1 Adicionar novo domínio
1. Atualize `data.mjs` (ou checklist específico) adicionando nova categoria com `id`, `name`, `description` e `sections`.
2. Preencha cada item com `guide` completo (ver seção 3) e IDs exclusivos.
3. Caso seja um novo módulo (ex.: Mobile), avalie criar arquivo dedicado e importar em `app.mjs` (similar a `cloudSecurity.mjs`).

### 5.2 Customização por plataforma
- **Mobile:** adicione tags `stage` específicas (ex.: `testing`/`access`) e campos extras no `guide` (proteção contra reverse engineering).
- **Cloud Native:** reforce controles de IAM, segredos, supply-chain e logging (ex.: `kubectl auth can-i`, `kube-hunter`).
- **CI/CD:** inclua itens para verificação de pipelines (assinatura de artefatos, scanning em cada estágio, política de branch).

### 5.3 Boas práticas de manutenção
- IDs no formato `categoria::secao::item` para persistência de estado.
- Atualize `INTERNAL_DOCS` em `app.mjs` ao adicionar novos fluxos de onboarding.
- Sempre gere o bundle com `npm run build` após alterar dados/JS.
- Execute testes (`npm test`) quando scripts forem atualizados (assegura lógica de métricas).

---

## 6. Referências rápidas
- OWASP Top 10 (2021 & 2023 API), OWASP ASVS, OWASP SAMM.
- PTES Technical Guidelines.
- NIST 800-53 / 800-218 (SSDF) para supply-chain.
- Guia Mozilla SSL, CIS Benchmarks, CNCF Security TAG.
- Ferramentas: Burp Suite, OWASP ZAP, Nuclei, Kiterunner, Trivy, Gitleaks, Snyk, Checkov, Cloudsploit, MobSF.

Mantenha este documento atualizado a cada incremento significativo do produto (novos domínios, métricas ou fluxos) para assegurar consistência entre equipes de AppSec, bug bounty e consultorias.
