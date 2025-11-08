# 🧠 OWASP AppSec Checklist Dashboard

Painel interativo completo para conduzir avaliações de segurança com base em **OWASP Top 10**, **OWASP API Security**, **PTES**, **SAST**, **DAST** e hardening de servidores. O projeto foi desenhado para ser **100% offline** e funcionar como base de conhecimento consolidada em segurança de aplicações.

## 🚀 Recursos principais

- ✅ Interface moderna em tema dark com navegação por abas
- ✅ Checklists completos com progresso, status (Passou/Falhou/N/A) e campo para notas/evidências
- ✅ Guias técnicos detalhados: impacto, detecção, ferramentas, comandos reais, passo a passo, mitigações, evidências
- ✅ Cobertura integral dos Top 10 OWASP Web 2021 e OWASP API Security 2023
- ✅ Seção dedicada a hardening de servidores (IIS, Apache, Nginx, Windows, Linux)
- ✅ **NOVO:** Guias de validação de dados em todas as linguagens web mais usadas (JavaScript/TypeScript, Python, PHP, Java, C#/.NET)
- ✅ **NOVO:** Guia completo de SAST - Static Application Security Testing com ferramentas e integração CI/CD
- ✅ **NOVO:** Testes de segurança automatizados para validação de dados
- ✅ Exportação rápida para PDF (utilize a função do navegador após abrir o relatório)
- ✅ Salvamento automático no servidor para não perder o progresso

## 📦 Estrutura dos arquivos

### Aplicação
| Arquivo | Descrição |
| --- | --- |
| `index.html` | Layout principal e containers da aplicação. |
| `styles.css` | Tema dark responsivo e estilos dos componentes. |
| `data.mjs` | Base de dados das checklists OWASP, PTES, SAST e DAST. |
| `securityTools.mjs` | Lista curada de ferramentas úteis e contexto rápido. |
| `serverConfig.mjs` | Itens de hardening para servidores e sistemas operacionais. |
| `app.mjs` | Lógica da interface, persistência e integração com servidor. |
| `server.mjs` | Servidor Node.js para gerenciar dados e progresso. |

### Documentação de Segurança
| Arquivo | Descrição |
| --- | --- |
| `CHECKLIST-COMPLETO.md` | Referência completa de checklists de segurança. |
| `DATA-VALIDATION-JAVASCRIPT.md` | 🆕 Guia completo de validação de dados em JavaScript/TypeScript com padrões SAST |
| `DATA-VALIDATION-PYTHON.md` | 🆕 Guia completo de validação de dados em Python com Pydantic e Bandit |
| `DATA-VALIDATION-PHP.md` | 🆕 Guia completo de validação de dados em PHP com filter_var e Symfony Validator |
| `DATA-VALIDATION-JAVA.md` | 🆕 Guia completo de validação de dados em Java com Jakarta Validation e SpotBugs |
| `DATA-VALIDATION-DOTNET.md` | 🆕 Guia completo de validação de dados em C#/.NET com Data Annotations e FluentValidation |
| `SAST-TOOLS-GUIDE.md` | 🆕 Guia completo de SAST com ferramentas, integração CI/CD e checklist |
| `API-SECURITY-GUIDE.md` | Proteção de APIs REST e GraphQL com contexto real. |
| `OWASP-LLM-TOP-10-COMPLETO.md` | Guia especializado para proteção de LLMs e chatbots. |
| `CSPM-PRACTICAL-GUIDE.md` | Gerenciamento de postura de segurança em nuvem. |
| `DEVSECOPS-AUTOMATION-GUIDE.md` | Automação de segurança em pipelines DevOps. |
| `DAST-PRACTICAL-GUIDE.md` | Testes dinâmicos de segurança com ferramentas práticas. |
| `NOTAS-TECNICAS.md` | Observações sobre arquitetura, dados locais e privacidade. |
| `TEST_GUIDE.md` | Tutorial prático para executar a aplicação e conduzir testes. |
| `SAMPLE-SECURITY-REPORT.md` | Exemplo de relatório de segurança formatado. |

### Testes
| Arquivo | Descrição |
| --- | --- |
| `src/logic.test.js` | Testes unitários de lógica de progresso e renderização. |
| `src/security-validation.test.js` | 🆕 Testes de segurança para validação de entrada e XSS prevention |

## 🛠️ Como usar

1. **Instale as dependências:**
   ```bash
   npm install
   ```
2. **Inicie o servidor de desenvolvimento:**
   ```bash
   npm start
   ```
3. **Acesse a aplicação:**
   Abra [http://localhost:3000](http://localhost:3000) no seu navegador.

4. Informe o nome do projeto e do tester na parte superior.
5. Navegue pelas abas (OWASP Web, OWASP API, PTES, SAST, DAST, Server Config).
6. Para cada item:
   - Marque a checkbox quando concluir o teste.
   - Escolha o status (Passou, Falhou, N/A).
   - Registre notas e evidências coletadas (logs, prints, comandos executados).
   - Clique em **📘 Guia real** para abrir instruções aprofundadas com impacto, técnicas de detecção, mitigações e checklist de evidências.
7. Clique em **📄 Exportar PDF** para gerar o relatório consolidado (use “Imprimir em PDF”).
8. Utilize **🧹 Resetar Dados** para limpar o estado local e iniciar um novo ciclo.

## 📥 Exportação do relatório

- O botão **📄 Exportar PDF** abre uma nova aba com relatório formatado.
- Utilize o atalho do navegador (`Ctrl + P` / `Cmd + P`) e escolha “Salvar como PDF”.
- O relatório contém: projeto, tester, data/hora, status por item e notas registradas.

## 🎯 Guias de Validação de Dados

Este projeto agora inclui **5 guias abrangentes sobre validação de dados** em linguagens web mais usadas:

### 📚 Guias por Linguagem

1. **JavaScript/TypeScript** (`DATA-VALIDATION-JAVASCRIPT.md`)
   - Validação com Zod, Joi, Yup
   - Escape de HTML com DOMPurify
   - Preparação de queries SQL
   - Testes com Jest/Vitest

2. **Python** (`DATA-VALIDATION-PYTHON.md`)
   - Validação com Pydantic, Marshmallow
   - HTML escape com markupsafe
   - Detecção de SSRF e injection
   - Testes com Bandit e pytest

3. **PHP** (`DATA-VALIDATION-PHP.md`)
   - Validação com filter_var, Symfony Validator
   - HTML Purifier para sanitização
   - PDO para prepared statements
   - Testes com PHPUnit

4. **Java** (`DATA-VALIDATION-JAVA.md`)
   - Jakarta Bean Validation
   - OWASP ESAPI para escaping
   - Apache Commons Validator
   - Testes com JUnit 5

5. **C#/.NET** (`DATA-VALIDATION-DOTNET.md`)
   - Data Annotations, FluentValidation
   - Entity Framework para queries
   - WebUtility para HTML encode
   - Testes com xUnit

### 📊 Pontos de Validação Críticos Cobertos

Cada guia detalha:
- ✅ Email validation (RFC 5322 compliant)
- ✅ URL validation com whitelist e SSRF prevention
- ✅ Número/montante com precisão decimal
- ✅ String validation contra XSS
- ✅ Enum validation para valores permitidos
- ✅ File upload validation (MIME, magic bytes, path traversal)
- ✅ JWT/Token validation e expiração
- ✅ SQL injection prevention
- ✅ HTML escaping por contexto
- ✅ Testes de segurança automatizados

## 🔍 Guia SAST - Static Application Security Testing

Consulte `SAST-TOOLS-GUIDE.md` para:

- **Ferramentas por linguagem:** Semgrep, Bandit, PHPStan, SpotBugs, SonarQube
- **Integração CI/CD:** GitHub Actions, GitLab CI, Jenkins
- **Análise de resultados:** Severidade, falsos positivos, priorização
- **Checklist de implementação:** Setup, remediation, governança
- **Exemplo prático:** Projeto Node.js + Python com SAST

## 🔎 Fluxo recomendado de validação

1. **Planeje** o escopo utilizando a aba PTES e confira se obrigações legais estão cobertas.
2. **Execute** os testes por categoria (OWASP, API, SAST, DAST, Hardening) consultando os guias para compreender impacto, técnicas de detecção e comandos.
3. **Colete evidências** descritas nos guias (logs, capturas, relatórios de ferramentas) e anexe o resumo no campo de notas.
4. **Classifique o status** de cada item com base no resultado observado (Passou/Falhou/N/A) e marque a checkbox quando finalizar.
5. **Revise mitigações sugeridas** e inclua recomendações específicas do ambiente analisado.
6. **Gere o relatório PDF** para anexar à documentação do projeto ou sistema de acompanhamento de vulnerabilidades.

### Validação de Código

- Utilize **SAST tools** automaticamente em CI/CD
- Execute **testes de segurança** antes de merge: `npm test`
- Revise **falsos positivos** e documente exceções
- Mantenha **histórico de vulnerabilidades** por commit

## 🔒 Privacidade e funcionamento

- O projeto agora utiliza um servidor Node.js para fornecer os dados e salvar o progresso.
- O estado (checkboxes, status, notas, nome do projeto/tester) é salvo no servidor.
- Para limpar dados basta usar o botão de reset.

## ✅ Testes de Segurança

Execute os testes de validação de dados automaticamente:

```bash
# Rodar todos os testes
npm test

# Executar apenas testes de segurança
npm test security-validation

# Modo watch (para desenvolvimento)
npm test -- --watch
```

**Cobertura de testes:**
- Email validation (entrada/saída válida e inválida)
- XSS prevention (múltiplos payloads)
- SQL injection prevention
- SSRF prevention
- Enum/valor permitido
- HTML escaping
- Testes de segurança integrados

---

## 🛠️ Ferramentas Recomendadas

### SAST Tools (por linguagem)
| Linguagem | Ferramenta | Comando |
|-----------|-----------|---------|
| JavaScript | Semgrep | `semgrep --config=p/owasp-top-ten` |
| Python | Bandit | `bandit -r src/` |
| PHP | PHPStan | `./vendor/bin/phpstan analyse src/` |
| Java | SpotBugs | `mvn spotbugs:check` |
| C#/.NET | Roslyn | `dotnet build` |

### Integração CI/CD
- GitHub Actions: Semgrep, Bandit, SonarCloud
- GitLab CI: GitLab SAST
- Jenkins: Pipeline com ferramentas customizadas

Veja `SAST-TOOLS-GUIDE.md` para setup completo.

---

## 📖 Documentação Completa

### Guias de Segurança por Tópico

**Data Validation (5 linguagens):**
- 🟦 JavaScript/TypeScript: `DATA-VALIDATION-JAVASCRIPT.md`
- 🐍 Python: `DATA-VALIDATION-PYTHON.md`
- 🐘 PHP: `DATA-VALIDATION-PHP.md`
- ☕ Java: `DATA-VALIDATION-JAVA.md`
- 🟦 C#/.NET: `DATA-VALIDATION-DOTNET.md`

**SAST & DevSecOps:**
- 🔍 SAST Tools Guide: `SAST-TOOLS-GUIDE.md`
- 🔐 API Security: `API-SECURITY-GUIDE.md`
- 🤖 DAST Practical: `DAST-PRACTICAL-GUIDE.md`
- ⚙️ DevSecOps: `DEVSECOPS-AUTOMATION-GUIDE.md`
- ☁️ Cloud Security: `CSPM-PRACTICAL-GUIDE.md`

**Especializado:**
- 🧠 LLM Security: `OWASP-LLM-TOP-10-COMPLETO.md`
- 📋 Completo: `CHECKLIST-COMPLETO.md`

---

## 🤝 Contribuições

- Adicione novos itens de checklist em `data.mjs` (para OWASP, PTES, SAST, DAST) ou em `serverConfig.mjs` (hardening)
- Mantenha a estrutura de dados consistente para que o modal de guias funcione corretamente
- Adicione testes em `src/security-validation.test.js` para cobrir novos validadores
- Ajustes visuais podem ser aplicados em `styles.css`
- Atualize README ao adicionar novos guias ou funcionalidades

---

## 📚 Referências externas

- [OWASP Top 10 Web (2021)](https://owasp.org/Top10/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Mobile Application Security](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Semgrep Rules](https://semgrep.dev/explore)
- [NIST 800-53 - Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

> Este painel busca centralizar **conhecimento consolidado** em um único lugar para agilizar avaliações AppSec, validação de dados, pentests ofensivos e implementação de SAST em pipelines CI/CD.
>
> **Último Update:** Novembro 2024 - Adicionados guias de validação em 5 linguagens + SAST tools + testes automatizados
