# 🧠 OWASP AppSec Checklist Dashboard

Painel interativo para conduzir avaliações de segurança com base em OWASP Top 10, OWASP API Security, PTES, SAST, DAST e hardening de servidores. O projeto foi desenhado para funcionar **100% offline**: basta abrir `index.html` no navegador e começar a checklist.

## 🚀 Recursos principais

- Interface moderna em tema dark com navegação por abas.
- Checklists completos com boxes de progresso, status (Passou/Falhou/N/A) e campo para notas e evidências.
- Guias técnicos detalhados por item: impacto, como identificar, ferramentas, comandos reais, passo a passo, mitigações e evidências sugeridas.
- Cobertura integral dos Top 10 OWASP Web 2021 e OWASP API Security 2023 com múltiplos testes acionáveis por categoria.
- Seção dedicada a hardening de servidores (IIS, Apache, Nginx, Windows, Linux).
- Exportação rápida para PDF (utilize a função do navegador após abrir o relatório).
- Salvamento automático no `localStorage` para não perder o progresso.

## 📦 Estrutura dos arquivos

| Arquivo | Descrição |
| --- | --- |
| `index.html` | Layout principal e containers da aplicação. |
| `styles.css` | Tema dark responsivo e estilos dos componentes. |
| `data.js` | Base de dados das checklists OWASP, PTES, SAST e DAST. |
| `securityTools.js` | Lista curada de ferramentas úteis e contexto rápido. |
| `serverConfig.js` | Itens de hardening para servidores e sistemas operacionais. |
| `app.js` | Lógica da interface, persistência local, modal de guias e exportação. |
| `CHECKLIST-COMPLETO.md` | Referência completa de checklists de segurança. |
| `NOTAS-TECNICAS.md` | Observações sobre arquitetura, dados locais e privacidade. |
| `VERSAO-ULTRA-DETALHADA.txt` | Comandos práticos, payloads e scripts auxiliares. |
| `OWASP-LLM-TOP-10-COMPLETO.md` | Guia especializado para proteção de LLMs e chatbots. |
| `TEST_GUIDE.md` | Tutorial prático para executar a aplicação e conduzir testes. |

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

## 🔎 Fluxo recomendado de validação

1. **Planeje** o escopo utilizando a aba PTES e confira se obrigações legais estão cobertas.
2. **Execute** os testes por categoria (OWASP, API, SAST, DAST, Hardening) consultando os guias para compreender impacto, técnicas de detecção e comandos.
3. **Colete evidências** descritas nos guias (logs, capturas, relatórios de ferramentas) e anexe o resumo no campo de notas.
4. **Classifique o status** de cada item com base no resultado observado (Passou/Falhou/N/A) e marque a checkbox quando finalizar.
5. **Revise mitigações sugeridas** e inclua recomendações específicas do ambiente analisado.
6. **Gere o relatório PDF** para anexar à documentação do projeto ou sistema de acompanhamento de vulnerabilidades.

## 🔒 Privacidade e funcionamento

- O projeto agora utiliza um servidor Node.js para fornecer os dados e salvar o progresso.
- O estado (checkboxes, status, notas, nome do projeto/tester) é salvo no servidor.
- Para limpar dados basta usar o botão de reset.

## 🤝 Contribuições

- Adicione novos itens de checklist em `data.js` (para OWASP, PTES, SAST, DAST) ou em `serverConfig.js` (hardening).
- Mantenha a estrutura de dados consistente para que o modal de guias funcione corretamente.
- Ajustes visuais podem ser aplicados em `styles.css`.

## 📚 Referências externas

- [OWASP Top 10 Web (2021)](https://owasp.org/Top10/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Mobile Application Security](https://owasp.org/www-project-mobile-security-testing-guide/)

> Este painel busca centralizar conhecimento em um único lugar para agilizar avaliações AppSec e pentests ofensivos.
