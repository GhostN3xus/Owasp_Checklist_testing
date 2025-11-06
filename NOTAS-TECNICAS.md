# 🧾 Notas Técnicas

## Arquitetura da aplicação

- O dashboard foi construído utilizando **HTML, CSS e JavaScript puros**.
- Não há dependências externas nem chamadas a APIs, permitindo uso offline completo.
- Todos os dados das checklists estão em `data.js`, `serverConfig.js` e `securityTools.js`.
- O modal de guia consome os objetos `guide` presentes em cada item, garantindo reuso de conteúdo.
- Estrutura esperada para `guide`: `overview`, `impact`, `detection`, `tools`, `commands`, `steps`, `mitigation`, `evidence` e `references` (todos opcionais, exibidos somente quando preenchidos).

## Persistência local

- As informações são armazenadas em `localStorage` com a chave `appsec-dashboard-state-v1`.
- Estrutura do objeto salvo:
  ```json
  {
    "items": {
      "categoria::secao::item": {
        "checked": true,
        "status": "passed",
        "notes": "Evidência..."
      }
    },
    "meta": {
      "project": "Nome do projeto",
      "tester": "Responsável"
    }
  }
  ```
- A função **Resetar Dados** limpa o estado e atualiza a interface.

## Geração de relatório

- Ao clicar em **Exportar PDF**, a aplicação abre uma nova janela com HTML formatado.
- Utilize a função de impressão do navegador para salvar como PDF.
- Todo conteúdo (status, notas, conclusão) é coletado diretamente do estado local.

## Segurança e privacidade

- Nenhum dado é enviado para terceiros; tudo fica restrito ao navegador do usuário.
- Para ambientes altamente sensíveis, recomenda-se abrir o dashboard em estação isolada.
- Caso precise compartilhar resultados, gere o PDF e armazene em repositório seguro.

## Customizações futuras

- **Novas checklists**: adicione objetos no array `checklistData` ou `serverHardening`.
- **Integração com APIs**: é possível estender `app.js` para salvar dados em backend seguro.
- **Internacionalização**: todo texto está centralizado nos arquivos de dados ou templates HTML.
- **Tema**: ajustes em `styles.css` permitem adaptar a paleta para modo claro.

## Manutenção

- Teste regularmente em navegadores atualizados (Chrome, Firefox, Edge).
- Utilize o console do navegador (`F12`) para depurar eventuais problemas no `localStorage`.
- Backup: exporte os arquivos `.md` e `.js` para manter histórico de checklists personalizados.
