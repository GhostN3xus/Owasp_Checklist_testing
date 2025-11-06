# 🧪 Guia Prático de Testes

Este documento traz um passo a passo objetivo para executar o OWASP AppSec Checklist Dashboard offline, realizar testes técnicos e gerar o relatório final.

## 1. Preparar o ambiente

1.1. Clone ou copie o diretório para sua estação de trabalho.

1.2. Opcional: levante um servidor HTTP local para testar recursos que dependem de requisições.

```bash
cd Owasp_Checklist_testing
python3 -m http.server 8000
# Acesse http://localhost:8000/index.html
```

1.3. Caso não deseje rodar um servidor, basta abrir `index.html` diretamente no navegador (Chrome, Firefox, Edge).

## 2. Configurar o painel

2.1. Informe o **nome do projeto** (ex.: "Portal Financeiro") e o **tester responsável**.

2.2. Escolha a aba referente ao escopo atual:

- `OWASP Web` – Aplicações web tradicionais.
- `OWASP API` – Interfaces REST/GraphQL, microserviços e APIs públicas.
- `PTES` – Ciclo completo de pentest (do planejamento à pós-exploração).
- `SAST` – Verificações de código por linguagem.
- `DAST` – Testes dinâmicos, payloads e checagens em produção/homologação.
- `Server Config` – Hardening de IIS, Apache, Nginx, Windows e Linux.

## 3. Conduzir os testes

3.1. Para cada card do checklist:

- Leia o resumo para entender o objetivo do controle.
- Execute os testes descritos no botão **📘 Guia real**.
- Marque a checkbox ao finalizar o item.
- Selecione o status apropriado (Passou, Falhou, N/A).
- Registre evidências no campo de notas (payloads, logs, prints, links). Utilize markdown simples se preferir.

3.2. Exemplos de comandos sugeridos (todos listados no painel):

```bash
# SQL Injection
sqlmap -u 'https://app.local/produto?id=1' --batch --risk=2

# Teste de cabeçalhos
curl -I https://app.local | egrep 'strict-transport|content-security-policy'

# Varredura SSRF
curl -X POST https://app.local/render -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# SAST Python
bandit -r src/ -lll
```

3.3. Utilize as ferramentas recomendadas na barra lateral como referência rápida (Burp, ZAP, sqlmap, Semgrep, nmap, trivy etc.).

## 4. Exportar o relatório

4.1. Após concluir os testes, clique em **📄 Exportar PDF**.

4.2. Uma nova janela será aberta com o relatório consolidado.

4.3. Use `Ctrl + P` (Windows/Linux) ou `Cmd + P` (macOS) e escolha “Salvar como PDF”.

4.4. Arquive o PDF gerado no repositório de evidências do projeto.

## 5. Resetar ou iniciar novo ciclo

- Utilize **🧹 Resetar Dados** para limpar o `localStorage` e começar uma nova rodada.
- Se preferir, limpe manualmente os dados do site no navegador.

## 6. Boas práticas adicionais

- Documente descobertas críticas imediatamente e comunique o time responsável.
- Combine os resultados do dashboard com scanners automatizados (ZAP, Nessus, Burp, trivy).
- Para cada falha, indique severidade, impacto e recomendação.
- Atualize os arquivos `data.js` e `serverConfig.js` com novos casos aprendidos em campo.

Bom hacking responsável! 🛡️
