# 🧠 Painel de Segurança AppSec

Um painel interativo e offline para guiar avaliações de segurança, cobrindo desde a configuração de nuvem até testes de API e aplicações web. Este projeto centraliza checklists, guias práticos e ferramentas para agilizar auditorias de segurança.

## 🚀 Recursos Principais

- **Interface Completa:** Navegação por abas para diferentes domínios de segurança.
- **Checklists Detalhados:** Acompanhe o progresso com status, notas e guias técnicos.
- **Foco Offline:** Funciona 100% no navegador, salvando o progresso localmente.
- **Exportação de Relatórios:** Gere relatórios em PDF para documentar suas descobertas.

## 📚 Guias Práticos de Segurança

Os seguintes guias fornecem instruções detalhadas, comandos e exemplos para executar testes de segurança em diferentes áreas:

| Guia | Descrição |
|---|---|
| **[Guia Prático de CSPM](./CSPM-PRACTICAL-GUIDE.md)** | Como auditar a segurança de ambientes AWS, GCP e Azure com Prowler e Scout Suite. |
| **[Guia Prático de DAST](./DAST-PRACTICAL-GUIDE.md)** | Como escanear aplicações web em busca de vulnerabilidades do OWASP Top 10 usando OWASP ZAP e Burp Suite. |
| **[Guia de Segurança de API](./API-SECURITY-GUIDE.md)** | Como testar APIs com foco no OWASP API Security Top 10, usando Burp Suite, Postman e ferramentas do Kali Linux. |
| **[Guia de Automação DevSecOps](./DEVSECOPS-AUTOMATION-GUIDE.md)** | Como integrar scanners de segurança (SAST e DAST) em um pipeline de CI/CD com GitHub Actions. |
| **[Exemplo de Relatório de Segurança](./SAMPLE-SECURITY-REPORT.md)** | Um modelo de como consolidar e apresentar as descobertas de uma análise de segurança. |

## 🛠️ Como Usar

1.  Clone o repositório.
2.  Abra o arquivo `index.html` em seu navegador.
3.  Use as abas para navegar entre os diferentes checklists.
4.  Clique em **📘 Guia real** em qualquer item para ver instruções detalhadas.
5.  Exporte seu progresso a qualquer momento clicando em **📄 Exportar PDF**.

## 🔒 Privacidade

Todos os dados inseridos (notas, status dos itens) são salvos apenas no `localStorage` do seu navegador. Nenhuma informação é enviada para servidores externos.
