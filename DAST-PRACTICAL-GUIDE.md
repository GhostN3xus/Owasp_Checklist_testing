# Guia Prático de DAST com OWASP ZAP

Este guia demonstra como usar o OWASP ZAP (Zed Attack Proxy), uma ferramenta open-source de *Dynamic Application Security Testing (DAST)*, para encontrar vulnerabilidades de segurança em aplicações web, com foco no **OWASP Top 10**.

## 1. O que é DAST e o OWASP Top 10?

- **DAST (Dynamic Application Security Testing):** É uma abordagem de teste de segurança "caixa-preta" onde o scanner interage com a aplicação em execução, sem conhecimento do código-fonte, para encontrar vulnerabilidades.
- **OWASP Top 10:** É uma lista de conscientização que representa os 10 riscos de segurança mais críticos para aplicações web. Inclui vulnerabilidades como Injeção (SQL, NoSQL, OS), Quebra de Autenticação, Exposição de Dados Sensíveis, etc.

## 2. Instalação do OWASP ZAP

O ZAP é multiplataforma (Windows, macOS, Linux) e requer Java 8+.

1. **Baixe o instalador:** Acesse o [site oficial do ZAP](https://www.zaproxy.org/download/) e baixe a versão para o seu sistema operacional.
2. **Instale:** Siga as instruções do instalador.

## 3. Rodando um Scan Automatizado

A forma mais simples de começar é com o scan automatizado, que faz o *spidering* (mapeamento) e o *active scanning* (ataque) de forma automática.

**Passo a Passo:**

1. **Inicie o OWASP ZAP.**
2. Na tela de início rápido, localize a caixa **"Automated Scan"**.
3. No campo **"URL to attack"**, insira a URL da sua aplicação de teste.
   - **Aviso:** Use apenas aplicações que você tenha permissão para testar. Para aprendizado, use aplicações vulneráveis de propósito, como a [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).
4. Clique no botão **"Attack"**.

**O que o ZAP está fazendo?**

- **Spidering:** O ZAP navegará por todos os links que encontrar na aplicação para mapear sua estrutura.
- **Active Scanning:** Após o spidering, o ZAP enviará milhares de payloads maliciosos para cada página e parâmetro descoberto, tentando explorar vulnerabilidades conhecidas (SQL Injection, XSS, etc.).

## 4. Analisando os Resultados

Após o término do scan, os resultados são exibidos na interface do ZAP.

1. **Aba "Alerts" (Alertas):** Localizada na parte inferior da tela, esta aba é a mais importante. Ela lista todas as vulnerabilidades encontradas, agrupadas por tipo.
2. **Classificação de Risco:** As vulnerabilidades são sinalizadas com bandeiras coloridas:
   - **Vermelha (High):** Problemas críticos, como SQL Injection.
   - **Laranja (Medium):** Riscos moderados, como Cross-Site Scripting (XSS).
   - **Amarela (Low):** Problemas de menor impacto.
   - **Azul (Informational):** Observações que não são vulnerabilidades, mas podem ser úteis.
3. **Detalhes da Vulnerabilidade:**
   - Ao clicar em um alerta, o painel à direita mostrará informações detalhadas:
     - **URL:** Onde a vulnerabilidade foi encontrada.
     - **Parameter:** O parâmetro vulnerável.
     - **Attack:** O payload que o ZAP usou.
     - **Description:** Uma explicação sobre o risco.
     - **Solution:** Recomendações de como corrigir o problema.

## 5. Gerando Relatórios

Gerar um relatório é fundamental para compartilhar as descobertas.

1. No menu superior, vá para **Report > Generate HTML Report...** (outros formatos como XML e Markdown também estão disponíveis).
2. Escolha um nome e local para salvar o arquivo.
3. O relatório gerado conterá um resumo executivo e uma lista detalhada de todos os alertas, ideal para documentar e entregar para as equipes de desenvolvimento.

Este guia inicial cobre o básico do scan automatizado. Para testes mais avançados, o ZAP pode ser usado como um proxy para interceptar e modificar o tráfego manualmente, permitindo testes mais profundos e direcionados.

## 6. Alternativa: Usando o Burp Suite Scanner

O Burp Suite é a ferramenta padrão da indústria para testes de segurança de aplicações web. Sua versão Community é gratuita, mas o scanner automatizado está disponível apenas na versão Professional.

**Passo a Passo (Burp Suite Professional):**

1. **Configure o Proxy:**
   - Abra o Burp Suite.
   - Vá para a aba **Proxy > Intercept**. Certifique-se de que a interceptação está desligada ("Intercept is off").
   - Configure seu navegador para usar o proxy do Burp, geralmente em `127.0.0.1:8080`.

2. **Mapeie a Aplicação (Spidering):**
   - Navegue pela aplicação web que você deseja testar.
   - Na aba **Target > Site map**, você verá o Burp Suite preenchendo a estrutura do site à medida que você navega.

3. **Inicie o Scan Ativo:**
   - No mapa do site, clique com o botão direito no domínio alvo.
   - Selecione **"Actively scan this host"**.
   - O Burp iniciará uma varredura ativa, enviando ataques para descobrir vulnerabilidades.

4. **Analise os Resultados:**
   - Vá para a aba **Dashboard**.
   - A seção **"Issue activity"** mostrará as vulnerabilidades em tempo real.
   - As descobertas são classificadas por severidade (High, Medium, Low) e confiança (Certain, Firm, Tentative).
   - O Burp oferece descrições detalhadas e recomendações de correção para cada vulnerabilidade encontrada.

5. **Gere um Relatório:**
   - Selecione os problemas que deseja incluir no relatório.
   - Clique com o botão direito e escolha **"Report selected issues"**.
   - Escolha o formato (HTML é o mais comum) e personalize o relatório.
