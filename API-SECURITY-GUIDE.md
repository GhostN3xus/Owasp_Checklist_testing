# Guia Prático de Segurança de API

Este guia foca em como testar a segurança de APIs (RESTful) usando ferramentas como Burp Suite e Postman, com ênfase no **OWASP API Security Top 10**.

## 1. O que é o OWASP API Security Top 10?

É uma lista de conscientização dos 10 riscos de segurança mais críticos para APIs. Diferente do Top 10 para web, ele aborda vulnerabilidades específicas do ecossistema de APIs, como:

- **API1:2019 Broken Object Level Authorization (BOLA):** Acesso indevido a dados de outros usuários ao manipular o ID de um objeto na requisição.
- **API2:2019 Broken User Authentication:** Falhas na autenticação que permitem a um invasor se passar por outro usuário.
- **API3:2019 Excessive Data Exposure:** A API retorna mais dados do que o necessário para o cliente.
- **API5:2019 Broken Function Level Authorization:** Restrição de acesso inadequada a funções administrativas.
- **API6:2019 Mass Assignment:** A API permite que um cliente modifique campos sensíveis (ex: `isAdmin`) que não deveriam ser alterados.

## 2. Ferramentas Essenciais

- **Postman:** Para mapear e interagir com a API de forma estruturada.
- **Burp Suite:** Para interceptar, manipular e analisar as requisições enviadas pelo Postman.

## 3. Mapeando a API com Postman

Antes de testar, você precisa entender como a API funciona.

1. **Importe a documentação:** Se a API tiver uma especificação (OpenAPI/Swagger), importe-a no Postman para criar uma coleção de requisições prontas.
2. **Crie uma coleção manualmente:** Se não houver documentação, navegue pela aplicação cliente (web ou mobile) com o Burp Suite ligado e capture as chamadas à API para recriá-las no Postman.

## 4. Testando Vulnerabilidades Específicas

Para os exemplos a seguir, imagine uma API com os seguintes endpoints:
- `GET /api/users/{userId}`: Retorna dados do usuário.
- `PUT /api/users/{userId}`: Atualiza dados do usuário.

### Teste de BOLA (API1:2019)

**Cenário:** O usuário A (ID `101`) está logado e quer ver se consegue acessar os dados do usuário B (ID `102`).

1. **Requisição legítima no Postman:**
   - Envie uma requisição `GET` para `/api/users/101`.
   - Inclua o token de autenticação do usuário A no cabeçalho `Authorization`.
   - A API deve retornar os dados do usuário A.

2. **Manipulação no Burp Suite Repeater:**
   - Envie a mesma requisição do Postman, mas intercepte-a com o Burp.
   - Envie a requisição para o **Repeater** (Ctrl+R).
   - No Repeater, **altere a URL** para `/api/users/102` (ID do usuário B), mas **mantenha o token de autenticação do usuário A**.
   - Envie a requisição.

3. **Análise do Resultado:**
   - **Vulnerável:** Se a API retornar os dados do usuário B (código 200 OK com o corpo da resposta contendo os dados de B), ela está vulnerável a BOLA.
   - **Seguro:** Se a API retornar um erro de autorização (`403 Forbidden` ou `401 Unauthorized`), ela está protegendo os dados corretamente.

### Teste de Mass Assignment (API6:2019)

**Cenário:** Ao atualizar seu perfil, um usuário tenta se promover a administrador adicionando um campo `isAdmin: true` no corpo da requisição.

1. **Requisição legítima no Postman:**
   - Envie uma requisição `PUT` para `/api/users/101`.
   - No corpo da requisição (JSON), envie os dados que você pode alterar:
     ```json
     {
       "name": "Novo Nome",
       "email": "novo@email.com"
     }
     ```

2. **Manipulação no Burp Suite Repeater:**
   - Intercepte a requisição e envie para o **Repeater**.
   - **Adicione um campo extra** no corpo JSON que não deveria ser modificável pelo usuário:
     ```json
     {
       "name": "Novo Nome",
       "email": "novo@email.com",
       "isAdmin": true
     }
     ```
   - Envie a requisição.

3. **Análise do Resultado:**
   - **Vulnerável:** Se a resposta for `200 OK` e, ao consultar novamente o perfil do usuário (`GET /api/users/101`), o campo `isAdmin` estiver como `true`, a API é vulnerável a Mass Assignment.
   - **Seguro:** A API deve ignorar o campo `isAdmin` ou retornar um erro (`400 Bad Request`).

## 5. Automação de Testes com Postman

O Postman permite criar scripts de teste na aba **"Tests"** para automatizar verificações básicas.

**Exemplo de script para verificar o status code:**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});
```

**Exemplo para verificar se dados sensíveis não estão sendo expostos (API3:2019):**
```javascript
pm.test("Response should not contain sensitive data like password hash", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.not.have.property('passwordHash');
});
```
Isso ajuda a criar uma suíte de regressão para segurança, garantindo que as vulnerabilidades corrigidas não retornem.

## 6. Ferramentas do Kali Linux para Agilizar Testes de API

O Kali Linux oferece ferramentas que automatizam a detecção de vulnerabilidades comuns em APIs.

### Commix (Command Injection)

Se um endpoint de API parece passar dados para o sistema operacional, você pode testá-lo com o `commix`.

**Cenário:** Um endpoint `GET /api/tools/ping?host=8.8.8.8` executa um ping.

**Comando:**
```bash
commix -u "http://api.example.com/api/tools/ping?host=8.8.8.8" --batch
```
O `commix` tentará injetar comandos do sistema operacional no parâmetro `host`.

### JWT_tool (Testes de JSON Web Tokens)

Para APIs que usam JWT para autenticação, o `jwt_tool` é excelente para testar vulnerabilidades comuns.

**Cenário:** A API usa um token JWT fraco.

**Comando para verificar fraquezas conhecidas (como `alg:none` e chaves fracas):**
```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Comando para tentar um ataque de dicionário na chave secreta:**
```bash
jwt_tool [TOKEN] -C -d /usr/share/wordlists/rockyou.txt
```
Isso ajuda a identificar rapidamente tokens que podem ser quebrados ou manipulados.
