# 🔒 OWASP Checklist Platform

> **Plataforma simples de testes de segurança e conformidade OWASP**
> HTML5 + JavaScript Vanilla + Python. Acesse em localhost, sem dependências Node.js.

---

## 🎯 O que é?

Uma **plataforma web simples e leve** para teste de segurança com:

✅ **Checklists OWASP Completos**
- Web Top 10 (2021)
- API Security Top 10 (2023)
- Mobile Top 10 (2023)
- LLM Top 10 (2024)

✅ **Rastreamento de Progresso** - Salvo localmente no navegador
✅ **Exportação de Relatórios** - Em formato texto
✅ **Interface Responsiva** - Funciona em desktop e mobile
✅ **Sem Dependências Externas** - Apenas Python e um navegador
✅ **Localhost Apenas** - Seguro e privado

---

## 🚀 Como usar?

### 1️⃣ Iniciar o servidor

```bash
python3 server.py
```

Ou no Windows:

```bash
python server.py
```

### 2️⃣ Abrir no navegador

Acesse: **http://localhost:8000**

### 3️⃣ Usar a plataforma

1. Selecione um checklist no menu lateral (Web, API, Mobile ou LLM)
2. Clique nos itens para marcar como completo
3. Veja o progresso em tempo real
4. Exporte o relatório em TXT

---

## 📁 Estrutura

```
Owasp_Checklist_testing/
├── index.html              # Aplicação completa (HTML5 + CSS + JS)
├── server.py               # Servidor Python simples
├── README.md               # Este arquivo
└── docs/                   # Documentação técnica adicional
```

---

## ✨ Funcionalidades

- 📋 **40+ itens de checklist** por categoria (4 categorias principais)
- 🎨 **Interface moderna** com design responsivo
- 💾 **Salva progresso** localmente no navegador
- 📥 **Exporta relatórios** em formato texto
- 🎯 **Rastreamento visual** com barras de progresso
- 🏷️ **Classificação de severidade** (Critical, High, Medium, Low)

---

## 🛠️ Requisitos

- Python 3.6+
- Navegador moderno (Chrome, Firefox, Safari, Edge)

---

## 📚 Documentação Técnica

Veja a pasta `/docs` para guias de:
- API Security
- Data Validation em múltiplas linguagens
- SAST/DAST Tools
- DevSecOps Automation
- E muito mais!

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se livre para:
- Adicionar novos checklists
- Melhorar a interface
- Corrigir bugs
- Sugerir novas funcionalidades

---

## 📜 Licença

Este projeto é licenciado sob a licença ISC.

---

## 🙏 Agradecimentos

- **OWASP Foundation** - pelos frameworks e checklists
- **Comunidade AppSec** - por compartilhar conhecimento

---

## 📞 Suporte

- 📖 Consulte a documentação em `/docs`
- 🐛 Reporte problemas via GitHub Issues

---

**Feito com ❤️ para a comunidade de Application Security**
