# AppSec Checklist & Guide – Design Guidelines

**Versão:** 2.0
**Última atualização:** 2025
**Autores:** AppSec Checklist Team

---

## 📋 Índice

1. [Filosofia de Design](#filosofia-de-design)
2. [Sistema de Cores](#sistema-de-cores)
3. [Tipografia](#tipografia)
4. [Espaçamento & Grid](#espaçamento--grid)
5. [Componentes](#componentes)
6. [Acessibilidade](#acessibilidade)
7. [Como Adicionar Novas Categorias](#como-adicionar-novas-categorias)
8. [Customização para Mobile & Cloud](#customização-para-mobile--cloud)
9. [Manutenção da Consistência Visual](#manutenção-da-consistência-visual)

---

## 🎨 Filosofia de Design

### Princípios Fundamentais

**1. Credibilidade Técnica sobre Gimmicks Visuais**

Este é um produto para profissionais de segurança ofensiva e analistas AppSec. O design deve transmitir seriedade, profissionalismo e conhecimento técnico profundo.

- ❌ **Evitar:** Animações excessivas, gradientes coloridos demais, ícones infantilizados
- ✅ **Preferir:** Paleta escura inspirada em terminais, tipografia clara, hierarquia visual forte

**2. Hierarquia Visual Clara para Priorização de Riscos**

Bug hunters e pentesters precisam identificar rapidamente itens críticos, falhas e chains de exploração.

- Use cores de severidade consistentes (vermelho=crítico, laranja=alto, amarelo=médio)
- Destaque visualmente itens "Falhou" vs. "Passou"
- Agrupe informações por contexto (OWASP, Mobile, Cloud, Advanced Techniques)

**3. Contraste Acessível (WCAG AAA quando possível)**

Testers frequentemente trabalham em ambientes com baixa luminosidade ou monitores variados.

- Contraste mínimo de 4.5:1 para texto normal
- Contraste de 7:1 para texto pequeno (quando possível)
- Testado com ferramentas de acessibilidade (axe DevTools, WAVE)

**4. Responsividade e Multi-Device**

O guia deve funcionar em:
- Desktop (1440px+): Layout completo com sidebar fixa
- Tablet (768px-1023px): Sidebar colapsável, grid adaptado
- Mobile (320px-767px): Stack vertical, navegação hamburger

---

## 🎨 Sistema de Cores

### Paleta Principal

```scss
// Backgrounds (camadas de profundidade)
$color-bg-primary: #0E1F2F;      // Fundo principal
$color-bg-elevated: #132A3F;     // Cards elevados
$color-bg-surface: #17344B;      // Surface de componentes
$color-bg-modal: #061421;        // Modais (mais escuro)

// Accent & Semantic
$color-accent: #00C6FF;          // Accent principal (links, CTAs)
$color-success: #3DDC97;         // Passou, completo
$color-danger: #FF6B6B;          // Falhou, crítico
$color-warning: #FFD166;         // Atenção, médio

// Text
$color-text-primary: #F8F9FA;    // Texto principal (alto contraste)
$color-text-secondary: #D1D5DB;  // Texto secundário
$color-text-muted: rgba(209, 213, 219, 0.7);  // Suporte
```

### Cores de Severidade (Findings)

```scss
$color-severity-critical: #FF6B6B;  // Vermelho vibrante
$color-severity-high: #FFA64D;      // Laranja
$color-severity-medium: #FFD166;    // Amarelo
$color-severity-low: #3DDC97;       // Verde
$color-severity-info: #00C6FF;      // Azul (accent)
```

### Uso Semântico

| Cor | Quando Usar | Exemplo |
|-----|-------------|---------|
| **Accent (#00C6FF)** | Links, CTAs primários, progresso | Botão "Exportar PDF", barra de progresso |
| **Success (#3DDC97)** | Status "Passou", itens completos | Tag "✅ Passou", checkmarks |
| **Danger (#FF6B6B)** | Status "Falhou", vulnerabilidades críticas | Tag "❌ Falhou", alerts |
| **Warning (#FFD166)** | Atenção, médio risco | Findings de severidade média |
| **Info (#6C8EEF)** | Informação, dicas | Tooltips, helper text |

### Contraste e Acessibilidade

Todas as combinações de texto/background atendem WCAG AA (4.5:1):

- `#F8F9FA` em `#0E1F2F`: **14.2:1** (AAA ✅)
- `#00C6FF` em `#0E1F2F`: **7.8:1** (AAA ✅)
- `#D1D5DB` em `#0E1F2F`: **11.3:1** (AAA ✅)

---

## ✍️ Tipografia

### Família de Fontes

```scss
$font-family-base: 'Inter', 'Poppins', 'Segoe UI', sans-serif;
$font-family-mono: 'Fira Code', 'Source Code Pro', monospace;
$font-family-heading: 'Inter', 'Poppins', sans-serif;
```

**Escolha:** Inter/Poppins são fontes sans-serif modernas com excelente legibilidade em telas e suporte a caracteres técnicos.

### Escala Tipográfica (1.25 ratio)

| Classe | Tamanho | Uso |
|--------|---------|-----|
| `.text--xs` | 0.75rem (12px) | Tags, metadata, footnotes |
| `.text--sm` | 0.875rem (14px) | Corpo de texto secundário, labels |
| `.text--md` | 1rem (16px) | **Corpo de texto principal** (base) |
| `.text--lg` | 1.25rem (20px) | Subtítulos, destaques |
| `.text--xl` | 1.5rem (24px) | Títulos de seção |
| `.text--2xl` | 2rem (32px) | Títulos principais, headings |
| `.text--3xl` | 2.5rem (40px) | Hero text, métricas grandes |

### Pesos de Fonte

- **300 (Light):** Nunca usar para texto principal
- **400 (Normal):** Corpo de texto
- **500 (Medium):** Labels, small headings
- **600 (Semibold):** Botões, CTA, títulos de cards
- **700 (Bold):** Headings, números de métricas
- **800 (Extrabold):** Uso esporádico, hero numbers

### Line Height & Letter Spacing

```scss
// Line Heights
$line-height-tight: 1.25;     // Headings grandes
$line-height-normal: 1.6;     // Corpo de texto (padrão)
$line-height-loose: 2;        // Espaçamento generoso

// Letter Spacing
$letter-spacing-tight: -0.01em;   // Títulos grandes
$letter-spacing-widest: 0.12em;   // UPPERCASE labels
```

---

## 📐 Espaçamento & Grid

### Sistema de Espaçamento (4px base)

Baseado no **8-point grid system** para consistência matemática.

```scss
$spacing-1: 0.25rem;   // 4px
$spacing-2: 0.5rem;    // 8px
$spacing-3: 0.75rem;   // 12px
$spacing-4: 1rem;      // 16px  ← Uso mais comum
$spacing-5: 1.25rem;   // 20px
$spacing-6: 1.5rem;    // 24px  ← Padrão para padding de cards
$spacing-8: 2rem;      // 32px
$spacing-10: 3rem;     // 48px
```

### Breakpoints Responsivos

| Nome | Largura | Uso |
|------|---------|-----|
| xs | 480px | Phones pequenos |
| sm | 640px | Phones grandes |
| md | 768px | Tablets portrait |
| lg | 1024px | Tablets landscape / Desktop pequeno |
| xl | 1280px | Desktop padrão |
| 2xl | 1536px | Desktop grande |

### Grid System

Uso de CSS Grid com 12 colunas:

```scss
$grid-columns: 12;
$grid-gutter: $spacing-6;  // 24px
```

**Exemplo de uso:**

```scss
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: $spacing-6;
}
```

---

## 🧩 Componentes

### Botões

**Variantes:**

1. **Primary** (`.btn--primary`): CTAs principais (Exportar PDF, Salvar)
2. **Secondary** (`.btn--secondary`): Ações secundárias (Filtrar, Limpar)
3. **Tertiary** (`.btn--tertiary`): Ações menos importantes
4. **Ghost** (`.btn--ghost`): Ações sutis, em listas
5. **Danger** (`.btn--danger`): Ações destrutivas (Deletar, Resetar)

**Tamanhos:**
- Small (`.btn--sm`): Uso em tabelas, listas compactas
- Default: Uso geral
- Large (`.btn--lg`): Hero sections, CTAs principais

**Estados:**
- `:hover` - Elevação leve, shadow aumentado
- `:active` - Sem elevação (pressed)
- `:disabled` - Opacity 0.5, cursor not-allowed
- `:focus-visible` - Focus ring de 3px azul

### Cards

**Tipos:**

1. **Card Padrão** (`.card`): Glass morphism, padding médio
2. **Card Elevado** (`.card--elevated`): Com hover effect e shadow forte
3. **Metric Card** (`.metric-card`): Para dashboards, com header/value/subtitle

**Anatomia do Metric Card:**

```html
<div class="metric-card">
  <header class="metric-card__header">
    <span class="metric-label">Label</span>
    <span class="metric-icon">📊</span>
  </header>
  <strong class="metric-card__value">1,234</strong>
  <p class="metric-card__subtitle">Descrição da métrica</p>
</div>
```

### Tags & Badges

**Uso Semântico:**

- `.tag--critical`: Vulnerabilidades críticas
- `.tag--high`: Riscos altos
- `.tag--medium`: Riscos médios
- `.tag--low`: Riscos baixos
- `.tag--info`: Informações gerais
- `.tag--success`: Passou, completo
- `.tag--danger`: Falhou
- `.tag--warning`: Atenção necessária

**Exemplo:**

```html
<span class="tag tag--critical">CRITICAL</span>
<span class="tag tag--success">✅ Passou</span>
```

### Forms & Inputs

**Input States:**

- Default: Borda sutil
- `:hover`: Borda accent clara
- `:focus`: Focus ring azul (acessibilidade)
- `.input--error`: Borda vermelha
- `.input--success`: Borda verde

**Labels obrigatórios:**

```html
<label class="label label--required">Email</label>
```

### Progress Bars

**Tipos:**

1. **Linear** (`.progress`): Barras horizontais
   - Small (`.progress--sm`): 4px height
   - Default: 8px height
   - Large (`.progress--lg`): 12px height

2. **Radial** (`.progress-radial`): Círculos de progresso
   - Usado para overview de conclusão

**Exemplo Linear:**

```html
<div class="progress">
  <div class="progress__bar" style="width: 65%"></div>
</div>
```

### Modais

**Estrutura:**

```html
<div class="modal">
  <div class="modal__content">
    <button class="modal__close">✖</button>
    <header class="modal__header">
      <h3 class="modal__title">Título</h3>
      <p class="modal__description">Descrição</p>
    </header>
    <div class="modal__body">
      <!-- Conteúdo -->
    </div>
    <footer class="modal__footer">
      <button class="btn btn--secondary">Cancelar</button>
      <button class="btn btn--primary">Confirmar</button>
    </footer>
  </div>
</div>
```

**Características:**

- Backdrop com blur (4px)
- Animação slideUp ao abrir
- Scroll interno suave com custom scrollbar
- Botão fechar com animação de rotação

### Tables

**Variantes:**

- `.table`: Padrão
- `.table--striped`: Linhas alternadas
- `.table--bordered`: Com bordas
- `.table--compact`: Padding reduzido

**Uso:**

Sempre incluir `<thead>` e `<tbody>` para semântica.

---

## ♿ Acessibilidade

### Checklist de Acessibilidade

✅ **Contraste:** Todas as combinações de cor atendem WCAG AA (mínimo 4.5:1)
✅ **Focus Visible:** Focus ring de 3px em azul para navegação por teclado
✅ **ARIA Labels:** `aria-label`, `aria-labelledby`, `aria-describedby` em elementos interativos
✅ **Semantic HTML:** Uso correto de `<header>`, `<nav>`, `<main>`, `<section>`, `<article>`
✅ **Keyboard Navigation:** Todos os componentes acessíveis via Tab/Enter/Space
✅ **Screen Reader:** Classes `.sr-only` para conteúdo apenas para leitores de tela

### Focus Ring

Aplicado automaticamente em:
- Botões
- Inputs
- Links
- Elementos focáveis customizados

```scss
@mixin focus-ring {
  outline: none;
  border-color: rgba(0, 198, 255, 0.65);
  box-shadow: 0 0 0 3px rgba(0, 198, 255, 0.25);
}
```

### Uso de ARIA

**Exemplo: Modal**

```html
<div id="guide-modal"
     class="modal"
     role="dialog"
     aria-modal="true"
     aria-labelledby="modal-title">
  <h3 id="modal-title">Guia Técnico</h3>
  <!-- conteúdo -->
</div>
```

**Exemplo: Navegação**

```html
<nav aria-label="Domínios do checklist">
  <ul>
    <li><button aria-current="true">OWASP Web</button></li>
  </ul>
</nav>
```

---

## 🆕 Como Adicionar Novas Categorias

### Passo 1: Adicionar Dados (`data.mjs`)

```javascript
{
  id: "nova-categoria",
  name: "Nova Categoria",
  description: "Descrição da categoria",
  sections: [
    {
      id: "sec-1",
      title: "Seção 1",
      summary: "Resumo da seção",
      items: [
        {
          id: "item-1",
          title: "Título do item",
          description: "Descrição do item",
          guide: {
            overview: "Visão geral técnica",
            impact: "Impacto de segurança",
            detection: ["Como detectar", "Payloads de teste"],
            tools: ["Ferramenta 1", "Ferramenta 2"],
            commands: ["comando1", "comando2"],
            steps: ["Passo 1", "Passo 2"],
            mitigation: ["Mitigação 1", "Mitigação 2"],
            evidence: ["Evidência 1", "Evidência 2"],
            references: ["https://link1.com", "https://link2.com"]
          }
        }
      ]
    }
  ]
}
```

### Passo 2: Validar Estrutura

Certifique-se de que todos os campos obrigatórios estão presentes:

- ✅ `id` único
- ✅ `name` e `description`
- ✅ `sections` array com pelo menos 1 seção
- ✅ Cada item com `guide` completo

### Passo 3: Testar Renderização

1. Inicie o servidor: `npm start`
2. Navegue até a nova categoria
3. Verifique se o modal de guia abre corretamente
4. Teste filtros e busca

### Passo 4: Adicionar Documentação

Crie um arquivo Markdown em `/docs/` explicando a categoria:

```markdown
# Nova Categoria - Guia Técnico

## Visão Geral

Explicação detalhada...

## Checklists Incluídos

- Item 1
- Item 2

## Ferramentas Recomendadas

...
```

---

## 📱 Customização para Mobile & Cloud

### Mobile Security

Para adicionar categorias específicas de Mobile (iOS/Android):

1. **Estrutura Sugerida:**

```
mobile-security/
  ├── storage/          (Keychain, Keystore)
  ├── network/          (SSL Pinning, Certificate Validation)
  ├── code-protection/  (Obfuscation, Anti-Reverse)
  ├── runtime/          (Frida Detection, Anti-Debug)
  └── permissions/      (Over-Permission, Dangerous Permissions)
```

2. **Ferramentas Específicas:**

- objection, Frida, MobSF, jadx, Hopper, apktool

3. **Templates de Evidência:**

- Screenshots de Keychain Dumper
- Logs de adb logcat filtrados
- Dumps de código decompilado
- Relatórios de MobSF

### Cloud Native & Kubernetes

Para adicionar categorias de Cloud:

1. **Estrutura Sugerida:**

```
cloud-native/
  ├── container-security/  (Image Scanning, Secrets in Layers)
  ├── k8s-security/        (RBAC, Network Policies, Pod Security)
  ├── serverless/          (IAM Roles, Cold Start Risks)
  └── cicd-pipeline/       (Build Security, Artifact Signing)
```

2. **Ferramentas Específicas:**

- trivy, grype, kubeaudit, kubectl, cosign, in-toto

3. **Métricas Específicas:**

- CVEs por image
- Service Accounts com over-permissions
- NetworkPolicies ausentes
- SBOM compliance rate

---

## 🎯 Manutenção da Consistência Visual

### Checklist de Review

Ao adicionar novos componentes ou páginas:

- [ ] Cores estão no design system (`appsec-design-system.scss`)?
- [ ] Espaçamento usa tokens do sistema (`$spacing-X`)?
- [ ] Tipografia usa classes utilitárias (`.text--md`)?
- [ ] Componentes têm estados de hover/focus/disabled?
- [ ] Contraste atende WCAG AA mínimo (4.5:1)?
- [ ] Responsividade testada em mobile/tablet/desktop?
- [ ] ARIA labels presentes em elementos interativos?
- [ ] Navegação por teclado funciona?

### Padrões de Nomenclatura

**Classes CSS (BEM):**

```scss
.block {}
.block__element {}
.block--modifier {}
```

**Exemplos:**

```scss
.modal {}
.modal__header {}
.modal__title {}
.modal--large {}

.btn {}
.btn--primary {}
.btn--sm {}
```

**Variáveis SCSS:**

```scss
$category-property-variant: value;

// Exemplos:
$color-bg-primary: #0E1F2F;
$spacing-6: 1.5rem;
$font-size-xl: 1.5rem;
```

### Versionamento de Design

Quando fazer mudanças que quebram compatibilidade:

1. Incremente versão no header do SCSS
2. Documente breaking changes em CHANGELOG.md
3. Forneça migration guide
4. Mantenha fallbacks quando possível

---

## 🔗 Referências

### Design System Inspirações

- [Material Design 3](https://m3.material.io/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Radix UI](https://www.radix-ui.com/)
- [Chakra UI](https://chakra-ui.com/)

### Acessibilidade

- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [A11y Project](https://www.a11yproject.com/)
- [MDN Accessibility](https://developer.mozilla.org/en-US/docs/Web/Accessibility)

### Ferramentas de Validação

- **axe DevTools:** Extensão de browser para testes de acessibilidade
- **WAVE:** Web accessibility evaluation tool
- **Lighthouse:** Auditorias de performance, acessibilidade, SEO
- **Contrast Checker:** WebAIM Contrast Checker

---

## 📝 Changelog

### v2.0 (2025)
- ✅ Sistema de cores expandido com severidades
- ✅ Componentes completos (modals, progress, tables)
- ✅ Mixins responsivos e utilitários
- ✅ Animações e transições profissionais
- ✅ Documentação completa de guidelines

### v1.0 (2024)
- ✅ Design system inicial
- ✅ Paleta dark theme
- ✅ Componentes básicos

---

**Mantido por:** AppSec Checklist Team
**Licença:** MIT
**Repositório:** [github.com/appsec-checklist](https://github.com/appsec-checklist)

---

© 2025 AppSec Checklist & Guide – Design Guidelines
