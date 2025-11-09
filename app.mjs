import { securityTools } from "./securityTools.mjs";
import { serverHardening } from "./serverConfig.mjs";
import { cloudSecurityChecklist } from "./cloudSecurity.mjs";
import { secureCodeChecklist } from "./secureCodeChecklist.mjs";
import { owaspCheatSheetChecklist } from "./owaspCheatSheetChecklist.mjs";
import { apiSecurityChecklist } from "./apiSecurity.mjs";
import { mobileSecurityChecklist } from "./mobileSecurity.mjs";
import { threatModelingChecklist } from "./threatModeling.mjs";
import { businessLogicChecklist } from "./businessLogic.mjs";
import { supplyChainSecurityChecklist } from "./supplyChainSecurity.mjs";
import { loggingMonitoringChecklist } from "./loggingMonitoring.mjs";
import { renderStatusBadge } from "./logic.js";
import { getReferenceUrl } from "./documentationLinks.mjs";
import { generateFullReport, generatePartialReport } from "./reportTemplate.mjs";

const WORKFLOW_STEPS = [
  { id: "recon", label: "Recon & Asset Discovery" },
  { id: "testing", label: "Testar & Fuzzing" },
  { id: "access", label: "Verificar Controles" },
  { id: "report", label: "Reportar & Evidenciar" },
  { id: "mitigate", label: "Mitigar & Validar" }
];

const INTERNAL_DOCS = {
  usage: {
    title: "Como usar este guia",
    description:
      "Estruture sua auditoria iniciando pelo recon, vinculando itens às fases do workflow e utilizando os templates de evidência para cada finding.",
    body: [
      "1. Selecione uma seção do checklist no menu lateral para visualizar controles associados.",
      "2. Utilize os filtros por status, tester e fase para organizar a rodada de testes.",
      "3. Documente cada teste com notas, narrativa de evidência e anexos. Marque a checklist de evidências para garantir consistência.",
      "4. Gere o relatório completo ao final ou exporte uma seleção parcial para revisões intermediárias." 
    ]
  },
  "new-section": {
    title: "Adicionar nova seção",
    description:
      "Estruture novas seções com título, sumário, itens (id, title, description) e campo guide com conteúdo técnico completo.",
    body: [
      "1. Atualize o arquivo data.mjs (ou o checklist específico) adicionando um novo objeto em sections.",
      "2. Cada item deve conter o campo guide com chaves: overview, impact, detection, tools, commands, steps, mitigation, evidence, references.",
      "3. Recompile o projeto com `npm run build` para atualizar o bundle.",
      "4. Garanta que IDs sejam únicos para evitar conflitos de estado." 
    ]
  },
  customization: {
    title: "Customizar para Mobile & Cloud Native",
    description:
      "Expanda o checklist adicionando controles específicos para mobile (secure storage, jailbreak detection) e Cloud Native (IAM, CSPM, supply-chain).",
    body: [
      "1. Utilize as seções existentes de Cloud Security e adicione controles específicos para Kubernetes, serverless e CI/CD.",
      "2. Para Mobile, crie seções abordando armazenamento seguro, transporte, jailbreak e engenharia reversa.",
      "3. Atualize o workflow incluindo fases de publicação em lojas/app stores quando aplicável.",
      "4. Ajuste as métricas adicionando tags de plataforma para facilitar filtros futuros." 
    ]
  }
};

const DEFAULT_EVIDENCE_FLAGS = {
  screenshot: false,
  logs: false,
  payload: false,
  impact: false
};

function normalizeEvidenceFlags(flags = {}) {
  return {
    screenshot: Boolean(flags.screenshot),
    logs: Boolean(flags.logs),
    payload: Boolean(flags.payload),
    impact: Boolean(flags.impact)
  };
}

function normalizeItemState(state = {}) {
  return {
    checked: Boolean(state.checked),
    status: state.status ?? "",
    notes: state.notes ?? "",
    attachments: Array.isArray(state.attachments) ? [...state.attachments] : [],
    severity: state.severity ?? "medium",
    stage: state.stage ?? "recon",
    assignee: state.assignee ?? "",
    priority: state.priority ?? "p2",
    evidenceNarrative: state.evidenceNarrative ?? "",
    evidenceChecklist: normalizeEvidenceFlags(state.evidenceChecklist)
  };
}

document.addEventListener("DOMContentLoaded", main);

async function main() {
  const response = await fetch("/api/data");
  const baseChecklistData = await response.json();
  const checklistData = [
    ...baseChecklistData,
    apiSecurityChecklist,
    mobileSecurityChecklist,
    cloudSecurityChecklist,
    secureCodeChecklist,
    owaspCheatSheetChecklist,
    threatModelingChecklist,
    businessLogicChecklist,
    supplyChainSecurityChecklist,
    loggingMonitoringChecklist
  ];

  const TABS = checklistData.map((category) => ({
    id: category.id,
    name: category.name,
    description: category.description,
    type: "checklist",
    payload: category
  }));

  TABS.push({
    id: "server-config",
    name: "Hardening & Infra",
    description: serverHardening.overview,
    type: "server",
    payload: serverHardening
  });

  TABS.push({
    id: "tools",
    name: "Playbook de Ferramentas",
    description: "Coleção curada de ferramentas para bug hunting, SAST/DAST e automações de resposta.",
    type: "tools",
    payload: securityTools
  });

  const tabListEl = document.getElementById("tab-list");
  const categoryContentEl = document.getElementById("category-content");
  const currentTabTitleEl = document.getElementById("current-tab-title");
  const currentTabDescriptionEl = document.getElementById("current-tab-description");
  const exportPdfBtn = document.getElementById("export-pdf");
  const exportPartialBtn = document.getElementById("export-partial");
  const resetBtn = document.getElementById("reset-state");
  const projectInput = document.getElementById("project-name");
  const testerInput = document.getElementById("tester-name");
  const auditWindowInput = document.getElementById("audit-window");
  const searchInput = document.getElementById("search-input");
  const statusFilterEl = document.getElementById("status-filter");
  const assigneeFilterEl = document.getElementById("assignee-filter");
  const stageFilterEl = document.getElementById("stage-filter");
  const clearFiltersBtn = document.getElementById("clear-filters");
  const modalEl = document.getElementById("guide-modal");
  const modalTitleEl = document.getElementById("modal-title");
  const modalDescriptionEl = document.getElementById("modal-description");
  const modalBodyContentEl = document.getElementById("modal-body-content");
  const modalCloseBtn = document.getElementById("close-modal");
  const notificationContainerEl = document.getElementById("notification-container");
  const itemTemplate = document.getElementById("checklist-item-template");

  const metricsEls = {
    total: document.querySelector('[data-metric="total-items"] .metric-value'),
    completed: document.querySelector('[data-metric="completed-items"] .metric-value'),
    failed: document.querySelector('[data-metric="failed-items"] .metric-value'),
    evidence: document.querySelector('[data-metric="evidence-count"] .metric-value')
  };

  const radialBarEl = document.querySelector(".radial-bar");
  const radialPercentEl = document.getElementById("radial-percent");
  const metricCompletedEl = document.getElementById("metric-completed");
  const metricFailedEl = document.getElementById("metric-failed");
  const metricNaEl = document.getElementById("metric-na");
  const metricPendingEl = document.getElementById("metric-pending");
  const categoryProgressEl = document.getElementById("category-progress");
  const workflowCounts = new Map(
    WORKFLOW_STEPS.map((step) => [step.id, document.querySelector(`[data-step-count="${step.id}"]`)] )
  );
  const insightRisksEl = document.getElementById("insight-top-risks");
  const insightGapsEl = document.getElementById("insight-gaps");
  const insightChainsEl = document.getElementById("insight-chains");

  const helpLinks = document.querySelectorAll(".help-links a[data-doc]");

  let state = await loadState();
  let activeSectionId = null;

  async function loadState() {
    try {
      const res = await fetch("/api/state");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const stored = await res.json();
      stored.items = stored.items || {};
      Object.keys(stored.items).forEach((key) => {
        stored.items[key] = normalizeItemState(stored.items[key]);
      });
      stored.meta = stored.meta || {};
      return stored;
    } catch (error) {
      console.warn("Falha ao carregar estado, iniciando com padrão.", error);
      return { items: {}, meta: {} };
    }
  }

  async function saveState(showToast = true) {
    try {
      const response = await fetch("/api/state", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(state)
      });
      if (!response.ok) throw new Error("Falha ao persistir estado");
      if (showToast) {
        showNotification("Progresso salvo.");
      }
    } catch (error) {
      console.error("Erro ao salvar estado", error);
      showNotification("Erro ao salvar o estado.", "error");
    }
  }

  function resetState() {
    if (!confirm("Deseja realmente apagar todos os dados salvos?")) return;
    state = { items: {}, meta: {} };
    projectInput.value = "";
    testerInput.value = "";
    auditWindowInput.value = "";
    renderUI();
    saveState(false);
    showNotification("Os dados foram resetados.");
  }

  function showNotification(message, type = "success") {
    const toast = document.createElement("div");
    toast.className = `notification ${type}`;
    toast.textContent = message;
    notificationContainerEl.appendChild(toast);
    requestAnimationFrame(() => {
      toast.classList.add("show");
    });
    setTimeout(() => {
      toast.classList.remove("show");
      toast.addEventListener("transitionend", () => toast.remove(), { once: true });
    }, 4000);
  }

  function getItemState(itemId) {
    if (!state.items[itemId]) {
      state.items[itemId] = normalizeItemState();
    }
    return state.items[itemId];
  }

  function updateItemState(itemId, updates) {
    const current = getItemState(itemId);
    const next = {
      ...current,
      ...updates,
      evidenceChecklist: updates.evidenceChecklist
        ? { ...current.evidenceChecklist, ...updates.evidenceChecklist }
        : current.evidenceChecklist
    };
    state.items[itemId] = next;
    scheduleDashboardRefresh();
    saveState(false);
  }

  function updateMeta() {
    state.meta = {
      project: projectInput.value,
      tester: testerInput.value,
      auditWindow: auditWindowInput.value
    };
    saveState(false);
  }

  function makeSectionId(categoryId, sectionId) {
    return `${categoryId}::${sectionId}`;
  }

  function makeItemId(categoryId, sectionId, itemId) {
    return `${categoryId}::${sectionId}::${itemId}`;
  }

  function getAllChecklistEntries() {
    const entries = [];
    TABS.forEach((tab) => {
      if (tab.type === "checklist") {
        tab.payload.sections.forEach((section) => {
          section.items.forEach((item) => {
            entries.push({
              categoryId: tab.id,
              categoryName: tab.name,
              sectionId: section.id,
              sectionTitle: section.title,
              item
            });
          });
        });
      } else if (tab.type === "server") {
        tab.payload.stacks.forEach((stack) => {
          stack.items.forEach((item) => {
            entries.push({
              categoryId: tab.id,
              categoryName: tab.name,
              sectionId: stack.id,
              sectionTitle: stack.name,
              item
            });
          });
        });
      }
    });
    return entries;
  }

  function renderNavigation() {
    tabListEl.innerHTML = "";
    const rootList = document.createElement("ul");

    TABS.forEach((tab) => {
      const tabLi = document.createElement("li");
      const tabBtn = document.createElement("button");
      tabBtn.className = "nav-category";
      tabBtn.textContent = tab.name;
      tabBtn.addEventListener("click", () => {
        const firstSectionId = getFirstSectionId(tab);
        if (firstSectionId) {
          activeSectionId = makeSectionId(tab.id, firstSectionId);
          renderUI();
        }
      });
      tabLi.appendChild(tabBtn);

      const sections = getSections(tab);
      if (sections.length > 0) {
        const subList = document.createElement("ul");
        subList.className = "nav-submenu";
        sections.forEach((section) => {
          const sectionLi = document.createElement("li");
          const sectionBtn = document.createElement("button");
          sectionBtn.className = "nav-link";
          sectionBtn.textContent = section.title || section.name;
          sectionBtn.dataset.id = makeSectionId(tab.id, section.id);
          if (sectionBtn.dataset.id === activeSectionId) {
            sectionBtn.setAttribute("aria-current", "true");
          }
          sectionBtn.addEventListener("click", () => {
            activeSectionId = sectionBtn.dataset.id;
            renderUI();
          });
          sectionLi.appendChild(sectionBtn);
          subList.appendChild(sectionLi);
        });
        tabLi.appendChild(subList);
      }

      rootList.appendChild(tabLi);
    });

    tabListEl.appendChild(rootList);
  }

  function getSections(tab) {
    if (tab.type === "checklist") {
      return tab.payload.sections || [];
    }
    if (tab.type === "server") {
      return tab.payload.stacks || [];
    }
    if (tab.type === "tools") {
      return [{ id: "all", title: "Ferramentas" }];
    }
    return [];
  }

  function getFirstSectionId(tab) {
    const sections = getSections(tab);
    return sections[0]?.id;
  }

  function renderContent() {
    if (!activeSectionId) {
      const firstTab = TABS[0];
      if (firstTab) {
        activeSectionId = makeSectionId(firstTab.id, getFirstSectionId(firstTab));
      }
    }

    if (!activeSectionId) {
      currentTabTitleEl.textContent = "Selecione um domínio";
      currentTabDescriptionEl.textContent = "Escolha uma categoria para iniciar sua rodada de testes.";
      categoryContentEl.innerHTML = '<p class="empty-state">Nenhum checklist carregado.</p>';
      return;
    }

    const [categoryId, sectionId] = activeSectionId.split("::");
    const tab = TABS.find((entry) => entry.id === categoryId);
    if (!tab) {
      categoryContentEl.innerHTML = '<p class="empty-state">Seção não encontrada.</p>';
      return;
    }

    if (tab.type === "checklist") {
      const section = tab.payload.sections.find((entry) => entry.id === sectionId);
      if (section) {
        currentTabTitleEl.textContent = section.title;
        currentTabDescriptionEl.textContent = section.summary;
        renderChecklistSection(tab, section);
      }
    } else if (tab.type === "server") {
      const stack = tab.payload.stacks.find((entry) => entry.id === sectionId);
      if (stack) {
        currentTabTitleEl.textContent = stack.name;
        currentTabDescriptionEl.textContent = stack.summary;
        renderServerSection(tab, stack);
      }
    } else if (tab.type === "tools") {
      currentTabTitleEl.textContent = tab.name;
      currentTabDescriptionEl.textContent = tab.description;
      renderToolsContent(tab.payload);
    }
  }

  function matchesFilters(itemState, item) {
    const searchTerm = searchInput.value.trim().toLowerCase();
    const statusValue = statusFilterEl.value;
    const assigneeValue = assigneeFilterEl.value;
    const stageValue = stageFilterEl.value;

    const matchesSearch =
      !searchTerm ||
      item.title.toLowerCase().includes(searchTerm) ||
      item.description.toLowerCase().includes(searchTerm);
    const matchesStatus = statusValue === "all" || itemState.status === statusValue;
    const matchesAssignee =
      assigneeValue === "all" ||
      (itemState.assignee || "").toLowerCase() === assigneeValue.toLowerCase();
    const matchesStage = stageValue === "all" || itemState.stage === stageValue;

    return matchesSearch && matchesStatus && matchesAssignee && matchesStage;
  }

  function renderChecklistSection(tab, section) {
    categoryContentEl.innerHTML = "";
    const itemsWrapper = document.createElement("div");
    itemsWrapper.className = "items-wrapper";

    const filteredItems = section.items.filter((item) => {
      const itemId = makeItemId(tab.id, section.id, item.id);
      const itemState = getItemState(itemId);
      return matchesFilters(itemState, item);
    });

    if (filteredItems.length === 0) {
      categoryContentEl.innerHTML = '<p class="empty-state">Nenhum item corresponde aos filtros aplicados.</p>';
      return;
    }

    filteredItems.forEach((item) => {
      const element = buildChecklistItem(tab.id, section, item);
      itemsWrapper.appendChild(element);
    });

    categoryContentEl.appendChild(itemsWrapper);
  }

  function renderServerSection(tab, stack) {
    categoryContentEl.innerHTML = "";
    const filteredItems = stack.items.filter((item) => {
      const itemId = makeItemId(tab.id, stack.id, item.id);
      const itemState = getItemState(itemId);
      return matchesFilters(itemState, item);
    });

    if (filteredItems.length === 0) {
      categoryContentEl.innerHTML = '<p class="empty-state">Nenhum item corresponde aos filtros aplicados.</p>';
      return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "items-wrapper";

    filteredItems.forEach((item) => {
      const element = buildChecklistItem(tab.id, stack, item);
      wrapper.appendChild(element);
    });

    categoryContentEl.appendChild(wrapper);
  }

  function renderToolsContent(tools) {
    categoryContentEl.innerHTML = "";
    const searchTerm = searchInput.value.trim().toLowerCase();
    const list = document.createElement("ul");
    list.className = "tools-list";

    const filtered = tools.filter((tool) => {
      const haystack = `${tool.name} ${tool.description} ${tool.category}`.toLowerCase();
      return haystack.includes(searchTerm);
    });

    if (filtered.length === 0) {
      categoryContentEl.innerHTML = '<p class="empty-state">Nenhuma ferramenta encontrada.</p>';
      return;
    }

    filtered.forEach((tool) => {
      const li = document.createElement("li");
      li.className = "tool-item";
      li.innerHTML = `
        <div class="tool-header">
          <h3>${tool.name}</h3>
          <span>${tool.category}</span>
        </div>
        <p>${tool.description}</p>
        ${tool.command ? `<pre>${tool.command}</pre>` : ""}
      `;
      list.appendChild(li);
    });

    categoryContentEl.appendChild(list);
  }

  function buildChecklistItem(categoryId, section, item) {
    const element = itemTemplate.content.firstElementChild.cloneNode(true);
    const checkbox = element.querySelector(".item-checkbox");
    const titleEl = element.querySelector(".item-title");
    const descriptionEl = element.querySelector(".item-description");
    const statusSelect = element.querySelector(".item-status");
    const severitySelect = element.querySelector(".item-severity");
    const stageSelect = element.querySelector(".item-stage");
    const assigneeInput = element.querySelector(".item-assignee");
    const prioritySelect = element.querySelector(".item-priority");
    const notesEl = element.querySelector(".item-notes");
    const evidenceNarrativeEl = element.querySelector(".item-evidence");
    const evidenceCheckboxes = element.querySelectorAll(".item-evidence-checkbox");
    const evidenceInput = element.querySelector(".item-evidence-input");
    const uploadBtn = element.querySelector(".item-upload-btn");
    const attachmentsList = element.querySelector(".item-attachments-list");
    const guideBtn = element.querySelector(".item-guide");
    const severityTag = element.querySelector(".tag.severity");
    const stageTag = element.querySelector(".tag.workflow");

    const itemId = makeItemId(categoryId, section.id, item.id);
    const itemState = getItemState(itemId);

    titleEl.textContent = item.title;
    descriptionEl.textContent = item.description;
    checkbox.checked = itemState.checked;
    statusSelect.value = itemState.status;
    severitySelect.value = itemState.severity;
    stageSelect.value = itemState.stage;
    assigneeInput.value = itemState.assignee;
    prioritySelect.value = itemState.priority;
    notesEl.value = itemState.notes;
    evidenceNarrativeEl.value = itemState.evidenceNarrative;
    updateSeverityTag();
    updateStageTag();
    renderAttachments();
    renderEvidenceChecklist();
    element.dataset.status = itemState.status || "";

    checkbox.addEventListener("change", () => {
      updateItemState(itemId, { checked: checkbox.checked });
      element.dataset.status = statusSelect.value;
      updateDashboardImmediate();
    });

    statusSelect.addEventListener("change", () => {
      updateItemState(itemId, { status: statusSelect.value });
      element.dataset.status = statusSelect.value;
      updateDashboardImmediate();
    });

    severitySelect.addEventListener("change", () => {
      updateItemState(itemId, { severity: severitySelect.value });
      updateSeverityTag();
      updateDashboardImmediate();
    });

    stageSelect.addEventListener("change", () => {
      updateItemState(itemId, { stage: stageSelect.value });
      updateStageTag();
      updateDashboardImmediate();
    });

    assigneeInput.addEventListener("input", () => {
      updateItemState(itemId, { assignee: assigneeInput.value });
      updateAssigneeFilterOptions();
      updateDashboardImmediate();
    });

    prioritySelect.addEventListener("change", () => {
      updateItemState(itemId, { priority: prioritySelect.value });
      updateDashboardImmediate();
    });

    notesEl.addEventListener("input", () => {
      updateItemState(itemId, { notes: notesEl.value });
    });

    evidenceNarrativeEl.addEventListener("input", () => {
      updateItemState(itemId, { evidenceNarrative: evidenceNarrativeEl.value });
    });

    evidenceCheckboxes.forEach((checkboxEl) => {
      checkboxEl.checked = Boolean(itemState.evidenceChecklist?.[checkboxEl.dataset.evidence]);
      checkboxEl.addEventListener("change", () => {
        updateItemState(itemId, {
          evidenceChecklist: {
            [checkboxEl.dataset.evidence]: checkboxEl.checked
          }
        });
      });
    });

    uploadBtn.addEventListener("click", async () => {
      const file = evidenceInput.files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("evidence", file);
      try {
        const response = await fetch("/api/upload", { method: "POST", body: formData });
        if (!response.ok) throw new Error("Upload falhou");
        const result = await response.json();
        const attachments = [...itemState.attachments, result.filePath];
        updateItemState(itemId, { attachments });
        evidenceInput.value = "";
        renderAttachments();
        showNotification("Arquivo anexado!");
      } catch (error) {
        console.error(error);
        showNotification("Falha no upload da evidência.", "error");
      }
    });

    guideBtn.addEventListener("click", () => {
      openGuideModal(item.title, item.description, item.guide || {});
    });

    function updateSeverityTag() {
      const severity = severitySelect.value;
      severityTag.dataset.severity = severity;
      const labels = {
        critical: "Gravidade crítica",
        high: "Gravidade alta",
        medium: "Gravidade média",
        low: "Gravidade baixa",
        info: "Informativa"
      };
      severityTag.textContent = labels[severity] || "Gravidade definida";
    }

    function updateStageTag() {
      stageTag.dataset.stage = stageSelect.value;
      stageTag.textContent = `Fase: ${WORKFLOW_STEPS.find((step) => step.id === stageSelect.value)?.label || stageSelect.value}`;
    }

    function renderAttachments() {
      attachmentsList.innerHTML = "";
      const currentState = getItemState(itemId);
      currentState.attachments.forEach((filePath) => {
        const li = document.createElement("li");
        const link = document.createElement("a");
        link.href = filePath;
        link.textContent = filePath.split("/").pop();
        link.target = "_blank";
        li.appendChild(link);
        attachmentsList.appendChild(li);
      });
    }

    function renderEvidenceChecklist() {
      const currentState = getItemState(itemId);
      evidenceCheckboxes.forEach((checkboxEl) => {
        checkboxEl.checked = Boolean(currentState.evidenceChecklist?.[checkboxEl.dataset.evidence]);
      });
    }

    return element;
  }

  function openGuideModal(title, description, guide = {}) {
    modalTitleEl.textContent = title;
    modalDescriptionEl.textContent = description || "";
    modalBodyContentEl.innerHTML = "";

    const sections = [
      { key: "overview", label: "Resumo técnico" },
      { key: "impact", label: "Impacto & riscos" },
      { key: "detection", label: "Como identificar" },
      { key: "tools", label: "Ferramentas" },
      { key: "commands", label: "Ferramentas/Comandos" },
      { key: "steps", label: "Passo a passo" },
      { key: "mitigation", label: "Mitigações recomendadas" },
      { key: "evidence", label: "Evidências sugeridas" },
      { key: "references", label: "Referências" }
    ];

    sections.forEach((section) => {
      const value = guide?.[section.key];
      if (!value || (Array.isArray(value) && value.length === 0)) return;

      const wrapper = document.createElement("div");
      wrapper.className = "modal-section";
      const heading = document.createElement("h4");
      heading.textContent = section.label;
      wrapper.appendChild(heading);

      if (Array.isArray(value)) {
        if (section.key === "commands") {
          value.forEach((command) => {
            const pre = document.createElement("pre");
            pre.textContent = command;
            wrapper.appendChild(pre);
          });
        } else if (section.key === "references") {
          const list = document.createElement("ul");
          value.forEach((entry) => {
            const url = getReferenceUrl(entry);
            const li = document.createElement("li");
            if (url) {
              const link = document.createElement("a");
              link.href = url;
              link.target = "_blank";
              link.rel = "noopener noreferrer";
              link.className = "reference-link";
              link.innerHTML = `${entry} <span class="external-icon">↗</span>`;
              li.appendChild(link);
            } else {
              li.textContent = entry;
            }
            list.appendChild(li);
          });
          wrapper.appendChild(list);
        } else {
          const list = document.createElement("ul");
          value.forEach((entry) => {
            const li = document.createElement("li");
            li.textContent = entry;
            list.appendChild(li);
          });
          wrapper.appendChild(list);
        }
      } else {
        const paragraph = document.createElement("p");
        paragraph.textContent = value;
        wrapper.appendChild(paragraph);
      }

      modalBodyContentEl.appendChild(wrapper);
    });

    modalEl.classList.remove("hidden");
  }

  function openInternalDoc(docKey) {
    const doc = INTERNAL_DOCS[docKey];
    if (!doc) return;
    modalTitleEl.textContent = doc.title;
    modalDescriptionEl.textContent = doc.description;
    modalBodyContentEl.innerHTML = "";
    const bodySection = document.createElement("div");
    bodySection.className = "modal-section";
    const list = document.createElement("ul");
    doc.body.forEach((line) => {
      const li = document.createElement("li");
      li.textContent = line;
      list.appendChild(li);
    });
    bodySection.appendChild(list);
    modalBodyContentEl.appendChild(bodySection);
    modalEl.classList.remove("hidden");
  }

  function closeModal() {
    modalEl.classList.add("hidden");
  }

  let dashboardUpdateQueued = false;
  function scheduleDashboardRefresh() {
    if (dashboardUpdateQueued) return;
    dashboardUpdateQueued = true;
    requestAnimationFrame(() => {
      dashboardUpdateQueued = false;
      updateDashboardImmediate();
    });
  }

  function updateDashboardImmediate() {
    renderMetrics();
    renderWorkflowCounters();
    updateAssigneeFilterOptions();
    renderInsights();
  }

  function renderMetrics() {
    const entries = getAllChecklistEntries();
    const totals = {
      total: 0,
      completed: 0,
      failed: 0,
      na: 0,
      pending: 0,
      evidence: 0
    };
    const progressByCategory = new Map();

    entries.forEach((entry) => {
      const itemId = makeItemId(entry.categoryId, entry.sectionId, entry.item.id);
      const itemState = getItemState(itemId);
      totals.total += 1;
      if (itemState.checked) totals.completed += 1;
      if (itemState.status === "failed") totals.failed += 1;
      if (itemState.status === "na") totals.na += 1;
      if (!itemState.status) totals.pending += 1;
      totals.evidence += itemState.attachments.length;

      const key = entry.categoryName;
      if (!progressByCategory.has(key)) {
        progressByCategory.set(key, { total: 0, completed: 0 });
      }
      const bucket = progressByCategory.get(key);
      bucket.total += 1;
      if (itemState.checked) bucket.completed += 1;
    });

    metricsEls.total.textContent = totals.total;
    metricsEls.completed.textContent = totals.completed;
    metricsEls.failed.textContent = totals.failed;
    metricsEls.evidence.textContent = totals.evidence;

    const percent = totals.total === 0 ? 0 : Math.round((totals.completed / totals.total) * 100);
    const dashArray = `${percent} ${100 - percent}`;
    radialBarEl.setAttribute("stroke-dasharray", dashArray);
    radialPercentEl.textContent = `${percent}%`;
    metricCompletedEl.textContent = totals.completed;
    metricFailedEl.textContent = totals.failed;
    metricNaEl.textContent = totals.na;
    metricPendingEl.textContent = totals.pending;

    categoryProgressEl.innerHTML = "";
    Array.from(progressByCategory.entries()).forEach(([categoryName, stats]) => {
      const row = document.createElement("div");
      row.className = "progress-row";
      row.innerHTML = `
        <header>
          <span>${categoryName}</span>
          <span>${stats.completed}/${stats.total}</span>
        </header>
        <div class="progress-bar"><span style="width: ${
          stats.total === 0 ? 0 : Math.round((stats.completed / stats.total) * 100)
        }%"></span></div>
      `;
      categoryProgressEl.appendChild(row);
    });
  }

  function renderWorkflowCounters() {
    const counters = new Map(WORKFLOW_STEPS.map((step) => [step.id, 0]));
    getAllChecklistEntries().forEach((entry) => {
      const state = getItemState(makeItemId(entry.categoryId, entry.sectionId, entry.item.id));
      counters.set(state.stage, (counters.get(state.stage) || 0) + 1);
    });
    counters.forEach((value, stepId) => {
      const el = workflowCounts.get(stepId);
      if (el) {
        el.textContent = `${value} itens`;
      }
    });
  }

  function updateAssigneeFilterOptions() {
    const existing = new Set(["all"]);
    getAllChecklistEntries().forEach((entry) => {
      const state = getItemState(makeItemId(entry.categoryId, entry.sectionId, entry.item.id));
      if (state.assignee) {
        existing.add(state.assignee.trim());
      }
    });

    const currentOptions = new Set(Array.from(assigneeFilterEl.options).map((opt) => opt.value));
    if (existing.size === currentOptions.size && [...existing].every((value) => currentOptions.has(value))) {
      return;
    }

    const currentValue = assigneeFilterEl.value;
    assigneeFilterEl.innerHTML = "";
    existing.forEach((assignee) => {
      const option = document.createElement("option");
      option.value = assignee;
      option.textContent = assignee === "all" ? "Todos" : assignee;
      assigneeFilterEl.appendChild(option);
    });
    if (existing.has(currentValue)) {
      assigneeFilterEl.value = currentValue;
    }
  }

  function renderInsights() {
    const entries = getAllChecklistEntries();
    const severityWeight = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const failedFindings = entries
      .map((entry) => {
        const state = getItemState(makeItemId(entry.categoryId, entry.sectionId, entry.item.id));
        return { entry, state };
      })
      .filter(({ state }) => state.status === "failed");

    if (failedFindings.length === 0) {
      insightRisksEl.textContent = "Nenhuma falha registrada até o momento.";
    } else {
      const sorted = failedFindings
        .sort((a, b) => (severityWeight[b.state.severity] || 0) - (severityWeight[a.state.severity] || 0))
        .slice(0, 3)
        .map(({ entry, state }) => `${entry.sectionTitle}: ${entry.item.title} (${state.severity.toUpperCase()})`);
      insightRisksEl.innerHTML = sorted.join("<br/>");
    }

    const sectionsWithPending = new Map();
    entries.forEach((entry) => {
      const state = getItemState(makeItemId(entry.categoryId, entry.sectionId, entry.item.id));
      if (!state.checked) {
        const key = `${entry.categoryName} / ${entry.sectionTitle}`;
        sectionsWithPending.set(key, (sectionsWithPending.get(key) || 0) + 1);
      }
    });
    if (sectionsWithPending.size === 0) {
      insightGapsEl.textContent = "Todas as seções estão com cobertura satisfatória.";
    } else {
      const topGaps = Array.from(sectionsWithPending.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([section, qty]) => `${section} – ${qty} itens pendentes`);
      insightGapsEl.innerHTML = topGaps.join("<br/>");
    }

    const chainCandidates = failedFindings
      .filter(({ state }) => ["critical", "high"].includes(state.severity))
      .map(({ entry, state }) => `Combine ${entry.item.title} (${state.severity}) com vetores adjacentes em ${entry.sectionTitle}`);
    if (chainCandidates.length === 0) {
      insightChainsEl.textContent = "Sem chains críticas. Continue correlacionando achados entre camadas.";
    } else {
      insightChainsEl.innerHTML = chainCandidates.slice(0, 2).join("<br/>");
    }
  }

  function buildReportContext(filteredEntries = null) {
    const entries = filteredEntries || getAllChecklistEntries();
    const grouped = new Map();
    entries.forEach((entry) => {
      const key = `${entry.categoryName}||${entry.sectionTitle}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key).push(entry);
    });

    const sections = Array.from(grouped.entries()).map(([key, items]) => {
      const [categoryName, sectionTitle] = key.split("||");
      const records = items.map((entry) => {
        const itemId = makeItemId(entry.categoryId, entry.sectionId, entry.item.id);
        const state = getItemState(itemId);
        return {
          title: entry.item.title,
          description: entry.item.description,
          status: state.status,
          checked: state.checked,
          notes: state.notes,
          severity: state.severity,
          stage: state.stage,
          priority: state.priority,
          assignee: state.assignee,
          evidenceNarrative: state.evidenceNarrative,
          attachments: state.attachments,
          evidenceChecklist: state.evidenceChecklist
        };
      });
      return { categoryName, sectionTitle, records };
    });

    const metadata = {
      project: projectInput.value || "Projeto sem nome",
      tester: testerInput.value || "Tester",
      auditWindow: auditWindowInput.value || "",
      generatedAt: new Date()
    };

    return { metadata, sections };
  }

  function exportFullReport() {
    const context = buildReportContext();
    const html = generateFullReport(context, WORKFLOW_STEPS);
    openReportWindow(html);
  }

  function exportPartialReport() {
    const [categoryId, sectionId] = (activeSectionId || "::").split("::");
    const tab = TABS.find((entry) => entry.id === categoryId);
    if (!tab) {
      showNotification("Selecione uma seção para exportar.", "error");
      return;
    }

    const filteredEntries = getAllChecklistEntries().filter((entry) => {
      if (entry.categoryId !== categoryId || entry.sectionId !== sectionId) return false;
      const itemId = makeItemId(entry.categoryId, entry.sectionId, entry.item.id);
      const state = getItemState(itemId);
      return matchesFilters(state, entry.item);
    });

    if (filteredEntries.length === 0) {
      showNotification("Nenhum item corresponde aos filtros atuais.", "error");
      return;
    }

    const context = buildReportContext(filteredEntries);
    const html = generatePartialReport(context, WORKFLOW_STEPS, {
      category: tab.name,
      section: filteredEntries[0]?.sectionTitle || "Seção"
    });
    openReportWindow(html);
  }

  function openReportWindow(html) {
    const reportWindow = window.open("", "_blank");
    if (!reportWindow) {
      alert("Permita pop-ups para gerar o relatório.");
      return;
    }
    reportWindow.document.write(html);
    reportWindow.document.close();
    reportWindow.focus();
    setTimeout(() => reportWindow.print(), 800);
  }

  function renderUI() {
    renderNavigation();
    renderContent();
    updateDashboardImmediate();
  }

  projectInput.addEventListener("input", updateMeta);
  testerInput.addEventListener("input", updateMeta);
  auditWindowInput.addEventListener("input", updateMeta);
  searchInput.addEventListener("input", () => {
    renderContent();
  });
  statusFilterEl.addEventListener("change", () => {
    renderContent();
  });
  assigneeFilterEl.addEventListener("change", () => {
    renderContent();
  });
  stageFilterEl.addEventListener("change", () => {
    renderContent();
  });
  clearFiltersBtn.addEventListener("click", () => {
    searchInput.value = "";
    statusFilterEl.value = "all";
    assigneeFilterEl.value = "all";
    stageFilterEl.value = "all";
    renderContent();
  });

  exportPdfBtn.addEventListener("click", exportFullReport);
  exportPartialBtn.addEventListener("click", exportPartialReport);
  resetBtn.addEventListener("click", resetState);
  modalCloseBtn.addEventListener("click", closeModal);
  modalEl.addEventListener("click", (event) => {
    if (event.target === modalEl) closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modalEl.classList.contains("hidden")) closeModal();
  });

  helpLinks.forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      const doc = event.currentTarget.getAttribute("data-doc");
      openInternalDoc(doc);
    });
  });

  projectInput.value = state.meta?.project || "";
  testerInput.value = state.meta?.tester || "";
  auditWindowInput.value = state.meta?.auditWindow || "";

  const firstTab = TABS[0];
  if (firstTab) {
    activeSectionId = makeSectionId(firstTab.id, getFirstSectionId(firstTab));
  }

  renderUI();
  updateAssigneeFilterOptions();
}
