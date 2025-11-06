import { checklistData as originalChecklistData } from "./data.mjs";
import { securityTools } from "./securityTools.mjs";
import { serverHardening } from "./serverConfig.mjs";
import { cloudSecurityChecklist } from "./cloudSecurity.mjs";
import { secureCodeChecklist } from "./secureCodeChecklist.mjs";
import { owaspCheatSheetChecklist } from "./owaspCheatSheetChecklist.mjs";
import { calculateProgress, renderStatusBadge } from "./src/logic.js";

const checklistData = [...originalChecklistData, cloudSecurityChecklist, secureCodeChecklist, owaspCheatSheetChecklist];

(() => {
  const TABS = checklistData.map((category) => ({
    id: category.id,
    name: category.name,
    description: category.description,
    type: "checklist",
    payload: category
  }));

  TABS.push({
    id: "server-config",
    name: "Server Config",
    description: serverHardening.overview,
    type: "server",
    payload: serverHardening
  });

  const stateKey = "appsec-dashboard-state-v1";
  const tabListEl = document.getElementById("tab-list");
  const categoryContentEl = document.getElementById("category-content");
  const currentTabTitleEl = document.getElementById("current-tab-title");
  const currentTabDescriptionEl = document.getElementById("current-tab-description");
  const exportPdfBtn = document.getElementById("export-pdf");
  const resetBtn = document.getElementById("reset-state");
  const projectInput = document.getElementById("project-name");
  const testerInput = document.getElementById("tester-name");
  const toolListEl = document.getElementById("tool-list");
  const modalEl = document.getElementById("guide-modal");
  const modalTitleEl = document.getElementById("modal-title");
  const modalDescriptionEl = document.getElementById("modal-description");
  const modalBodyContentEl = document.getElementById("modal-body-content");
  const modalCloseBtn = document.getElementById("close-modal");

  const cardTemplate = document.getElementById("checklist-card-template");
  const itemTemplate = document.getElementById("checklist-item-template");

  let state = loadState();

  function loadState() {
    try {
      const raw = localStorage.getItem(stateKey);
      return raw ? JSON.parse(raw) : { items: {}, meta: {} };
    } catch (error) {
      console.error("Falha ao carregar estado, usando padrão.", error);
      alert("Erro ao carregar dados salvos. Suas alterações não serão recuperadas.");
      return { items: {}, meta: {} };
    }
  }

  function saveState() {
    try {
      localStorage.setItem(stateKey, JSON.stringify(state));
    } catch (error) {
      console.error("Não foi possível salvar o estado local.", error);
      if (error.name === 'QuotaExceededError') {
        alert("Erro: Não foi possível salvar. O armazenamento local está cheio.");
      } else {
        alert("Erro desconhecido ao salvar o estado.");
      }
    }
  }

  function resetState() {
    state = { items: {}, meta: {} };
    projectInput.value = "";
    testerInput.value = "";
    renderActiveTab(activeTabId);
    saveState();
  }

  function getItemState(itemId) {
    if (!state.items[itemId]) {
      state.items[itemId] = { checked: false, status: "", notes: "" };
    }
    return state.items[itemId];
  }

  function updateItemState(itemId, updates) {
    state.items[itemId] = { ...getItemState(itemId), ...updates };
    saveState();
  }

  function renderTabs() {
    tabListEl.innerHTML = "";
    TABS.forEach((tab) => {
      const button = document.createElement("button");
      button.className = "tab-button";
      button.textContent = tab.name;
      button.dataset.tab = tab.id;
      if (tab.id === activeTabId) {
        button.classList.add("active");
      }
      button.addEventListener("click", () => {
        activeTabId = tab.id;
        renderActiveTab(activeTabId);
        renderTabs();
      });
      tabListEl.appendChild(button);
    });
  }

  function renderTools() {
    if (!Array.isArray(securityTools) || securityTools.length === 0) {
      toolListEl.innerHTML = '<li class="empty-state">Sem ferramentas cadastradas.</li>';
      return;
    }
    toolListEl.innerHTML = "";
    securityTools.forEach((tool) => {
      const li = document.createElement("li");
      li.innerHTML = `<strong>${tool.name}</strong> · <span>${tool.category}</span><br/><span>${tool.description}</span>`;
      toolListEl.appendChild(li);
    });
  }

  function renderActiveTab(tabId) {
    const tab = TABS.find((entry) => entry.id === tabId);
    if (!tab) {
      currentTabTitleEl.textContent = "Selecione uma aba";
      currentTabDescriptionEl.textContent = "Escolha um domínio de segurança para iniciar a avaliação.";
      categoryContentEl.innerHTML = "";
      return;
    }

    currentTabTitleEl.textContent = tab.name;
    currentTabDescriptionEl.textContent = tab.description;

    if (tab.type === "checklist") {
      renderChecklist(tab.payload);
    } else if (tab.type === "server") {
      renderServerHardening(tab.payload);
    }
  }

  function renderChecklist(category) {
    categoryContentEl.innerHTML = "";

    if (!category.sections || category.sections.length === 0) {
      categoryContentEl.innerHTML = '<p class="empty-state">Nenhum item cadastrado ainda.</p>';
      return;
    }

    category.sections.forEach((section) => {
      const card = cardTemplate.content.firstElementChild.cloneNode(true);
      const cardTitle = card.querySelector(".card-title");
      const cardSummary = card.querySelector(".card-summary");
      const progressLabel = card.querySelector(".progress-label");
      const progressValue = card.querySelector(".progress-value");
      const cardBody = card.querySelector(".card-body");

      cardTitle.textContent = section.title;
      cardSummary.textContent = section.summary;

      cardBody.innerHTML = "";

      const itemStates = section.items.map((item) => getItemState(makeItemId(category.id, section.id, item.id)));
      const progress = calculateProgress(itemStates);
      progressLabel.textContent = `${progress.completed}/${progress.total} completos`;
      progressValue.style.width = `${progress.percent}%`;

      section.items.forEach((item) => {
        const element = buildItem(item, { categoryId: category.id, sectionId: section.id });
        cardBody.appendChild(element);
      });

      categoryContentEl.appendChild(card);
    });
  }

  function renderServerHardening(payload) {
    categoryContentEl.innerHTML = "";
    if (!payload.stacks || payload.stacks.length === 0) {
      categoryContentEl.innerHTML = '<p class="empty-state">Nenhum checklist configurado.</p>';
      return;
    }

    payload.stacks.forEach((stack) => {
      const card = cardTemplate.content.firstElementChild.cloneNode(true);
      const cardTitle = card.querySelector(".card-title");
      const cardSummary = card.querySelector(".card-summary");
      const progressLabel = card.querySelector(".progress-label");
      const progressValue = card.querySelector(".progress-value");
      const cardBody = card.querySelector(".card-body");

      cardTitle.textContent = stack.name;
      cardSummary.textContent = stack.summary;

      const itemStates = stack.items.map((item) => getItemState(makeItemId(payload.id || "server", stack.id, item.id)));
      const progress = calculateProgress(itemStates);
      progressLabel.textContent = `${progress.completed}/${progress.total} completos`;
      progressValue.style.width = `${progress.percent}%`;

      cardBody.innerHTML = "";
      stack.items.forEach((item) => {
        const element = buildItem(item, { categoryId: "server-config", sectionId: stack.id, stackName: stack.name });
        cardBody.appendChild(element);
      });

      categoryContentEl.appendChild(card);
    });
  }

  function buildItem(item, { categoryId, sectionId, stackName }) {
    const element = itemTemplate.content.firstElementChild.cloneNode(true);
    const checkbox = element.querySelector(".item-checkbox");
    const titleEl = element.querySelector(".item-title");
    const descriptionEl = element.querySelector(".item-description");
    const statusSelect = element.querySelector(".item-status");
    const notesEl = element.querySelector(".item-notes");
    const guideBtn = element.querySelector(".item-guide");

    const itemId = makeItemId(categoryId, sectionId, item.id);
    const itemState = getItemState(itemId);

    titleEl.textContent = item.title;
    descriptionEl.textContent = item.description;
    checkbox.checked = itemState.checked;
    statusSelect.value = itemState.status || "";
    notesEl.value = itemState.notes || "";

    checkbox.addEventListener("change", () => {
      updateItemState(itemId, { checked: checkbox.checked });
      refreshProgressBars();
    });

    statusSelect.addEventListener("change", () => {
      updateItemState(itemId, { status: statusSelect.value });
    });

    notesEl.addEventListener("input", (event) => {
      updateItemState(itemId, { notes: event.target.value });
    });

    guideBtn.addEventListener("click", () => {
      openGuideModal(
        item.title,
        item.description,
        item.guide || {
          overview: item.notes,
          commands: item.verification,
          tools: [stackName],
          steps: [
            "Documente evidências (logs, screenshots) para cada configuração aplicada."
          ],
          references: ["CIS Benchmarks", "OWASP Server Security"]
        }
      );
    });

    return element;
  }

  function openGuideModal(title, description, guide = {}) {
    modalTitleEl.textContent = title;
    modalDescriptionEl.textContent = description || "";
    modalBodyContentEl.innerHTML = "";

    const sections = [
      { key: "overview", label: "Resumo técnico" },
      { key: "impact", label: "Impacto e riscos" },
      { key: "detection", label: "Como identificar" },
      { key: "tools", label: "Ferramentas" },
      { key: "commands", label: "Comandos" },
      { key: "steps", label: "Passo a passo" },
      { key: "mitigation", label: "Mitigações recomendadas" },
      { key: "evidence", label: "Evidências sugeridas" },
      { key: "references", label: "Referências" }
    ];

    sections.forEach((section) => {
      const value = guide?.[section.key];
      if (!value || (Array.isArray(value) && value.length === 0)) {
        return;
      }

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

  function closeModal() {
    modalEl.classList.add("hidden");
  }

  function makeItemId(categoryId, sectionId, itemId) {
    return `${categoryId}::${sectionId}::${itemId}`;
  }

  function refreshProgressBars() {
    // Re-render the active tab to update progress indicators
    renderActiveTab(activeTabId);
  }

  function exportToPdf() {
    const projectName = projectInput.value || "Projeto sem nome";
    const testerName = testerInput.value || "Tester";
    const reportWindow = window.open("", "_blank");

    if (!reportWindow) {
      alert("Permita pop-ups para gerar o relatório.");
      return;
    }

    const sectionsHtml = buildReportSections();

    reportWindow.document.write(`
      <html>
        <head>
          <meta charset="utf-8" />
          <title>Relatório AppSec – ${escapeHtml(projectName)}</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 2rem; color: #111; }
            h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
            h2 { margin-top: 2rem; border-bottom: 2px solid #111; padding-bottom: 0.25rem; }
            h3 { margin-top: 1.5rem; color: #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
            th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; vertical-align: top; }
            th { background: #f2f2f2; }
            .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 999px; font-size: 0.75rem; }
            .badge-passed { background: #dcfce7; color: #166534; }
            .badge-failed { background: #fee2e2; color: #991b1b; }
            .badge-na { background: #e0f2fe; color: #0369a1; }
            .badge-empty { background: #e5e7eb; color: #374151; }
            .notes { white-space: pre-wrap; }
            footer { margin-top: 3rem; font-size: 0.85rem; color: #555; }
          </style>
        </head>
        <body>
          <h1>Relatório AppSec</h1>
          <p><strong>Projeto:</strong> ${escapeHtml(projectName)}<br/>
          <strong>Tester:</strong> ${escapeHtml(testerName)}<br/>
          <strong>Data:</strong> ${new Date().toLocaleString()}</p>
          ${sectionsHtml}
          <footer>Gerado automaticamente pelo OWASP AppSec Checklist Dashboard.</footer>
        </body>
      </html>
    `);
    reportWindow.document.close();
    reportWindow.focus();
    setTimeout(() => reportWindow.print(), 500);
  }

  function buildReportSections() {
    const sections = [];

    checklistData.forEach((category) => {
      sections.push(`<h2>${escapeHtml(category.name)}</h2>`);
      category.sections.forEach((section) => {
        sections.push(`<h3>${escapeHtml(section.title)}</h3>`);
        sections.push(buildItemsTable(category.id, section.id, section.items));
      });
    });

    sections.push(`<h2>Server Config</h2>`);
    serverHardening.stacks.forEach((stack) => {
      sections.push(`<h3>${escapeHtml(stack.name)}</h3>`);
      sections.push(buildItemsTable("server-config", stack.id, stack.items));
    });

    return sections.join("\n");
  }

  function buildItemsTable(categoryId, sectionId, items) {
    const rows = items
      .map((item) => {
        const itemId = makeItemId(categoryId, sectionId, item.id);
        const itemState = getItemState(itemId);
        const statusBadge = renderStatusBadge(itemState.status);
        return `
          <tr>
            <td>${escapeHtml(item.title)}</td>
            <td>${statusBadge}</td>
            <td>${itemState.checked ? "✔️" : ""}</td>
            <td class="notes">${escapeHtml(itemState.notes || "")}</td>
          </tr>
        `;
      })
      .join("\n");

    return `
      <table>
        <thead>
          <tr>
            <th>Item</th>
            <th>Status</th>
            <th>Concluído</th>
            <th>Notas / Evidências</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    `;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function restoreMeta() {
    if (state.meta) {
      projectInput.value = state.meta.project || "";
      testerInput.value = state.meta.tester || "";
    }
  }

  function persistMeta() {
    state.meta = {
      project: projectInput.value,
      tester: testerInput.value
    };
    saveState();
  }

  projectInput.addEventListener("input", persistMeta);
  testerInput.addEventListener("input", persistMeta);

  exportPdfBtn.addEventListener("click", exportToPdf);
  resetBtn.addEventListener("click", () => {
    if (confirm("Deseja realmente apagar todos os dados salvos?")) {
      resetState();
    }
  });

  modalCloseBtn.addEventListener("click", closeModal);
  modalEl.addEventListener("click", (event) => {
    if (event.target === modalEl) {
      closeModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modalEl.classList.contains("hidden")) {
      closeModal();
    }
  });

  let activeTabId = TABS[0]?.id;
  restoreMeta();
  renderTabs();
  renderTools();
  renderActiveTab(activeTabId);
})();
