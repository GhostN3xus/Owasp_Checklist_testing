import { securityTools } from "./securityTools.mjs";
import { serverHardening } from "./serverConfig.mjs";
import { cloudSecurityChecklist } from "./cloudSecurity.mjs";
import { secureCodeChecklist } from "./secureCodeChecklist.mjs";
import { owaspCheatSheetChecklist } from "./owaspCheatSheetChecklist.mjs";
import { renderStatusBadge } from "./logic.js";
import { getReferenceUrl, hasDocumentationLink } from "./documentationLinks.mjs";

async function main() {
  const response = await fetch('/api/data');
  const originalChecklistData = await response.json();
  const checklistData = [...originalChecklistData, cloudSecurityChecklist, secureCodeChecklist, owaspCheatSheetChecklist];

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

  TABS.push({
    id: "tools",
    name: "Tools",
    description: "Uma lista de ferramentas de segurança e testes.",
    type: "tools",
    payload: securityTools
  });

  const sidebarNavEl = document.getElementById("tab-list");
  const categoryContentEl = document.getElementById("category-content");
  const currentTabTitleEl = document.getElementById("current-tab-title");
  const currentTabDescriptionEl = document.getElementById("current-tab-description");
  const exportPdfBtn = document.getElementById("export-pdf");
  const resetBtn = document.getElementById("reset-state");
  const projectInput = document.getElementById("project-name");
  const testerInput = document.getElementById("tester-name");
  const searchInput = document.getElementById("search-input");
  const statusFilterEl = document.getElementById("status-filter");
  const modalEl = document.getElementById("guide-modal");
  const modalTitleEl = document.getElementById("modal-title");
  const modalDescriptionEl = document.getElementById("modal-description");
  const modalBodyContentEl = document.getElementById("modal-body-content");
  const modalCloseBtn = document.getElementById("close-modal");
  const notificationContainerEl = document.getElementById("notification-container");

  const itemTemplate = document.getElementById("checklist-item-template");

  let state = await loadState();
  let activeItemId = null;

  async function loadState() {
    try {
      const response = await fetch('/api/state');
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error("Falha ao carregar estado.", error);
      return { items: {}, meta: {} };
    }
  }

  async function saveState() {
    try {
      const response = await fetch('/api/state', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state),
      });
      if (response.ok) {
        showNotification("Progresso salvo com sucesso!");
      } else {
        throw new Error("Falha ao salvar o estado.");
      }
    } catch (error) {
      console.error("Não foi possível salvar o estado no servidor.", error);
      showNotification("Erro ao salvar o estado.", "error");
    }
  }

  function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notificationContainerEl.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
      notification.classList.remove('show');
      notification.addEventListener('transitionend', () => notification.remove());
    }, 4000);
  }

  function resetState() {
    state = { items: {}, meta: {} };
    projectInput.value = "";
    testerInput.value = "";
    renderContent();
    saveState();
    showNotification("Os dados foram resetados.", "success");
  }

  function getItemState(itemId) {
    if (!state.items[itemId]) {
      state.items[itemId] = { checked: false, status: "", notes: "", attachments: [] };
    }
    if (!Array.isArray(state.items[itemId].attachments)) {
      state.items[itemId].attachments = [];
    }
    return state.items[itemId];
  }

  function updateItemState(itemId, updates) {
    state.items[itemId] = { ...getItemState(itemId), ...updates };
    saveState();
  }

  function renderNavigation() {
    sidebarNavEl.innerHTML = "";
    const navUl = document.createElement("ul");

    TABS.forEach((category) => {
      const categoryLi = document.createElement("li");
      const categoryButton = document.createElement("button");
      categoryButton.className = "nav-category";
      categoryButton.textContent = category.name;
      categoryLi.appendChild(categoryButton);

      let sections = [];
      if (category.type === "checklist") sections = category.payload.sections || [];
      else if (category.type === "server") sections = category.payload.stacks || [];
      else if (category.type === "tools") sections = [{ id: "all", title: "Todas as Ferramentas" }];

      if (sections.length > 0) {
        const subList = document.createElement("ul");
        subList.className = "nav-submenu";
        sections.forEach((section) => {
          const sectionLi = document.createElement("li");
          const sectionButton = document.createElement("button");
          sectionButton.className = "nav-link";
          sectionButton.textContent = section.title || section.name;
          sectionButton.dataset.id = makeSectionId(category.id, section.id);

          if (sectionButton.dataset.id === activeItemId) {
            sectionButton.setAttribute("aria-current", "true");
          }

          sectionButton.addEventListener("click", (e) => {
            e.preventDefault();
            activeItemId = e.currentTarget.dataset.id;
            renderUI();
          });

          sectionLi.appendChild(sectionButton);
          subList.appendChild(sectionLi);
        });
        categoryLi.appendChild(subList);
      }
      navUl.appendChild(categoryLi);
    });
    sidebarNavEl.appendChild(navUl);
  }

  function renderContent() {
    if (!activeItemId) {
      currentTabTitleEl.textContent = "Selecione uma categoria";
      currentTabDescriptionEl.textContent = "Escolha um tópico na barra de navegação para começar.";
      categoryContentEl.innerHTML = '<p class="empty-state">Bem-vindo ao AppSec Dashboard!</p>';
      return;
    }

    const [categoryId, sectionId] = activeItemId.split("::");
    const category = TABS.find((tab) => tab.id === categoryId);
    if (!category) return;

    if (category.type === "checklist") {
      const section = category.payload.sections.find((s) => s.id === sectionId);
      if (section) renderChecklistContent(section, category.payload.id);
    } else if (category.type === "server") {
      const stack = category.payload.stacks.find((s) => s.id === sectionId);
      if (stack) renderServerContent(stack, category.payload.id);
    } else if (category.type === "tools") {
      renderToolsContent(category.payload);
    }
  }

    function renderChecklistContent(section, categoryId) {
        const searchTerm = searchInput.value.toLowerCase();
        const statusFilter = statusFilterEl.value;
        currentTabTitleEl.textContent = section.title;
        currentTabDescriptionEl.textContent = section.summary;

        const filteredItems = section.items.filter(item => {
            const itemState = getItemState(makeItemId(categoryId, section.id, item.id));
            const matchesSearch = item.title.toLowerCase().includes(searchTerm) || item.description.toLowerCase().includes(searchTerm);
            const matchesStatus = statusFilter === "all" || itemState.status === statusFilter;
            return matchesSearch && matchesStatus;
        });

        if (filteredItems.length === 0) {
            categoryContentEl.innerHTML = '<p class="empty-state">Nenhum item corresponde aos filtros.</p>';
            return;
        }

        const itemsContainer = document.createElement('div');
        itemsContainer.className = 'items-container';
        filteredItems.forEach(item => {
            itemsContainer.appendChild(buildItem(item, { categoryId, sectionId: section.id }));
        });
        categoryContentEl.innerHTML = '';
        categoryContentEl.appendChild(itemsContainer);
    }

    function renderServerContent(stack, categoryId) {
        const searchTerm = searchInput.value.toLowerCase();
        const statusFilter = statusFilterEl.value;
        currentTabTitleEl.textContent = stack.name;
        currentTabDescriptionEl.textContent = stack.summary;

        const filteredItems = stack.items.filter(item => {
            const itemState = getItemState(makeItemId(categoryId, stack.id, item.id));
            const matchesSearch = item.title.toLowerCase().includes(searchTerm) || item.description.toLowerCase().includes(searchTerm);
            const matchesStatus = statusFilter === "all" || itemState.status === statusFilter;
            return matchesSearch && matchesStatus;
        });

        if (filteredItems.length === 0) {
            categoryContentEl.innerHTML = '<p class="empty-state">Nenhum item corresponde aos filtros.</p>';
            return;
        }

        const itemsContainer = document.createElement('div');
        itemsContainer.className = 'items-container';
        filteredItems.forEach(item => {
            itemsContainer.appendChild(buildItem(item, { categoryId, sectionId: stack.id, stackName: stack.name }));
        });
        categoryContentEl.innerHTML = '';
        categoryContentEl.appendChild(itemsContainer);
    }

    function renderToolsContent(tools) {
        currentTabTitleEl.textContent = "Ferramentas de Pentest";
        currentTabDescriptionEl.textContent = "Uma lista de ferramentas úteis para testes de segurança.";
        const searchTerm = searchInput.value.toLowerCase();

        const filteredTools = tools.filter(tool =>
            tool.name.toLowerCase().includes(searchTerm) ||
            tool.description.toLowerCase().includes(searchTerm) ||
            tool.category.toLowerCase().includes(searchTerm)
        );

        if (filteredTools.length === 0) {
            categoryContentEl.innerHTML = '<p class="empty-state">Nenhuma ferramenta encontrada.</p>';
            return;
        }

        const toolsList = document.createElement("ul");
        toolsList.className = "tools-list";
        filteredTools.forEach((tool) => {
            const li = document.createElement("li");
            li.className = "tool-item";
            li.innerHTML = `
                <div class="tool-header">
                    <h3 class="tool-name">${tool.name}</h3>
                    <span class="tool-category">${tool.category}</span>
                </div>
                <p class="tool-description">${tool.description}</p>
                ${tool.command ? `<pre class="tool-command">${tool.command}</pre>` : ""}
            `;
            toolsList.appendChild(li);
        });

        categoryContentEl.innerHTML = '';
        categoryContentEl.appendChild(toolsList);
    }


  function buildItem(item, { categoryId, sectionId, stackName }) {
    const element = itemTemplate.content.firstElementChild.cloneNode(true);
    const checkbox = element.querySelector(".item-checkbox");
    const titleEl = element.querySelector(".item-title");
    const descriptionEl = element.querySelector(".item-description");
    const statusSelect = element.querySelector(".item-status");
    const itemTitleCheckbox = element.querySelector(".checkbox");
    const notesEl = element.querySelector(".item-notes");
    const guideBtn = element.querySelector(".item-guide");
    const evidenceInput = element.querySelector('.item-evidence-input');
    const uploadBtn = element.querySelector('.item-upload-btn');
    const attachmentsList = element.querySelector('.item-attachments-list');

    const itemId = makeItemId(categoryId, sectionId, item.id);
    const itemState = getItemState(itemId);

    titleEl.textContent = item.title;
    descriptionEl.textContent = item.description;
    checkbox.checked = itemState.checked;
    statusSelect.value = itemState.status || "";
    notesEl.value = itemState.notes || "";

    renderAttachments();

    itemTitleCheckbox.addEventListener("click", (e) => {
        if (e.target.type !== 'checkbox') {
            element.classList.toggle("expanded");
        }
    });

    checkbox.addEventListener("change", () => updateItemState(itemId, { checked: checkbox.checked }));
    statusSelect.addEventListener("change", () => updateItemState(itemId, { status: statusSelect.value }));
    notesEl.addEventListener("input", (event) => updateItemState(itemId, { notes: event.target.value }));

    uploadBtn.addEventListener('click', async () => {
      const file = evidenceInput.files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append('evidence', file);
      try {
        const response = await fetch('/api/upload', { method: 'POST', body: formData });
        if (!response.ok) throw new Error('Falha no upload.');
        const result = await response.json();
        const updatedAttachments = [...itemState.attachments, result.filePath];
        updateItemState(itemId, { attachments: updatedAttachments });
        evidenceInput.value = '';
        renderAttachments();
        showNotification("Arquivo enviado com sucesso!");
      } catch (error) {
        showNotification("Falha no upload do arquivo.", "error");
      }
    });

    function renderAttachments() {
      attachmentsList.innerHTML = '';
      if (itemState.attachments && itemState.attachments.length > 0) {
        itemState.attachments.forEach(filePath => {
          const li = document.createElement('li');
          const a = document.createElement('a');
          a.href = filePath;
          a.textContent = filePath.split('/').pop();
          a.target = '_blank';
          li.appendChild(a);
          attachmentsList.appendChild(li);
        });
      }
    }

    guideBtn.addEventListener("click", () => openGuideModal(item.title, item.description, item.guide));

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
        } else if (section.key === "references") {
          const list = document.createElement("ul");
          value.forEach((entry) => {
            const li = document.createElement("li");
            const url = getReferenceUrl(entry);
            if (url) {
              const link = document.createElement("a");
              link.href = url;
              link.target = "_blank";
              link.rel = "noopener noreferrer";
              link.className = "reference-link";
              link.innerHTML = `${escapeHtml(entry)} <span class="external-icon">↗</span>`;
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

  function closeModal() {
    modalEl.classList.add("hidden");
  }

  function makeSectionId(categoryId, sectionId) {
    return `${categoryId}::${sectionId}`;
  }

  function makeItemId(categoryId, sectionId, itemId) {
    return `${categoryId}::${sectionId}::${itemId}`;
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
    TABS.forEach((category) => {
        if (category.type === 'tools') return; // Skip tools category in PDF report for now

        sections.push(`<h2>${escapeHtml(category.name)}</h2>`);
        let categorySections = [];
        if (category.type === 'checklist') {
            categorySections = category.payload.sections || [];
        } else if (category.type === 'server') {
            categorySections = category.payload.stacks || [];
        }

        categorySections.forEach((section) => {
            sections.push(`<h3>${escapeHtml(section.title || section.name)}</h3>`);
            sections.push(buildItemsTable(category.id, section.id, section.items));
        });
    });

    return sections.join("\n");
  }

  function buildItemsTable(categoryId, sectionId, items) {
    const rows = items
      .map((item) => {
        const itemId = makeItemId(categoryId, sectionId, item.id);
        const itemState = getItemState(itemId);
        const statusBadge = renderStatusBadge(itemState.status);
        const attachmentsHtml = (itemState.attachments || [])
          .map(path => `<li><a href="${path}" target="_blank">${escapeHtml(path.split('/').pop())}</a></li>`)
          .join('');

        return `
          <tr>
            <td>${escapeHtml(item.title)}</td>
            <td>${statusBadge}</td>
            <td>${itemState.checked ? "✔️" : ""}</td>
            <td class="notes">
              ${escapeHtml(itemState.notes || "")}
              ${attachmentsHtml ? `<h4>Anexos:</h4><ul>${attachmentsHtml}</ul>` : ''}
            </td>
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
    state.meta = { project: projectInput.value, tester: testerInput.value };
    saveState();
  }

    function renderUI() {
        renderNavigation();
        renderContent();
    }

  projectInput.addEventListener("input", persistMeta);
  testerInput.addEventListener("input", persistMeta);
  searchInput.addEventListener("input", renderContent);
  statusFilterEl.addEventListener("change", renderContent);
  exportPdfBtn.addEventListener("click", exportToPdf);
  resetBtn.addEventListener("click", () => {
    if (confirm("Deseja realmente apagar todos os dados salvos?")) resetState();
  });
  modalCloseBtn.addEventListener("click", closeModal);
  modalEl.addEventListener("click", (event) => {
    if (event.target === modalEl) closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modalEl.classList.contains("hidden")) closeModal();
  });

  // Initialize the first section as active by default
  const firstCategory = TABS[0];
  if (firstCategory) {
    let firstSectionId;
    if (firstCategory.type === "checklist") firstSectionId = firstCategory.payload?.sections?.[0]?.id;
    else if (firstCategory.type === "server") firstSectionId = firstCategory.payload?.stacks?.[0]?.id;
    else if (firstCategory.type === "tools") firstSectionId = "all";
    if (firstSectionId) {
      activeItemId = makeSectionId(firstCategory.id, firstSectionId);
    }
  }

  restoreMeta();
  renderUI();
}

document.addEventListener("DOMContentLoaded", main);
