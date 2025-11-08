import { renderStatusBadge } from "./logic.js";

const STATUS_ICONS = {
  passed: "✅",
  failed: "❌",
  na: "⚠️",
  "": "⬜"
};

export function generateFullReport(context, workflowSteps) {
  return buildReportDocument({
    ...context,
    title: "Relatório Técnico Completo",
    subtitle: "Cobertura integral do AppSec Checklist & Guide",
    workflowSteps
  });
}

export function generatePartialReport(context, workflowSteps, selection) {
  return buildReportDocument({
    ...context,
    title: `Relatório Parcial – ${selection.category}`,
    subtitle: `Foco na seção: ${selection.section}`,
    workflowSteps
  });
}

function buildReportDocument({ metadata, sections, title, subtitle, workflowSteps }) {
  const stats = computeStats(sections);
  const summaryHtml = renderSummary(stats, workflowSteps);
  const sectionsHtml = sections
    .map((section) => renderSectionTable(section))
    .join("\n<pagebreak />\n");

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(title)} – ${escapeHtml(metadata.project)}</title>
  <style>
    @page {
      size: A4;
      margin: 2cm;
    }
    body {
      font-family: 'Inter', 'Segoe UI', sans-serif;
      color: #0e1f2f;
      margin: 0;
      padding: 0;
      background: #ffffff;
    }
    header.report-cover {
      padding: 3rem 2.5rem;
      background: linear-gradient(135deg, #0e1f2f, #123a55);
      color: #f8f9fa;
      border-bottom: 6px solid #00c6ff;
      text-align: left;
    }
    header.report-cover h1 {
      margin: 0 0 1rem;
      font-size: 2.35rem;
    }
    header.report-cover p {
      margin: 0.25rem 0;
      font-size: 1rem;
    }
    .report-meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-top: 1.5rem;
    }
    .report-meta div {
      padding: 0.75rem 1rem;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      border: 1px solid rgba(0, 198, 255, 0.45);
    }
    main {
      padding: 2.5rem;
      display: grid;
      gap: 2.5rem;
    }
    h2.section-title {
      margin: 0 0 1rem;
      color: #0e1f2f;
      font-size: 1.5rem;
      border-bottom: 2px solid #00c6ff;
      padding-bottom: 0.35rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1.25rem;
      font-size: 0.95rem;
    }
    thead th {
      background: #0e1f2f;
      color: #f8f9fa;
      padding: 0.75rem;
      text-align: left;
    }
    tbody td {
      border-bottom: 1px solid rgba(14, 31, 47, 0.12);
      padding: 0.65rem 0.75rem;
      vertical-align: top;
    }
    tbody tr:nth-child(even) {
      background: rgba(0, 198, 255, 0.08);
    }
    .status-cell {
      font-weight: 600;
      white-space: nowrap;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.55rem;
      border-radius: 999px;
      background: rgba(0, 198, 255, 0.12);
      color: #0e1f2f;
      font-size: 0.8rem;
    }
    .badge.failed,
    .badge.badge-failed { background: rgba(255, 107, 107, 0.18); }
    .badge.passed,
    .badge.badge-passed { background: rgba(61, 220, 151, 0.22); }
    .badge.na,
    .badge.badge-na { background: rgba(255, 209, 102, 0.22); }
    .report-summary {
      display: grid;
      gap: 2rem;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }
    .summary-card {
      border: 1px solid rgba(14, 31, 47, 0.12);
      border-radius: 16px;
      padding: 1.25rem;
      background: #f5fbff;
    }
    .summary-card h3 {
      margin: 0 0 0.5rem;
      font-size: 1rem;
      color: #0e1f2f;
    }
    .summary-card strong {
      font-size: 1.85rem;
      color: #00a2d4;
    }
    .summary-card p {
      margin: 0.35rem 0 0;
      color: #445b6e;
      font-size: 0.85rem;
    }
    .progress-bar {
      position: relative;
      background: rgba(14, 31, 47, 0.08);
      border-radius: 999px;
      height: 10px;
      overflow: hidden;
      margin-top: 0.75rem;
    }
    .progress-bar span {
      display: block;
      height: 100%;
      background: linear-gradient(90deg, #00c6ff, #3ddc97);
    }
    .workflow-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
    }
    .workflow-step-card {
      border: 1px solid rgba(14, 31, 47, 0.12);
      border-radius: 14px;
      padding: 1rem;
      background: #ffffff;
    }
    .workflow-step-card h4 {
      margin: 0 0 0.35rem;
      font-size: 1rem;
      color: #0e1f2f;
    }
    .workflow-step-card span {
      font-size: 0.85rem;
      color: #4a6274;
    }
    .evidence-list {
      margin: 0.35rem 0 0;
      padding-left: 1.1rem;
      color: #274052;
      font-size: 0.85rem;
    }
    footer.report-footer {
      text-align: center;
      font-size: 0.75rem;
      color: #4a6274;
      padding: 1rem 0 2rem;
    }
    .notes-column {
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  ${renderCover(metadata, title, subtitle)}
  <main>
    ${summaryHtml}
    ${sectionsHtml}
  </main>
  <footer class="report-footer">
    © 2025 AppSec Checklist &amp; Guide — https://appsec-checklist.guide — Página <span class="pageNumber"></span>
  </footer>
</body>
</html>`;
}

function renderCover(metadata, title, subtitle) {
  return `<header class="report-cover">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(subtitle)}</p>
    <div class="report-meta">
      <div>
        <strong>Projeto</strong><br/>
        ${escapeHtml(metadata.project)}
      </div>
      <div>
        <strong>Tester líder</strong><br/>
        ${escapeHtml(metadata.tester)}
      </div>
      <div>
        <strong>Janela da auditoria</strong><br/>
        ${escapeHtml(metadata.auditWindow || "Não informado")}
      </div>
      <div>
        <strong>Gerado em</strong><br/>
        ${metadata.generatedAt.toLocaleString()}
      </div>
    </div>
  </header>`;
}

function renderSummary(stats, workflowSteps) {
  const completion = stats.total === 0 ? 0 : Math.round((stats.completed / stats.total) * 100);
  const failure = stats.total === 0 ? 0 : Math.round((stats.failed / stats.total) * 100);
  const severityRows = Object.entries(stats.severity)
    .map(([severity, value]) => {
      const percent = stats.total === 0 ? 0 : Math.round((value / stats.total) * 100);
      return `<div class="summary-card">
        <h3>${severityLabel(severity)}</h3>
        <strong>${value}</strong>
        <p>${percent}% dos itens</p>
        <div class="progress-bar"><span style="width:${percent}%"></span></div>
      </div>`;
    })
    .join("");

  const workflowCards = workflowSteps
    .map((step) => {
      const value = stats.workflow[step.id] || 0;
      return `<div class="workflow-step-card">
        <h4>${step.label}</h4>
        <span>${value} itens mapeados</span>
      </div>`;
    })
    .join("");

  return `<section class="report-summary">
    <h2 class="section-title">Resumo executivo</h2>
    <div class="summary-grid">
      <div class="summary-card">
        <h3>Itens avaliados</h3>
        <strong>${stats.total}</strong>
        <p>Cobertura total do checklist selecionado.</p>
      </div>
      <div class="summary-card">
        <h3>Conclusão</h3>
        <strong>${completion}%</strong>
        <p>${stats.completed} concluídos / ${stats.pending} pendentes.</p>
        <div class="progress-bar"><span style="width:${completion}%"></span></div>
      </div>
      <div class="summary-card">
        <h3>Falhas</h3>
        <strong>${stats.failed}</strong>
        <p>${failure}% do total requer correção.</p>
        <div class="progress-bar"><span style="width:${failure}%"></span></div>
      </div>
      <div class="summary-card">
        <h3>Evidências anexadas</h3>
        <strong>${stats.attachments}</strong>
        <p>Logs, PoCs, capturas e validações.</p>
      </div>
    </div>
    <h2 class="section-title">Distribuição por severidade</h2>
    <div class="summary-grid">
      ${severityRows}
    </div>
    <h2 class="section-title">Workflow de bug hunting</h2>
    <div class="workflow-grid">
      ${workflowCards}
    </div>
  </section>`;
}

function renderSectionTable(section) {
  const rows = section.records
    .map((record) => {
      const statusIcon = STATUS_ICONS[record.status] || STATUS_ICONS[""];
      const priorityLabel = priorityMap(record.priority);
      const badgeClass = record.status ? `badge ${record.status}` : "badge";
      const references = renderEvidenceChecklist(record.evidenceChecklist);
      const attachments = record.attachments
        .map((attachment) => `<li>${escapeHtml(attachment)}</li>`)
        .join("");

      return `<tr>
        <td>
          <strong>${escapeHtml(record.title)}</strong><br/>
          <small>${escapeHtml(record.description)}</small>
        </td>
        <td class="status-cell">
          ${statusIcon} ${renderStatusBadge(record.status)}
        </td>
        <td>${record.checked ? "✔️" : ""}</td>
        <td class="notes-column">
          <div class="badge ${badgeClass}">${escapeHtml(priorityLabel)}</div>
          <div><strong>Severidade:</strong> ${severityLabel(record.severity)}</div>
          <div><strong>Fase:</strong> ${escapeHtml(stageLabel(record.stage))}</div>
          ${record.assignee ? `<div><strong>Tester:</strong> ${escapeHtml(record.assignee)}</div>` : ""}
          ${record.evidenceNarrative ? `<div><strong>Narrativa:</strong> ${escapeHtml(record.evidenceNarrative)}</div>` : ""}
          ${record.notes ? `<div><strong>Notas:</strong> ${escapeHtml(record.notes)}</div>` : ""}
          ${references}
          ${attachments ? `<div><strong>Anexos:</strong><ul class="evidence-list">${attachments}</ul></div>` : ""}
        </td>
      </tr>`;
    })
    .join("");

  return `<section>
    <h2 class="section-title">${escapeHtml(section.categoryName)} · ${escapeHtml(section.sectionTitle)}</h2>
    <table>
      <thead>
        <tr>
          <th>Item</th>
          <th>Status</th>
          <th>Concluído</th>
          <th>Notas / Evidências / Prioridade</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </section>`;
}

function renderEvidenceChecklist(checklist) {
  if (!checklist) return "";
  const enabled = Object.entries(checklist)
    .filter(([, value]) => value)
    .map(([key]) => evidenceLabel(key));
  if (enabled.length === 0) return "";
  return `<div><strong>Evidências:</strong> ${enabled.join(", ")}</div>`;
}

function computeStats(sections) {
  const stats = {
    total: 0,
    completed: 0,
    failed: 0,
    na: 0,
    pending: 0,
    attachments: 0,
    severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    workflow: { recon: 0, testing: 0, access: 0, report: 0, mitigate: 0 }
  };

  sections.forEach((section) => {
    section.records.forEach((record) => {
      stats.total += 1;
      if (record.checked) stats.completed += 1;
      if (record.status === "failed") stats.failed += 1;
      if (record.status === "na") stats.na += 1;
      if (!record.status) stats.pending += 1;
      stats.attachments += record.attachments.length;
      if (stats.severity[record.severity] !== undefined) {
        stats.severity[record.severity] += 1;
      }
      if (stats.workflow[record.stage] !== undefined) {
        stats.workflow[record.stage] += 1;
      }
    });
  });
  return stats;
}

function severityLabel(severity) {
  const map = {
    critical: "Crítica",
    high: "Alta",
    medium: "Média",
    low: "Baixa",
    info: "Informativa"
  };
  return map[severity] || "Definida";
}

function priorityMap(priority) {
  const map = {
    p0: "P0 – Mitigação imediata",
    p1: "P1 – Alta prioridade",
    p2: "P2 – Tratamento planejado",
    p3: "P3 – Monitoramento"
  };
  return map[priority] || "Prioridade definida";
}

function evidenceLabel(key) {
  const map = {
    screenshot: "Screenshot / Vídeo",
    logs: "Logs coletados",
    payload: "Payload & resposta",
    impact: "Impacto documentado"
  };
  return map[key] || key;
}

function stageLabel(stage) {
  const map = {
    recon: "Recon & Asset Discovery",
    testing: "Testar & Fuzzing",
    access: "Verificar Controles",
    report: "Reportar & Evidenciar",
    mitigate: "Mitigar & Validar"
  };
  return map[stage] || stage;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
