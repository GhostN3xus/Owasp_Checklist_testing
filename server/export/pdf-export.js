/**
 * PDF Export Module
 * Uses pdf-lib for lightweight PDF generation
 * @license ISC
 */

/**
 * Generate PDF report as HTML/CSS (for browser printing)
 * @param {Object} state - Project state
 * @param {Object} standards - Standards data
 * @returns {string} - HTML string for PDF rendering
 */
export function generatePDFHTML(state, standards) {
  const checksWithState = Object.entries(state.checkStates).map(([checkId, checkState]) => {
    let standardInfo = null;

    for (const stdName of ['asvs', 'masvs', 'api', 'wstg']) {
      if (!standards[stdName]) continue;

      const item = standards[stdName].data.find(row => row.ID === checkId);
      if (item) {
        standardInfo = {
          standard: stdName.toUpperCase(),
          ...item
        };
        break;
      }
    }

    return {
      id: checkId,
      status: checkState.status,
      severity: checkState.severity || 'Medium',
      notes: state.notes[checkId] || '',
      evidence: state.evidences.filter(e => e.checkId === checkId),
      cvss: state.cvss[checkId] || null,
      cwe: state.cwe[checkId] || [],
      mitre_attack: state.mitre_attack[checkId] || [],
      standardInfo
    };
  });

  // Calculate statistics
  const stats = {
    total: checksWithState.length,
    passed: checksWithState.filter(c => c.status === 'passed').length,
    failed: checksWithState.filter(c => c.status === 'failed').length,
    na: checksWithState.filter(c => c.status === 'na').length,
    notTested: checksWithState.filter(c => c.status === 'not-tested').length,
    percentComplete: checksWithState.length > 0 ?
      Math.round((checksWithState.filter(c => c.status === 'passed').length / checksWithState.length) * 100) :
      0,
    criticalFindings: checksWithState.filter(c => c.cvss && c.cvss.score >= 9.0).length,
    highFindings: checksWithState.filter(c => c.cvss && c.cvss.score >= 7.0 && c.cvss.score < 9.0).length
  };

  const reportDate = new Date().toLocaleString();

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AppSec Report - ${state.name}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #333;
      line-height: 1.6;
      background: #f5f5f5;
    }

    .page {
      background: white;
      padding: 40px;
      margin: 20px auto;
      max-width: 900px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }

    .cover-page {
      text-align: center;
      page-break-after: always;
      padding: 80px 40px;
    }

    .cover-page h1 {
      font-size: 48px;
      margin-bottom: 20px;
      color: #0066cc;
    }

    .cover-page .subtitle {
      font-size: 24px;
      color: #666;
      margin-bottom: 40px;
    }

    .cover-page .meta {
      margin-top: 60px;
      text-align: left;
      display: inline-block;
      font-size: 14px;
    }

    .cover-page .meta p {
      margin: 10px 0;
    }

    h1 {
      font-size: 32px;
      margin: 30px 0 20px 0;
      color: #0066cc;
      border-bottom: 3px solid #0066cc;
      padding-bottom: 10px;
    }

    h2 {
      font-size: 24px;
      margin: 25px 0 15px 0;
      color: #0099ff;
    }

    h3 {
      font-size: 18px;
      margin: 20px 0 10px 0;
      color: #0099ff;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
      margin: 30px 0;
    }

    .stat-box {
      background: #f9f9f9;
      border: 2px solid #ddd;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }

    .stat-box .value {
      font-size: 36px;
      font-weight: bold;
      color: #0066cc;
    }

    .stat-box .label {
      font-size: 14px;
      color: #666;
      margin-top: 10px;
    }

    .metrics {
      background: #f0f8ff;
      border-left: 4px solid #0066cc;
      padding: 20px;
      margin: 20px 0;
      border-radius: 4px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
      font-size: 13px;
    }

    th {
      background: #0066cc;
      color: white;
      padding: 12px;
      text-align: left;
      font-weight: 600;
    }

    td {
      padding: 10px 12px;
      border-bottom: 1px solid #ddd;
    }

    tr:nth-child(even) {
      background: #f9f9f9;
    }

    .status-badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 12px;
    }

    .status-passed {
      background: #d4edda;
      color: #155724;
    }

    .status-failed {
      background: #f8d7da;
      color: #721c24;
    }

    .status-na {
      background: #e2e3e5;
      color: #383d41;
    }

    .status-not-tested {
      background: #fff3cd;
      color: #856404;
    }

    .severity-critical {
      background: #dc3545;
      color: white;
    }

    .severity-high {
      background: #fd7e14;
      color: white;
    }

    .severity-medium {
      background: #ffc107;
      color: black;
    }

    .severity-low {
      background: #28a745;
      color: white;
    }

    .evidence-section {
      background: #f9f9f9;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 15px;
      margin: 10px 0;
    }

    .evidence-title {
      font-weight: 600;
      color: #0066cc;
      margin-bottom: 5px;
    }

    .note {
      background: #fffacd;
      padding: 10px;
      border-left: 3px solid #ffc107;
      margin: 10px 0;
      font-size: 13px;
    }

    .page-break {
      page-break-after: always;
    }

    .toc {
      page-break-after: always;
    }

    .toc ol {
      margin-left: 20px;
    }

    .toc li {
      margin: 8px 0;
    }

    @media print {
      body {
        background: white;
      }
      .page {
        box-shadow: none;
        margin: 0;
        page-break-inside: avoid;
      }
    }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="page cover-page">
    <h1>🔒 AppSec Assessment Report</h1>
    <div class="subtitle">Comprehensive Security Evaluation</div>

    <div class="meta">
      <p><strong>Project:</strong> ${escapeHTML(state.name)}</p>
      <p><strong>Generated:</strong> ${reportDate}</p>
      <p><strong>Language Targets:</strong> ${(state.languageTargets || []).join(', ') || 'N/A'}</p>
      <p><strong>Cloud Platforms:</strong> ${(state.cloudTargets || []).join(', ') || 'N/A'}</p>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="page">
    <h1>Executive Summary</h1>

    <div class="stats-grid">
      <div class="stat-box">
        <div class="value">${stats.percentComplete}%</div>
        <div class="label">Completion Rate</div>
      </div>
      <div class="stat-box">
        <div class="value">${stats.passed}/${stats.total}</div>
        <div class="label">Items Passed</div>
      </div>
      <div class="stat-box">
        <div class="value">${stats.failed}</div>
        <div class="label">Critical Issues</div>
      </div>
    </div>

    <div class="metrics">
      <h3>Assessment Metrics</h3>
      <table>
        <tr>
          <td><strong>Total Checks</strong></td>
          <td>${stats.total}</td>
        </tr>
        <tr>
          <td><strong>Passed</strong></td>
          <td>${stats.passed}</td>
        </tr>
        <tr>
          <td><strong>Failed</strong></td>
          <td>${stats.failed}</td>
        </tr>
        <tr>
          <td><strong>Not Applicable</strong></td>
          <td>${stats.na}</td>
        </tr>
        <tr>
          <td><strong>Not Tested</strong></td>
          <td>${stats.notTested}</td>
        </tr>
        <tr>
          <td><strong>Critical Findings (CVSS ≥ 9.0)</strong></td>
          <td>${stats.criticalFindings}</td>
        </tr>
        <tr>
          <td><strong>High Findings (CVSS 7.0-8.9)</strong></td>
          <td>${stats.highFindings}</td>
        </tr>
      </table>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="page">
    <h1>Detailed Findings</h1>

    <table>
      <thead>
        <tr>
          <th>Check ID</th>
          <th>Title</th>
          <th>Status</th>
          <th>Severity</th>
          <th>CVSS</th>
        </tr>
      </thead>
      <tbody>
        ${checksWithState.map(check => `
          <tr>
            <td><strong>${escapeHTML(check.id)}</strong></td>
            <td>${escapeHTML(check.standardInfo?.Title || 'N/A')}</td>
            <td>
              <span class="status-badge status-${check.status || 'not-tested'}">
                ${check.status ? check.status.toUpperCase() : 'NOT TESTED'}
              </span>
            </td>
            <td>
              <span class="status-badge severity-${(check.severity || 'low').toLowerCase()}">
                ${check.severity || 'Medium'}
              </span>
            </td>
            <td>${check.cvss?.score || '-'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  <!-- Detailed Findings -->
  <div class="page">
    <h1>Detailed Assessment Results</h1>

    ${checksWithState.filter(c => c.status === 'failed' || (c.cvss && c.cvss.score >= 7)).map(check => `
      <div style="margin: 30px 0; page-break-inside: avoid;">
        <h2>${escapeHTML(check.id)} - ${escapeHTML(check.standardInfo?.Title || 'Unknown')}</h2>

        <table style="width: 100%;">
          <tr>
            <td style="width: 25%;"><strong>Standard:</strong></td>
            <td>${check.standardInfo?.standard || 'N/A'}</td>
          </tr>
          <tr>
            <td><strong>Status:</strong></td>
            <td>
              <span class="status-badge status-${check.status || 'not-tested'}">
                ${check.status ? check.status.toUpperCase() : 'NOT TESTED'}
              </span>
            </td>
          </tr>
          <tr>
            <td><strong>Severity:</strong></td>
            <td>
              <span class="status-badge severity-${(check.severity || 'low').toLowerCase()}">
                ${check.severity || 'Medium'}
              </span>
            </td>
          </tr>
          ${check.cvss ? `
            <tr>
              <td><strong>CVSS Score:</strong></td>
              <td>${check.cvss.score} (${check.cvss.vector || 'N/A'})</td>
            </tr>
          ` : ''}
          ${check.cwe.length > 0 ? `
            <tr>
              <td><strong>CWE:</strong></td>
              <td>${check.cwe.join(', ')}</td>
            </tr>
          ` : ''}
          ${check.mitre_attack.length > 0 ? `
            <tr>
              <td><strong>MITRE ATT&CK:</strong></td>
              <td>${check.mitre_attack.join(', ')}</td>
            </tr>
          ` : ''}
        </table>

        ${check.notes ? `
          <div class="note">
            <strong>Notes:</strong> ${escapeHTML(check.notes)}
          </div>
        ` : ''}

        ${check.evidence.length > 0 ? `
          <h3>Evidence</h3>
          ${check.evidence.map(ev => `
            <div class="evidence-section">
              <div class="evidence-title">${escapeHTML(ev.title)}</div>
              <div style="font-size: 12px; color: #666;">Type: ${ev.type} | ${new Date(ev.timestamp).toLocaleString()}</div>
              ${ev.description ? `<div style="margin-top: 8px;">${escapeHTML(ev.description)}</div>` : ''}
            </div>
          `).join('')}
        ` : ''}
      </div>
    `).join('')}
  </div>

  <!-- Appendix -->
  <div class="page">
    <h1>Appendix: Full Checklist</h1>

    <table>
      <thead>
        <tr>
          <th>Check ID</th>
          <th>Title</th>
          <th>Status</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        ${checksWithState.map(check => `
          <tr>
            <td style="font-size: 11px;"><strong>${escapeHTML(check.id)}</strong></td>
            <td style="font-size: 11px;">${escapeHTML(check.standardInfo?.Title || 'N/A')}</td>
            <td style="font-size: 11px;">
              <span class="status-badge status-${check.status || 'not-tested'}">
                ${check.status ? check.status.substring(0, 3).toUpperCase() : 'N/T'}
              </span>
            </td>
            <td style="font-size: 11px;">${check.notes ? escapeHTML(check.notes.substring(0, 30) + '...') : '-'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
</body>
</html>
  `;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
function escapeHTML(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

export default {
  generatePDFHTML
};
