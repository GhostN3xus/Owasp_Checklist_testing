/**
 * CSV Export Module
 * @license ISC
 */

/**
 * Escape CSV field value
 * @param {string} value - Field value
 * @returns {string} - Escaped value
 */
function escapeCSV(value) {
  if (value === null || value === undefined) return '';

  const str = String(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Export project checks to CSV
 * @param {Object} state - Project state
 * @param {Object} standards - Standards data
 * @returns {string} - CSV string
 */
export function exportChecksToCSV(state, standards) {
  const headers = [
    'ID',
    'Standard',
    'Title',
    'Status',
    'Severity',
    'CVSS Vector',
    'CVSS Score',
    'CWE IDs',
    'MITRE ATT&CK',
    'Evidence Count',
    'Notes'
  ];

  const rows = Object.entries(state.checkStates).map(([checkId, checkState]) => {
    let standardInfo = null;

    for (const stdName of ['asvs', 'masvs', 'api', 'wstg']) {
      if (!standards[stdName]) continue;

      const item = standards[stdName].data.find(row => row.ID === checkId);
      if (item) {
        standardInfo = {
          standard: stdName.toUpperCase(),
          title: item.Title || ''
        };
        break;
      }
    }

    const cvss = state.cvss[checkId] || {};
    const cweIds = (state.cwe[checkId] || []).join(';');
    const mitre = (state.mitre_attack[checkId] || []).join(';');
    const evidenceCount = state.evidences.filter(e => e.checkId === checkId).length;

    return [
      checkId,
      standardInfo?.standard || 'UNKNOWN',
      standardInfo?.title || '',
      checkState.status || 'not-tested',
      checkState.severity || 'Medium',
      cvss.vector || '',
      cvss.score || '',
      cweIds,
      mitre,
      evidenceCount,
      escapeCSV(state.notes[checkId] || '')
    ].map(escapeCSV);
  });

  // Build CSV
  let csv = headers.map(escapeCSV).join(',') + '\n';
  csv += rows.map(row => row.join(',')).join('\n');

  return csv;
}

/**
 * Export project findings to CSV
 * @param {Object} state - Project state
 * @param {Object} standards - Standards data
 * @returns {string} - CSV string
 */
export function exportFindingsToCSV(state, standards) {
  const headers = [
    'Timestamp',
    'Check ID',
    'Standard',
    'Title',
    'CVSS Score',
    'Status',
    'Evidence Title',
    'Evidence Type',
    'Description'
  ];

  const rows = [];

  state.evidences.forEach(evidence => {
    const checkState = state.checkStates[evidence.checkId] || {};
    const cvss = state.cvss[evidence.checkId] || {};

    let standardInfo = null;
    for (const stdName of ['asvs', 'masvs', 'api', 'wstg']) {
      if (!standards[stdName]) continue;

      const item = standards[stdName].data.find(row => row.ID === evidence.checkId);
      if (item) {
        standardInfo = {
          standard: stdName.toUpperCase(),
          title: item.Title || ''
        };
        break;
      }
    }

    rows.push([
      new Date(evidence.timestamp).toLocaleString(),
      evidence.checkId,
      standardInfo?.standard || 'UNKNOWN',
      standardInfo?.title || '',
      cvss.score || '',
      checkState.status || 'not-tested',
      escapeCSV(evidence.title || ''),
      evidence.type || 'note',
      escapeCSV(evidence.description || '')
    ].map(escapeCSV));
  });

  // Build CSV
  let csv = headers.map(escapeCSV).join(',') + '\n';
  csv += rows.map(row => row.join(',')).join('\n');

  return csv;
}

/**
 * Export project summary to CSV
 * @param {Object} state - Project state
 * @returns {string} - CSV string
 */
export function exportSummaryToCSV(state) {
  const checksWithState = Object.values(state.checkStates);
  const total = checksWithState.length;
  const passed = checksWithState.filter(c => c.status === 'passed').length;
  const failed = checksWithState.filter(c => c.status === 'failed').length;
  const na = checksWithState.filter(c => c.status === 'na').length;
  const notTested = checksWithState.filter(c => c.status === 'not-tested').length;

  const criticalFindings = Object.values(state.cvss || {}).filter(c => c.score >= 9.0).length;
  const highFindings = Object.values(state.cvss || {}).filter(c => c.score >= 7.0 && c.score < 9.0).length;

  const csv = [
    'Project Summary',
    '',
    'Project Name,' + escapeCSV(state.name),
    'Created At,' + state.createdAt,
    'Language Targets,' + (state.languageTargets || []).join(';'),
    'Cloud Targets,' + (state.cloudTargets || []).join(';'),
    '',
    'Check Status',
    'Total,' + total,
    'Passed,' + passed,
    'Failed,' + failed,
    'Not Applicable,' + na,
    'Not Tested,' + notTested,
    'Completion %,' + (total > 0 ? Math.round((passed / total) * 100) : 0),
    '',
    'Findings Summary',
    'Critical Findings,' + criticalFindings,
    'High Findings,' + highFindings,
    'Evidence Count,' + state.evidences.length
  ].join('\n');

  return csv;
}

export default {
  exportChecksToCSV,
  exportFindingsToCSV,
  exportSummaryToCSV
};
