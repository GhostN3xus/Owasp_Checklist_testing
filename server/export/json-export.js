/**
 * JSON Export Module
 * @license ISC
 */

/**
 * Export project to JSON
 * @param {Object} state - Project state
 * @param {Object} standards - Standards data
 * @returns {Object} - Exportable JSON object
 */
export function exportJSON(state, standards) {
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

  return {
    project: {
      id: state.id,
      name: state.name,
      createdAt: state.createdAt,
      languageTargets: state.languageTargets,
      cloudTargets: state.cloudTargets,
      settings: state.settings
    },
    statistics: stats,
    checks: checksWithState,
    exportedAt: new Date().toISOString()
  };
}

/**
 * Convert export object to JSON string
 * @param {Object} exportData - Export object
 * @returns {string} - JSON string
 */
export function jsonToString(exportData) {
  return JSON.stringify(exportData, null, 2);
}

export default {
  exportJSON,
  jsonToString
};
