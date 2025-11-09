/**
 * CVSS v3.1 Calculator
 * Calculates CVSS score from vector string
 * @license ISC
 */

/**
 * Parse CVSS v3.1 vector string
 * @param {string} vector - Vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
 * @returns {Object} - Parsed metrics
 */
export function parseVector(vector) {
  const metrics = {};
  const parts = vector.split('/');

  for (const part of parts) {
    if (part.includes(':')) {
      const [key, value] = part.split(':');
      metrics[key] = value;
    }
  }

  return metrics;
}

/**
 * Get base score from metrics
 * @param {Object} metrics - Parsed metrics
 * @returns {number} - Base score (0-10)
 */
export function calculateBaseScore(metrics) {
  // Default values for missing metrics
  const av = metrics.AV || 'N';
  const ac = metrics.AC || 'L';
  const pr = metrics.PR || 'N';
  const ui = metrics.UI || 'N';
  const s = metrics.S || 'U';
  const c = metrics.C || 'N';
  const i = metrics.I || 'N';
  const a = metrics.A || 'N';

  // Score values
  const avScore = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[av] || 0;
  const acScore = { L: 0.77, H: 0.44 }[ac] || 0;

  // PR depends on scope
  const scope = s === 'C' ? 'Changed' : 'Unchanged';
  const prScore = scope === 'Changed'
    ? { N: 0.85, L: 0.68, H: 0.5 }[pr] || 0
    : { N: 0.85, L: 0.62, H: 0.27 }[pr] || 0;

  const uiScore = { N: 0.85, R: 0.62 }[ui] || 0;
  const cScore = { H: 0.56, L: 0.22, N: 0 }[c] || 0;
  const iScore = { H: 0.56, L: 0.22, N: 0 }[i] || 0;
  const aScore = { H: 0.56, L: 0.22, N: 0 }[a] || 0;

  // Calculate scope
  const scopeScore = s === 'C' ? 7.52 : 6.42;
  const impactScore = 1 - ((1 - cScore) * (1 - iScore) * (1 - aScore));
  const exploitScore = 8.22 * avScore * acScore * prScore * uiScore;

  let baseScore;
  if (impactScore <= 0) {
    baseScore = 0;
  } else if (s === 'U') {
    baseScore = Math.min(exploitScore + impactScore, 10);
  } else {
    baseScore = Math.min(scopeScore * impactScore + exploitScore - 0.029, 10);
  }

  return Math.round(baseScore * 10) / 10;
}

/**
 * Calculate temporal score
 * @param {Object} metrics - Parsed metrics
 * @param {number} baseScore - Base score
 * @returns {number} - Temporal score
 */
export function calculateTemporalScore(metrics, baseScore) {
  const e = metrics.E || 'X';
  const rl = metrics.RL || 'X';
  const rc = metrics.RC || 'X';

  const eScore = { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 }[e] || 1;
  const rlScore = { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 }[rl] || 1;
  const rcScore = { X: 1, U: 0.92, R: 0.96, C: 1 }[rc] || 1;

  const temporalScore = baseScore * eScore * rlScore * rcScore;
  return Math.round(temporalScore * 10) / 10;
}

/**
 * Calculate environmental score
 * @param {Object} metrics - Parsed metrics
 * @param {number} baseScore - Base score
 * @returns {number} - Environmental score
 */
export function calculateEnvironmentalScore(metrics, baseScore) {
  const cr = metrics.CR || 'X';
  const ir = metrics.IR || 'X';
  const ar = metrics.AR || 'X';
  const mav = metrics.MAV || 'X';
  const mac = metrics.MAC || 'X';
  const mpr = metrics.MPR || 'X';
  const mui = metrics.MUI || 'X';
  const ms = metrics.MS || 'X';
  const mc = metrics.MC || 'X';
  const mi = metrics.MI || 'X';
  const ma = metrics.MA || 'X';

  // If no modified metrics, return temporal score
  if (mav === 'X' && mac === 'X' && mpr === 'X' && mui === 'X' &&
      ms === 'X' && mc === 'X' && mi === 'X' && ma === 'X') {
    return baseScore;
  }

  // Confidence scores
  const crScore = { X: 1, L: 0.5, M: 0.75, H: 1 }[cr] || 1;
  const irScore = { X: 1, L: 0.5, M: 0.75, H: 1 }[ir] || 1;
  const arScore = { X: 1, L: 0.5, M: 0.75, H: 1 }[ar] || 1;

  // Use modified metrics or fall back to base metrics
  const av = mav === 'X' ? metrics.AV || 'N' : mav;
  const ac = mac === 'X' ? metrics.AC || 'L' : mac;
  const pr = mpr === 'X' ? metrics.PR || 'N' : mpr;
  const ui = mui === 'X' ? metrics.UI || 'N' : mui;
  const s = ms === 'X' ? metrics.S || 'U' : ms;
  const c = mc === 'X' ? metrics.C || 'N' : mc;
  const i = mi === 'X' ? metrics.I || 'N' : mi;
  const a = ma === 'X' ? metrics.A || 'N' : ma;

  // Recalculate base score with modified metrics
  const modifiedBaseScore = calculateBaseScore({
    AV: av, AC: ac, PR: pr, UI: ui, S: s, C: c, I: i, A: a
  });

  const envScore = (modifiedBaseScore * crScore * irScore * arScore) * (1 - 0.01);
  return Math.round(envScore * 10) / 10;
}

/**
 * Calculate full CVSS score from vector
 * @param {string} vector - CVSS vector string
 * @returns {Object} - { baseScore, temporalScore, environmentalScore }
 */
export function calculateScore(vector) {
  if (!vector || !vector.includes('CVSS:3.1')) {
    return { baseScore: 0, temporalScore: 0, environmentalScore: 0 };
  }

  try {
    const metrics = parseVector(vector);
    const baseScore = calculateBaseScore(metrics);
    const temporalScore = calculateTemporalScore(metrics, baseScore);
    const environmentalScore = calculateEnvironmentalScore(metrics, baseScore);

    return {
      baseScore,
      temporalScore,
      environmentalScore
    };
  } catch (error) {
    console.error('Error calculating CVSS score:', error);
    return { baseScore: 0, temporalScore: 0, environmentalScore: 0 };
  }
}

/**
 * Get severity rating from score
 * @param {number} score - CVSS score
 * @returns {string} - Severity level
 */
export function getSeverity(score) {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

/**
 * Validate CVSS vector format
 * @param {string} vector - Vector string
 * @returns {boolean} - True if valid
 */
export function isValidVector(vector) {
  if (!vector || typeof vector !== 'string') return false;
  if (!vector.startsWith('CVSS:3.1/')) return false;

  const parts = vector.split('/');
  const validMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
  const validValues = {
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'R'],
    S: ['U', 'C'],
    C: ['H', 'L', 'N'],
    I: ['H', 'L', 'N'],
    A: ['H', 'L', 'N'],
    E: ['X', 'U', 'P', 'F', 'H'],
    RL: ['X', 'O', 'T', 'W', 'U'],
    RC: ['X', 'U', 'R', 'C'],
    CR: ['X', 'L', 'M', 'H'],
    IR: ['X', 'L', 'M', 'H'],
    AR: ['X', 'L', 'M', 'H']
  };

  for (let i = 1; i < parts.length; i++) {
    const [key, value] = parts[i].split(':');

    if (!validMetrics.includes(key)) return false;
    if (!validValues[key] || !validValues[key].includes(value)) return false;
  }

  return true;
}

export default {
  parseVector,
  calculateBaseScore,
  calculateTemporalScore,
  calculateEnvironmentalScore,
  calculateScore,
  getSeverity,
  isValidVector
};
