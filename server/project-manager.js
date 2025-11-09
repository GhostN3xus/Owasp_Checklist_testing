/**
 * Project Manager Module
 * Handles project lifecycle with encryption and persistence
 * @license ISC
 */

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { encryptToFile, decryptFromFile } from './crypto/aesgcm.js';

const DATA_DIR = './data';

/**
 * Create data directory if it doesn't exist
 */
async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (error) {
    console.error('Error creating data directory:', error);
  }
}

/**
 * Project state structure
 */
function createProjectState(name, languageTargets = [], cloudTargets = []) {
  return {
    id: crypto.randomUUID(),
    name,
    createdAt: new Date().toISOString(),
    languageTargets,
    cloudTargets,
    checkStates: {}, // { "ASVS-V1.1.1": { status: "passed"|"failed"|"na"|"not-tested", severity: "" } }
    evidences: [], // { id, checkId, title, type, content, timestamp }
    cvss: {}, // { checkId: { vector: "...", score: 3.5 } }
    cwe: {}, // { checkId: [...] }
    mitre_attack: {}, // { checkId: [...] }
    mappings: {}, // Custom mappings
    notes: {}, // { checkId: "text" }
    settings: {
      language: 'en',
      theme: 'dark',
      filters: {}
    }
  };
}

/**
 * Create a new project
 * @param {string} name - Project name
 * @param {string} password - Project password for encryption
 * @param {Array<string>} languageTargets - Languages to test (e.g., ['JavaScript', 'Python'])
 * @param {Array<string>} cloudTargets - Cloud platforms (e.g., ['AWS', 'GCP'])
 * @returns {Promise<Object>} - Created project
 */
export async function createProject(name, password, languageTargets = [], cloudTargets = []) {
  await ensureDataDir();

  const state = createProjectState(name, languageTargets, cloudTargets);
  const projectDir = path.join(DATA_DIR, state.id);

  try {
    // Create project directory
    await fs.mkdir(projectDir, { recursive: true });
    await fs.mkdir(path.join(projectDir, 'evidence'), { recursive: true });

    // Encrypt and save project state
    const stateJson = JSON.stringify(state, null, 2);
    await encryptToFile(
      path.join(projectDir, 'state.json'),
      stateJson,
      password
    );

    return state;
  } catch (error) {
    console.error('Error creating project:', error);
    throw error;
  }
}

/**
 * Load a project
 * @param {string} projectId - Project ID
 * @param {string} password - Project password
 * @returns {Promise<Object>} - Project state
 */
export async function loadProject(projectId, password) {
  const projectDir = path.join(DATA_DIR, projectId);
  const stateFile = path.join(projectDir, 'state.json');

  try {
    const decrypted = await decryptFromFile(stateFile, password);
    const state = JSON.parse(decrypted.toString('utf8'));
    return state;
  } catch (error) {
    if (error.message.includes('Decryption failed')) {
      throw new Error('Invalid password');
    }
    throw error;
  }
}

/**
 * Save project state
 * @param {string} projectId - Project ID
 * @param {Object} state - Project state
 * @param {string} password - Project password
 */
export async function saveProject(projectId, state, password) {
  const projectDir = path.join(DATA_DIR, projectId);
  const stateFile = path.join(projectDir, 'state.json');

  try {
    const stateJson = JSON.stringify(state, null, 2);
    await encryptToFile(stateFile, stateJson, password);
  } catch (error) {
    console.error('Error saving project:', error);
    throw error;
  }
}

/**
 * List all projects (without decryption)
 * @returns {Promise<Array>} - Array of project IDs
 */
export async function listProjects() {
  await ensureDataDir();

  try {
    const entries = await fs.readdir(DATA_DIR, { withFileTypes: true });
    return entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name);
  } catch (error) {
    return [];
  }
}

/**
 * Get project metadata without decryption
 * @param {string} projectId - Project ID
 * @returns {Promise<Object>} - { id, name, createdAt }
 */
export async function getProjectMetadata(projectId) {
  const projectDir = path.join(DATA_DIR, projectId);
  const metaFile = path.join(projectDir, '.metadata');

  try {
    const content = await fs.readFile(metaFile, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    // Return basic metadata if file doesn't exist
    return { id: projectId, name: 'Unknown Project', createdAt: null };
  }
}

/**
 * Save project metadata (unencrypted, for listing)
 * @param {string} projectId - Project ID
 * @param {string} name - Project name
 * @param {string} createdAt - Creation date
 */
export async function saveProjectMetadata(projectId, name, createdAt) {
  const projectDir = path.join(DATA_DIR, projectId);

  try {
    await fs.writeFile(
      path.join(projectDir, '.metadata'),
      JSON.stringify({ id: projectId, name, createdAt }, null, 2),
      'utf8'
    );
  } catch (error) {
    console.error('Error saving project metadata:', error);
  }
}

/**
 * Delete a project
 * @param {string} projectId - Project ID
 */
export async function deleteProject(projectId) {
  const projectDir = path.join(DATA_DIR, projectId);

  try {
    await fs.rm(projectDir, { recursive: true, force: true });
  } catch (error) {
    console.error('Error deleting project:', error);
    throw error;
  }
}

/**
 * Update check state
 * @param {Object} state - Project state
 * @param {string} checkId - Check ID
 * @param {Object} update - { status, severity, notes }
 */
export function updateCheckState(state, checkId, update) {
  if (!state.checkStates[checkId]) {
    state.checkStates[checkId] = {};
  }

  Object.assign(state.checkStates[checkId], update);
}

/**
 * Add evidence
 * @param {Object} state - Project state
 * @param {string} checkId - Check ID
 * @param {Object} evidence - { title, type, content, description }
 * @returns {string} - Evidence ID
 */
export function addEvidence(state, checkId, evidence) {
  const id = crypto.randomUUID();
  const evidenceRecord = {
    id,
    checkId,
    ...evidence,
    timestamp: new Date().toISOString()
  };

  state.evidences.push(evidenceRecord);
  return id;
}

/**
 * Remove evidence
 * @param {Object} state - Project state
 * @param {string} evidenceId - Evidence ID
 */
export function removeEvidence(state, evidenceId) {
  state.evidences = state.evidences.filter(e => e.id !== evidenceId);
}

/**
 * Update CVSS for a check
 * @param {Object} state - Project state
 * @param {string} checkId - Check ID
 * @param {Object} cvss - { vector, score }
 */
export function updateCVSS(state, checkId, cvss) {
  state.cvss[checkId] = cvss;
}

/**
 * Update CWE mapping
 * @param {Object} state - Project state
 * @param {string} checkId - Check ID
 * @param {Array<string>} cweIds - CWE IDs
 */
export function updateCWE(state, checkId, cweIds) {
  state.cwe[checkId] = cweIds;
}

/**
 * Update MITRE ATT&CK mapping
 * @param {Object} state - Project state
 * @param {string} checkId - Check ID
 * @param {Array<string>} techniques - MITRE ATT&CK technique IDs
 */
export function updateMitreAttack(state, checkId, techniques) {
  state.mitre_attack[checkId] = techniques;
}

/**
 * Save note for a check
 * @param {Object} state - Project state
 * @param {string} checkId - Check ID
 * @param {string} note - Note text
 */
export function updateNote(state, checkId, note) {
  state.notes[checkId] = note;
}

/**
 * Get all checks with their state
 * @param {Object} state - Project state
 * @returns {Array<Object>} - Checks with state
 */
export function getChecksWithState(state) {
  return Object.entries(state.checkStates).map(([checkId, checkState]) => ({
    checkId,
    ...checkState,
    note: state.notes[checkId] || '',
    cvss: state.cvss[checkId] || null,
    cwe: state.cwe[checkId] || [],
    mitre_attack: state.mitre_attack[checkId] || [],
    evidences: state.evidences.filter(e => e.checkId === checkId)
  }));
}

/**
 * Calculate project statistics
 * @param {Object} state - Project state
 * @returns {Object} - Statistics
 */
export function calculateStatistics(state) {
  const checks = Object.values(state.checkStates);
  const total = checks.length;
  const passed = checks.filter(c => c.status === 'passed').length;
  const failed = checks.filter(c => c.status === 'failed').length;
  const na = checks.filter(c => c.status === 'na').length;
  const notTested = checks.filter(c => c.status === 'not-tested').length;

  return {
    total,
    passed,
    failed,
    na,
    notTested,
    percentComplete: total > 0 ? Math.round((passed / total) * 100) : 0,
    criticalFindings: state.cvss ? Object.values(state.cvss).filter(c => c.score >= 9.0).length : 0,
    highFindings: state.cvss ? Object.values(state.cvss).filter(c => c.score >= 7.0 && c.score < 9.0).length : 0
  };
}

export default {
  createProject,
  loadProject,
  saveProject,
  listProjects,
  getProjectMetadata,
  saveProjectMetadata,
  deleteProject,
  updateCheckState,
  addEvidence,
  removeEvidence,
  updateCVSS,
  updateCWE,
  updateMitreAttack,
  updateNote,
  getChecksWithState,
  calculateStatistics
};
