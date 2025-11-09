/**
 * Standards CSV Loader Module
 * Loads and manages ASVS, MASVS, API 2023, WSTG standards
 * @license ISC
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STANDARDS_DIR = path.join(__dirname, '..', 'content', 'standards');

/**
 * Parse CSV string to array of objects
 * @param {string} csv - CSV content
 * @param {Array<string>} headers - Column headers
 * @returns {Array<Object>} - Array of row objects
 */
function parseCSV(csv, headers) {
  const lines = csv.trim().split('\n');
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    const cells = [];
    let currentCell = '';
    let inQuotes = false;

    for (let j = 0; j < line.length; j++) {
      const char = line[j];
      const nextChar = line[j + 1];

      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        cells.push(currentCell.trim());
        currentCell = '';
      } else {
        currentCell += char;
      }
    }
    cells.push(currentCell.trim());

    const row = {};
    headers.forEach((header, index) => {
      row[header] = cells[index] || '';
    });
    rows.push(row);
  }

  return rows;
}

/**
 * Load a standards CSV file
 * @param {string} filename - Filename (e.g., 'asvs.csv')
 * @returns {Promise<Object>} - { headers, data }
 */
async function loadStandard(filename) {
  const filePath = path.join(STANDARDS_DIR, filename);
  const content = await fs.readFile(filePath, 'utf8');
  const lines = content.trim().split('\n');
  const headers = lines[0].split(',').map(h => h.trim());
  const data = parseCSV(content, headers);

  return { headers, data };
}

/**
 * Load all standards
 * @returns {Promise<Object>} - Object with all standards
 */
export async function loadAllStandards() {
  const standards = {};

  try {
    standards.asvs = await loadStandard('asvs.csv');
    standards.masvs = await loadStandard('masvs.csv');
    standards.api = await loadStandard('api_2023.csv');
    standards.wstg = await loadStandard('wstg.csv');
  } catch (error) {
    console.error('Error loading standards:', error);
  }

  return standards;
}

/**
 * Search standards by ID or title
 * @param {Object} standards - Loaded standards
 * @param {string} query - Search query
 * @returns {Array<Object>} - Matching items with standard name
 */
export function searchStandards(standards, query) {
  const results = [];
  const q = query.toLowerCase();

  ['asvs', 'masvs', 'api', 'wstg'].forEach(stdName => {
    if (!standards[stdName]) return;

    standards[stdName].data.forEach(item => {
      if (
        item.ID.toLowerCase().includes(q) ||
        item.Title.toLowerCase().includes(q) ||
        item.Description.toLowerCase().includes(q)
      ) {
        results.push({
          standard: stdName.toUpperCase(),
          ...item
        });
      }
    });
  });

  return results;
}

/**
 * Get standard by ID
 * @param {Object} standards - Loaded standards
 * @param {string} id - Item ID
 * @returns {Object|null} - Item with standard name or null
 */
export function getStandardById(standards, id) {
  for (const stdName of ['asvs', 'masvs', 'api', 'wstg']) {
    if (!standards[stdName]) continue;

    const item = standards[stdName].data.find(row => row.ID === id);
    if (item) {
      return {
        standard: stdName.toUpperCase(),
        ...item
      };
    }
  }

  return null;
}

/**
 * Get all items from a standard
 * @param {Object} standards - Loaded standards
 * @param {string} standardName - Standard name (asvs, masvs, api, wstg)
 * @returns {Array<Object>} - Items from standard
 */
export function getStandard(standards, standardName) {
  const std = standards[standardName.toLowerCase()];
  if (!std) return [];

  return std.data.map(item => ({
    standard: standardName.toUpperCase(),
    ...item
  }));
}

/**
 * Extract tags from a standard item
 * @param {Object} item - Standard item
 * @returns {Array<string>} - Tags
 */
export function extractTags(item) {
  const tags = [];

  if (item.Tags) {
    tags.push(...item.Tags.split(',').map(t => t.trim()).filter(t => t));
  }

  if (item.Category) {
    tags.push(item.Category);
  }

  if (item.Risk) {
    tags.push(item.Risk);
  }

  return [...new Set(tags)];
}

/**
 * Calculate risk score (High=3, Medium=2, Low=1)
 * @param {string} risk - Risk level
 * @returns {number} - Risk score
 */
export function getRiskScore(risk) {
  const scores = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1
  };
  return scores[risk] || 0;
}

export default {
  loadAllStandards,
  searchStandards,
  getStandardById,
  getStandard,
  extractTags,
  getRiskScore
};
