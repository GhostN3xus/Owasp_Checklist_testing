/**
 * Migration Script: Plaintext to Encrypted Projects
 * Converts existing plaintext project files to encrypted format
 * @license ISC
 */

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import readline from 'readline';
import { encryptToFile } from '../server/crypto/aesgcm.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '..', 'data');

/**
 * Create readline interface for prompts
 */
function createPrompt() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
}

/**
 * Prompt user for input
 */
function promptUser(question) {
  return new Promise((resolve) => {
    const rl = createPrompt();
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Prompt for password (hidden input)
 */
async function promptPassword(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question(question, (password) => {
      rl.close();
      resolve(password);
    });
  });
}

/**
 * Check if file is plaintext JSON
 */
async function isPlaintextProject(projectDir) {
  try {
    const stateFile = path.join(projectDir, 'state.json');
    const content = await fs.readFile(stateFile, 'utf8');
    const json = JSON.parse(content);

    // Check if it has project structure
    return json.id && json.name && !json.salt;
  } catch (error) {
    return false;
  }
}

/**
 * List all plaintext projects
 */
async function listPlaintextProjects() {
  try {
    const entries = await fs.readdir(DATA_DIR, { withFileTypes: true });
    const plaintextProjects = [];

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const isPlaintext = await isPlaintextProject(path.join(DATA_DIR, entry.name));
        if (isPlaintext) {
          plaintextProjects.push(entry.name);
        }
      }
    }

    return plaintextProjects;
  } catch (error) {
    return [];
  }
}

/**
 * Migrate a single project
 */
async function migrateProject(projectId, password) {
  try {
    const projectDir = path.join(DATA_DIR, projectId);
    const stateFile = path.join(projectDir, 'state.json');
    const backupFile = path.join(projectDir, 'state.json.backup');

    // Read plaintext state
    const content = await fs.readFile(stateFile, 'utf8');
    const state = JSON.parse(content);

    // Create backup
    await fs.copyFile(stateFile, backupFile);
    console.log(`  ✓ Backup created: state.json.backup`);

    // Encrypt and save
    await encryptToFile(stateFile, JSON.stringify(state, null, 2), password);
    console.log(`  ✓ Project encrypted and saved`);

    // Verify encrypted file
    const verifyContent = await fs.readFile(stateFile, 'utf8');
    const encrypted = JSON.parse(verifyContent);

    if (encrypted.salt && encrypted.iv && encrypted.ciphertext && encrypted.authTag) {
      console.log(`  ✓ Encryption verified`);
      return true;
    } else {
      throw new Error('Encryption verification failed');
    }
  } catch (error) {
    console.error(`  ✗ Migration failed: ${error.message}`);
    return false;
  }
}

/**
 * Main migration function
 */
async function main() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  📦 AppSec Checklist - Project Migration Tool');
  console.log('  Plaintext → Encrypted (AES-256-GCM with PBKDF2)');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    // Check if data directory exists
    await fs.access(DATA_DIR);
  } catch (error) {
    console.log('✗ Data directory not found. No projects to migrate.\n');
    process.exit(0);
  }

  // List plaintext projects
  console.log('🔍 Scanning for plaintext projects...\n');
  const plaintextProjects = await listPlaintextProjects();

  if (plaintextProjects.length === 0) {
    console.log('✓ No plaintext projects found. All projects are encrypted.\n');
    process.exit(0);
  }

  console.log(`Found ${plaintextProjects.length} plaintext project(s):\n`);
  plaintextProjects.forEach((id, index) => {
    console.log(`  ${index + 1}. ${id}`);
  });
  console.log('');

  // Ask for confirmation
  const confirm = await promptUser('Proceed with migration? (yes/no): ');
  if (confirm.toLowerCase() !== 'yes' && confirm.toLowerCase() !== 'y') {
    console.log('\n✗ Migration cancelled.\n');
    process.exit(0);
  }

  console.log('');

  let successCount = 0;
  let failureCount = 0;

  // Migrate each project
  for (const projectId of plaintextProjects) {
    console.log(`📦 Migrating project: ${projectId}`);

    const password = await promptPassword('  Enter encryption password: ');
    const confirmPassword = await promptPassword('  Confirm password: ');

    if (password !== confirmPassword) {
      console.log('  ✗ Passwords do not match. Skipping.\n');
      failureCount++;
      continue;
    }

    if (password.length < 8) {
      console.log('  ✗ Password must be at least 8 characters. Skipping.\n');
      failureCount++;
      continue;
    }

    const success = await migrateProject(projectId, password);
    console.log('');

    if (success) {
      successCount++;
    } else {
      failureCount++;
    }
  }

  // Summary
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`  ✓ Migration Summary`);
  console.log(`  Successful: ${successCount}/${plaintextProjects.length}`);
  console.log(`  Failed: ${failureCount}/${plaintextProjects.length}`);
  console.log('═══════════════════════════════════════════════════════════════\n');

  if (failureCount === 0) {
    console.log('✓ All projects migrated successfully!\n');
  } else {
    console.log('⚠ Some projects failed to migrate. Check logs above.\n');
  }
}

// Run migration
main().catch(error => {
  console.error('Fatal error:', error.message);
  process.exit(1);
});
