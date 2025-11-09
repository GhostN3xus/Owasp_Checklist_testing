/**
 * AES-GCM Encryption/Decryption Module
 * Uses PBKDF2 for key derivation (200k iterations)
 * @license ISC
 */

import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

const ALGORITHM = 'aes-256-gcm';
const PBKDF2_ITERATIONS = 200000;
const PBKDF2_DIGEST = 'sha256';
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

/**
 * Derive a 256-bit key from password using PBKDF2
 * @param {string} password - User password
 * @param {Buffer} salt - Random salt (32 bytes)
 * @returns {Buffer} - Derived key (32 bytes)
 */
export function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    32,
    PBKDF2_DIGEST
  );
}

/**
 * Encrypt plaintext using AES-256-GCM
 * @param {Buffer|string} plaintext - Data to encrypt
 * @param {string} password - Password for encryption
 * @returns {Object} - { salt (hex), iv (hex), ciphertext (hex), authTag (hex) }
 */
export function encrypt(plaintext, password) {
  if (typeof plaintext === 'string') {
    plaintext = Buffer.from(plaintext, 'utf8');
  }

  // Generate random salt and IV
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  // Derive key from password
  const key = deriveKey(password, salt);

  // Encrypt
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  return {
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    ciphertext: encrypted.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Decrypt ciphertext using AES-256-GCM
 * @param {Object} encrypted - { salt, iv, ciphertext, authTag } as hex strings
 * @param {string} password - Password for decryption
 * @returns {Buffer} - Decrypted data
 * @throws {Error} - If decryption fails or authentication fails
 */
export function decrypt(encrypted, password) {
  try {
    const salt = Buffer.from(encrypted.salt, 'hex');
    const iv = Buffer.from(encrypted.iv, 'hex');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'hex');
    const authTag = Buffer.from(encrypted.authTag, 'hex');

    // Derive key from password
    const key = deriveKey(password, salt);

    // Decrypt
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);

    return decrypted;
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

/**
 * Encrypt data and write to file
 * @param {string} filePath - File path to write to
 * @param {Buffer|string} plaintext - Data to encrypt
 * @param {string} password - Password for encryption
 */
export async function encryptToFile(filePath, plaintext, password) {
  const encrypted = encrypt(plaintext, password);
  await fs.writeFile(
    filePath,
    JSON.stringify(encrypted, null, 2),
    'utf8'
  );
}

/**
 * Read encrypted file and decrypt
 * @param {string} filePath - File path to read from
 * @param {string} password - Password for decryption
 * @returns {Buffer} - Decrypted data
 */
export async function decryptFromFile(filePath, password) {
  const content = await fs.readFile(filePath, 'utf8');
  const encrypted = JSON.parse(content);
  return decrypt(encrypted, password);
}

/**
 * Encrypt file contents (binary or text) and write alongside metadata
 * @param {string} inputPath - Input file path
 * @param {string} outputPath - Output file path (will create .enc and .meta files)
 * @param {string} password - Password for encryption
 */
export async function encryptFile(inputPath, outputPath, password) {
  const fileData = await fs.readFile(inputPath);
  const encrypted = encrypt(fileData, password);

  // Write metadata (salt, iv, authTag)
  const metaPath = outputPath + '.meta';
  await fs.writeFile(
    metaPath,
    JSON.stringify({
      salt: encrypted.salt,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      originalName: path.basename(inputPath)
    }, null, 2),
    'utf8'
  );

  // Write encrypted data
  await fs.writeFile(outputPath, Buffer.from(encrypted.ciphertext, 'hex'));
}

/**
 * Decrypt file using metadata
 * @param {string} encryptedPath - Path to encrypted file
 * @param {string} metaPath - Path to metadata file
 * @param {string} password - Password for decryption
 * @returns {Buffer} - Decrypted data
 */
export async function decryptFile(encryptedPath, metaPath, password) {
  const ciphertext = await fs.readFile(encryptedPath);
  const metaContent = await fs.readFile(metaPath, 'utf8');
  const meta = JSON.parse(metaContent);

  return decrypt({
    salt: meta.salt,
    iv: meta.iv,
    ciphertext: ciphertext.toString('hex'),
    authTag: meta.authTag
  }, password);
}

export default {
  deriveKey,
  encrypt,
  decrypt,
  encryptToFile,
  decryptFromFile,
  encryptFile,
  decryptFile,
  ALGORITHM,
  PBKDF2_ITERATIONS,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH
};
