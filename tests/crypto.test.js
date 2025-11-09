/**
 * Crypto Module Tests
 * @license ISC
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  encrypt,
  decrypt,
  deriveKey,
  isValidVector
} from '../server/crypto/aesgcm.js';

describe('AES-GCM Encryption', () => {
  const password = 'secure-password-123456';
  const plaintext = 'sensitive data';

  it('should encrypt plaintext buffer', () => {
    const encrypted = encrypt(Buffer.from(plaintext), password);

    expect(encrypted).toHaveProperty('salt');
    expect(encrypted).toHaveProperty('iv');
    expect(encrypted).toHaveProperty('ciphertext');
    expect(encrypted).toHaveProperty('authTag');
  });

  it('should encrypt plaintext string', () => {
    const encrypted = encrypt(plaintext, password);

    expect(encrypted.ciphertext).toBeDefined();
    expect(typeof encrypted.ciphertext).toBe('string');
  });

  it('should decrypt encrypted data', () => {
    const encrypted = encrypt(plaintext, password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe(plaintext);
  });

  it('should fail with wrong password', () => {
    const encrypted = encrypt(plaintext, password);

    expect(() => {
      decrypt(encrypted, 'wrong-password');
    }).toThrow('Decryption failed');
  });

  it('should fail with corrupted ciphertext', () => {
    const encrypted = encrypt(plaintext, password);
    encrypted.ciphertext = 'corrupted-data';

    expect(() => {
      decrypt(encrypted, password);
    }).toThrow('Decryption failed');
  });

  it('should fail with corrupted auth tag', () => {
    const encrypted = encrypt(plaintext, password);
    encrypted.authTag = 'aaaaaaaaaaaaaaaa'; // Wrong auth tag

    expect(() => {
      decrypt(encrypted, password);
    }).toThrow('Decryption failed');
  });

  it('should generate unique salts', () => {
    const encrypted1 = encrypt(plaintext, password);
    const encrypted2 = encrypt(plaintext, password);

    expect(encrypted1.salt).not.toBe(encrypted2.salt);
  });

  it('should generate unique IVs', () => {
    const encrypted1 = encrypt(plaintext, password);
    const encrypted2 = encrypt(plaintext, password);

    expect(encrypted1.iv).not.toBe(encrypted2.iv);
  });

  it('should handle large data', () => {
    const largeData = 'x'.repeat(10000);
    const encrypted = encrypt(largeData, password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe(largeData);
  });

  it('should handle special characters', () => {
    const specialChars = '!@#$%^&*()_+-=[]{}|;:",.<>?/~`™£¢∞§';
    const encrypted = encrypt(specialChars, password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe(specialChars);
  });

  it('should handle unicode characters', () => {
    const unicode = '你好世界 مرحبا بالعالم Привет мир';
    const encrypted = encrypt(unicode, password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe(unicode);
  });

  it('should handle empty string', () => {
    const encrypted = encrypt('', password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe('');
  });
});

describe('Key Derivation', () => {
  it('should derive same key from same password and salt', () => {
    const password = 'test-password';
    const salt = Buffer.from('a'.repeat(64), 'hex');

    const key1 = deriveKey(password, salt);
    const key2 = deriveKey(password, salt);

    expect(key1.toString('hex')).toBe(key2.toString('hex'));
  });

  it('should derive different keys from different passwords', () => {
    const salt = Buffer.from('a'.repeat(64), 'hex');

    const key1 = deriveKey('password1', salt);
    const key2 = deriveKey('password2', salt);

    expect(key1.toString('hex')).not.toBe(key2.toString('hex'));
  });

  it('should derive 32-byte key', () => {
    const key = deriveKey('password', Buffer.from('a'.repeat(64), 'hex'));

    expect(key.length).toBe(32);
  });
});

describe('Edge Cases', () => {
  it('should handle very long password', () => {
    const longPassword = 'x'.repeat(1000);
    const encrypted = encrypt('data', longPassword);
    const decrypted = decrypt(encrypted, longPassword);

    expect(decrypted.toString('utf8')).toBe('data');
  });

  it('should be case-sensitive for passwords', () => {
    const encrypted = encrypt('data', 'Password');

    expect(() => {
      decrypt(encrypted, 'password');
    }).toThrow('Decryption failed');
  });

  it('should handle whitespace in password', () => {
    const password = '  password with spaces  ';
    const encrypted = encrypt('data', password);
    const decrypted = decrypt(encrypted, password);

    expect(decrypted.toString('utf8')).toBe('data');
  });
});
