/**
 * CVSS Calculator Tests
 * @license ISC
 */

import { describe, it, expect } from 'vitest';
import {
  parseVector,
  calculateBaseScore,
  calculateScore,
  getSeverity,
  isValidVector
} from '../server/cvss-calculator.js';

describe('CVSS Vector Parsing', () => {
  it('should parse valid vector', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const metrics = parseVector(vector);

    expect(metrics.AV).toBe('N');
    expect(metrics.AC).toBe('L');
    expect(metrics.PR).toBe('N');
    expect(metrics.UI).toBe('N');
    expect(metrics.S).toBe('U');
    expect(metrics.C).toBe('H');
    expect(metrics.I).toBe('H');
    expect(metrics.A).toBe('H');
  });

  it('should handle temporal metrics', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:T/RC:C';
    const metrics = parseVector(vector);

    expect(metrics.E).toBe('P');
    expect(metrics.RL).toBe('T');
    expect(metrics.RC).toBe('C');
  });

  it('should handle environmental metrics', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H';
    const metrics = parseVector(vector);

    expect(metrics.CR).toBe('H');
    expect(metrics.IR).toBe('H');
    expect(metrics.AR).toBe('H');
  });
});

describe('Base Score Calculation', () => {
  it('should calculate critical vulnerability', () => {
    const metrics = {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S: 'U',
      C: 'H',
      I: 'H',
      A: 'H'
    };

    const score = calculateBaseScore(metrics);
    expect(score).toBe(9.8);
  });

  it('should calculate high severity', () => {
    const metrics = {
      AV: 'N',
      AC: 'L',
      PR: 'L',
      UI: 'N',
      S: 'U',
      C: 'H',
      I: 'H',
      A: 'N'
    };

    const score = calculateBaseScore(metrics);
    expect(score).toBeGreaterThan(7);
    expect(score).toBeLessThan(9);
  });

  it('should calculate medium severity', () => {
    const metrics = {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S: 'U',
      C: 'H',
      I: 'N',
      A: 'N'
    };

    const score = calculateBaseScore(metrics);
    expect(score).toBeGreaterThan(4);
    expect(score).toBeLessThan(7);
  });

  it('should calculate low severity', () => {
    const metrics = {
      AV: 'N',
      AC: 'H',
      PR: 'H',
      UI: 'R',
      S: 'U',
      C: 'L',
      I: 'N',
      A: 'N'
    };

    const score = calculateBaseScore(metrics);
    expect(score).toBeLessThan(4);
  });

  it('should calculate no impact', () => {
    const metrics = {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S: 'U',
      C: 'N',
      I: 'N',
      A: 'N'
    };

    const score = calculateBaseScore(metrics);
    expect(score).toBe(0);
  });

  it('should handle scope change', () => {
    const unchangedScore = calculateBaseScore({
      AV: 'N',
      AC: 'L',
      PR: 'L',
      UI: 'N',
      S: 'U',
      C: 'H',
      I: 'H',
      A: 'H'
    });

    const changedScore = calculateBaseScore({
      AV: 'N',
      AC: 'L',
      PR: 'L',
      UI: 'N',
      S: 'C',
      C: 'H',
      I: 'H',
      A: 'H'
    });

    expect(changedScore).toBeGreaterThan(unchangedScore);
  });
});

describe('Full Score Calculation', () => {
  it('should calculate full CVSS score', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const result = calculateScore(vector);

    expect(result.baseScore).toBe(9.8);
    expect(result.temporalScore).toBeLessThanOrEqual(9.8);
    expect(result.environmentalScore).toBeLessThanOrEqual(9.8);
  });

  it('should return zeros for invalid vector', () => {
    const result = calculateScore('invalid');

    expect(result.baseScore).toBe(0);
    expect(result.temporalScore).toBe(0);
    expect(result.environmentalScore).toBe(0);
  });

  it('should handle empty vector', () => {
    const result = calculateScore('');

    expect(result.baseScore).toBe(0);
  });

  it('should handle null vector', () => {
    const result = calculateScore(null);

    expect(result.baseScore).toBe(0);
  });
});

describe('Severity Ratings', () => {
  it('should rate none', () => {
    expect(getSeverity(0)).toBe('None');
  });

  it('should rate low', () => {
    expect(getSeverity(1)).toBe('Low');
    expect(getSeverity(3.9)).toBe('Low');
  });

  it('should rate medium', () => {
    expect(getSeverity(4)).toBe('Medium');
    expect(getSeverity(6.9)).toBe('Medium');
  });

  it('should rate high', () => {
    expect(getSeverity(7)).toBe('High');
    expect(getSeverity(8.9)).toBe('High');
  });

  it('should rate critical', () => {
    expect(getSeverity(9)).toBe('Critical');
    expect(getSeverity(10)).toBe('Critical');
  });
});

describe('Vector Validation', () => {
  it('should validate correct vector', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    expect(isValidVector(vector)).toBe(true);
  });

  it('should reject invalid metrics', () => {
    const vector = 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    expect(isValidVector(vector)).toBe(false);
  });

  it('should reject missing CVSS prefix', () => {
    const vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    expect(isValidVector(vector)).toBe(false);
  });

  it('should reject null vector', () => {
    expect(isValidVector(null)).toBe(false);
  });

  it('should reject non-string vector', () => {
    expect(isValidVector(123)).toBe(false);
  });

  it('should reject empty string', () => {
    expect(isValidVector('')).toBe(false);
  });

  it('should validate with temporal metrics', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:T/RC:C';
    expect(isValidVector(vector)).toBe(true);
  });

  it('should validate with environmental metrics', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:H';
    expect(isValidVector(vector)).toBe(true);
  });
});

describe('Real-world Vectors', () => {
  it('should calculate SQL injection', () => {
    // SQL injection in web app
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const result = calculateScore(vector);

    expect(result.baseScore).toBe(9.8);
    expect(getSeverity(result.baseScore)).toBe('Critical');
  });

  it('should calculate XSS vulnerability', () => {
    // XSS requiring user interaction
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
    const result = calculateScore(vector);

    expect(result.baseScore).toBeGreaterThan(5);
    expect(getSeverity(result.baseScore)).toBe('Medium');
  });

  it('should calculate local privilege escalation', () => {
    // Local priv esc
    const vector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
    const result = calculateScore(vector);

    expect(result.baseScore).toBeGreaterThan(7);
    expect(getSeverity(result.baseScore)).toBe('High');
  });
});
