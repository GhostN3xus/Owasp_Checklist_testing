import { describe, it, expect } from 'vitest';
import { calculateProgress, renderStatusBadge } from './logic.js';

describe('calculateProgress', () => {
  it('should return 0% for no items', () => {
    expect(calculateProgress([])).toEqual({ total: 0, completed: 0, percent: 0 });
  });

  it('should return 0% for no completed items', () => {
    const items = [{ checked: false }, { checked: false }];
    expect(calculateProgress(items)).toEqual({ total: 2, completed: 0, percent: 0 });
  });

  it('should return 100% for all completed items', () => {
    const items = [{ checked: true }, { checked: true }];
    expect(calculateProgress(items)).toEqual({ total: 2, completed: 2, percent: 100 });
  });

  it('should return 50% for half completed items', () => {
    const items = [{ checked: true }, { checked: false }];
    expect(calculateProgress(items)).toEqual({ total: 2, completed: 1, percent: 50 });
  });
});

describe('renderStatusBadge', () => {
  it('should return "Passou" badge for "passed" status', () => {
    expect(renderStatusBadge('passed')).toBe('<span class="badge badge-passed">Passou</span>');
  });

  it('should return "Falhou" badge for "failed" status', () => {
    expect(renderStatusBadge('failed')).toBe('<span class="badge badge-failed">Falhou</span>');
  });

  it('should return "N/A" badge for "na" status', () => {
    expect(renderStatusBadge('na')).toBe('<span class="badge badge-na">N/A</span>');
  });

  it('should return a default badge for other statuses', () => {
    expect(renderStatusBadge('unknown')).toBe('<span class="badge badge-empty">--</span>');
  });
});
