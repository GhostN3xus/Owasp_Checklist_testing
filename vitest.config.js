/**
 * Vitest Configuration
 * @license ISC
 */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.test.js'
      ],
      lines: 80,
      functions: 80,
      branches: 80,
      statements: 80
    },
    include: ['tests/**/*.test.js'],
    exclude: ['node_modules', 'dist'],
    testTimeout: 10000
  }
});
