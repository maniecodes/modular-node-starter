import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: './src',
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: './tsconfig.test.json' }],
  },
  setupFiles: ['<rootDir>/../jest.setup.ts'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    '^@/core/(.*)$': '<rootDir>/core/$1',
    '^@/common/(.*)$': '<rootDir>/common/$1',
    '^@/modules/(.*)$': '<rootDir>/modules/$1',
  },
  coverageDirectory: '../coverage',
  collectCoverageFrom: ['**/*.ts', '!**/__tests__/**', '!**/index.ts'],
  clearMocks: true,
};

export default config;
