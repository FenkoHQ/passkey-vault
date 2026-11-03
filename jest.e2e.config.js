// End-to-end tests in a real Chromium with the built extension. They need a
// local Chrome and openssl, so `npm test` leaves them out; run
// `npm run test:e2e:webauthn` (which builds dist/ first).
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/tests/e2e/**/*.e2e.ts'],
  testTimeout: 120000,
  maxWorkers: 1,
};
