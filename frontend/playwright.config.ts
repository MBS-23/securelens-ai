import { defineConfig, devices } from "@playwright/test";

// End-to-end tests run the real stack: a fresh SQLite database, the FastAPI
// server and the production build of the dashboard. Nothing is mocked.
const API_PORT = Number(process.env.SECURELENS_E2E_API_PORT ?? 8765);
const WEB_PORT = Number(process.env.SECURELENS_E2E_WEB_PORT ?? 4180);
const PYTHON = process.env.SECURELENS_E2E_PYTHON ?? ".venv/bin/python"; // relative to ../backend
const DATABASE = process.env.SECURELENS_E2E_DATABASE_URL ?? `sqlite:////tmp/securelens-e2e-${process.pid}.db`;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  timeout: 60_000,
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      cwd: "../backend",
      command: `${PYTHON} -m securelens.manage migrate && ${PYTHON} -m uvicorn securelens.main:app --host 127.0.0.1 --port ${API_PORT}`,
      url: `http://127.0.0.1:${API_PORT}/api/v1/healthz`,
      env: {
        SECURELENS_DATABASE_URL: DATABASE,
        SECURELENS_SECRET_KEY: "e2e-only-secret-key-not-for-production-use-0123456789",
        SECURELENS_ENVIRONMENT: "development",
      },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npm run build && npx vite preview --host 127.0.0.1 --port ${WEB_PORT} --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}`,
      env: { SECURELENS_API_URL: `http://127.0.0.1:${API_PORT}` },
      reuseExistingServer: false,
      timeout: 180_000,
    },
  ],
});
