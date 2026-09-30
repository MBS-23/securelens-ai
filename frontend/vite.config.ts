import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The API is served from the same origin (/api) in every environment: the dev
// server proxies it, and the production container's nginx does the same. The
// session cookie is SameSite=Strict and scoped to /api, so the browser never
// sends it cross-site.
const api = process.env.SECURELENS_API_URL ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { "/api": { target: api, changeOrigin: false } },
  },
  preview: {
    port: 4173,
    proxy: { "/api": { target: api, changeOrigin: false } },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 4000,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.{ts,tsx}"],
  },
});
