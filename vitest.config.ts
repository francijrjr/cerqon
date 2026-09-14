import { defineConfig } from "vitest/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@cerqon/types": path.resolve(__dirname, "packages/types/src/index.ts"),
      "@cerqon/core": path.resolve(__dirname, "packages/core/src/index.ts"),
      "@cerqon/adapters": path.resolve(__dirname, "packages/adapters/src/index.ts"),
      "@cerqon/risk-engine": path.resolve(__dirname, "packages/risk-engine/src/index.ts"),
      "@cerqon/policy-engine": path.resolve(__dirname, "packages/policy-engine/src/index.ts"),
      "@cerqon/reporters": path.resolve(__dirname, "packages/reporters/src/index.ts"),
      "@cerqon/scanner": path.resolve(__dirname, "packages/scanner/src/index.ts"),
    },
  },
  test: {
    globals: true,
  },
});
