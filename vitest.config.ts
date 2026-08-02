import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
export default defineConfig({
    test: {
        name: "testing",
        root: resolve(here),
        include: ["tests/**/*.test.ts"],
        environment: "node",
        globals: false,
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: "v8",
            include: ["src/**/*.ts"],
            all: true,
            reporter: ["text", "html", "json-summary"],
        },
    },
});
