import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: "happy-dom",
    include: ["tests/**/*.component.test.ts"],
    setupFiles: ["tests/vitest.setup.ts"],
    restoreMocks: true,
  },
});
