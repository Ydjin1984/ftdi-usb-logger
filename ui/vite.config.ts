import { defineConfig } from "vite";

// UI всегда живёт рядом с движком: dev-режим проксирует REST/WS на 127.0.0.1:7811,
// release-сборка кладётся в ui/dist и раздаётся тем же движком.
export default defineConfig({
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: "http://127.0.0.1:7811", changeOrigin: false },
      "/ws": { target: "ws://127.0.0.1:7811", ws: true },
    },
  },
});
