import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({ include: ["buffer", "events", "stream", "util"] }),
  ],
  define: {
    global: "globalThis",
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:3100",
    },
  },
});
