import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server on 6173 (verified free — avoids all prod/listening ports).
// /api is proxied to the Intent-Aware FastAPI (default :8000) so the browser
// never hits CORS; override the backend with VITE_API_TARGET.
export default defineConfig({
  // Served under a sub-path on the test vhost (https://espace-v3-test.gridcrm.fr/intent-aware/).
  // Dev stays at "/"; the deploy build sets VITE_BASE=/intent-aware/.
  base: process.env.VITE_BASE || "/",
  plugins: [react()],
  // A single React instance, always. The lazy 3D chunk pulls in react-three-fiber,
  // and without this React would be duplicated into that chunk → "Invalid hook
  // call" (#321) and a blank page. Dedupe + a shared react-vendor chunk fix it.
  resolve: { dedupe: ["react", "react-dom"] },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes("node_modules")) {
            if (/[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return "react-vendor";
            if (id.includes("three") || id.includes("@react-three")) return "three-vendor";
          }
        },
      },
    },
  },
  server: {
    port: 6173,
    host: "127.0.0.1",
    strictPort: true,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
  preview: { port: 6173, host: "127.0.0.1", strictPort: true },
});
