import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Pas de source maps publiées en production : on n'expose pas le code source.
    sourcemap: false,
    // Aucun script inline dans index.html -> compatible avec une CSP sans 'unsafe-inline'.
    assetsInlineLimit: 0,
  },
  server: {
    // En développement uniquement : même principe « même origine » qu'en prod.
    proxy: { "/api": "http://localhost:8000" },
  },
});
// GROGNON
