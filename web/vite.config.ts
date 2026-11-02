import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the UI talks to a local daemon on :7600.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:7600", ws: true },
    },
  },
});
