import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/_counterprompt/",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/_counterprompt/api": "http://127.0.0.1:8080",
      "/_counterprompt/ws": { target: "ws://127.0.0.1:8080", ws: true },
    },
  },
});
