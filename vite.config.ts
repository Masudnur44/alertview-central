import path from "node:path";
import { defineConfig } from "vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import tsConfigPaths from "vite-tsconfig-paths";
import { nitro } from "nitro/vite";

// Self-hosted build: `vite build` emits a Node server in .output/ (run with `npm start`).
export default defineConfig(({ command }) => ({
  server: { host: "::", port: 8080, allowedHosts: [".app.github.dev", ".githubpreview.dev", "localhost"] },
  resolve: {
    alias: { "@": path.resolve(process.cwd(), "src") },
    dedupe: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime", "@tanstack/react-query", "@tanstack/query-core"],
  },
  plugins: [
    tsConfigPaths({ projects: ["./tsconfig.json"] }),
    tanstackStart({
      // Route the server entry through src/server.ts (SSR error wrapper + security headers).
      server: { entry: "server" },
    }),
    ...(command === "build" ? [nitro({ preset: "node-server" })] : []),
    viteReact(),
    tailwindcss(),
  ],
}));
