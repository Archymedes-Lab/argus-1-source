import { defineConfig, type Plugin } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync } from "node:fs";

// Development only: `JARVIS_UI_FIXTURE=/path/state.json bun run dev` serves a
// saved /api/state document so the interface can be designed and screenshot
// in a plain browser. Never part of a build; the app talks to Rust commands.
function fixture(): Plugin {
  return {
    name: "jarvis-fixture",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/__fixture/state.json", (_req, res) => {
        const path = process.env.JARVIS_UI_FIXTURE;
        if (!path) { res.statusCode = 404; res.end("{}"); return; }
        res.setHeader("Content-Type", "application/json");
        res.end(readFileSync(path));
      });
      // JARVIS_UI_LICENCE_FIXTURE=/path/licence.json: a saved GET /api/licence answer for the Licence view.
      server.middlewares.use("/__fixture/licence.json", (_req, res) => {
        const path = process.env.JARVIS_UI_LICENCE_FIXTURE;
        if (!path) { res.statusCode = 404; res.end("{}"); return; }
        res.setHeader("Content-Type", "application/json");
        res.end(readFileSync(path));
      });
    },
  };
}

export default defineConfig({
  plugins: [svelte(), tailwindcss(), fixture()],
  clearScreen: false,
  server: { port: 5199, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", outDir: "dist", emptyOutDir: true, assetsInlineLimit: 0, sourcemap: false },
});
