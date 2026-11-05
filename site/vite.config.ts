import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import adapter from "@sveltejs/adapter-static";
import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig, type Connect, type Plugin } from "vite";

// In dev and preview, serve a local build at /latest/ and /builds/<sequence>/,
// as R2 does next to the published site. OPENCRLSET_OUT picks the build.
const out = resolve(process.env.OPENCRLSET_OUT ?? "../out");

const TYPES: Record<string, string> = {
  ".json": "application/json",
  ".ndjson": "application/x-ndjson",
  ".gz": "application/gzip",
};

const serveBuild: Connect.NextHandleFunction = async (request, response: ServerResponse, next) => {
  const path = new URL(request.url ?? "/", "http://localhost").pathname;
  const relative = path.match(/^\/(?:latest|builds\/\d+)\/(.*)$/)?.[1];
  if (relative === undefined) return next();
  const file = normalize(join(out, decodeURIComponent(relative)));
  if (!file.startsWith(out + sep) || !(await stat(file).catch(() => null))?.isFile()) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(response);
};

const localBuild: Plugin = {
  name: "opencrlset-local-build",
  configureServer: (server) => void server.middlewares.use(serveBuild),
  configurePreviewServer: (server) => void server.middlewares.use(serveBuild),
};

export default defineConfig({
  // any Host header, so tunnels (e.g. trycloudflare.com) can reach dev and preview
  server: { allowedHosts: true },
  preview: { allowedHosts: true },
  plugins: [
    sveltekit({
      compilerOptions: {
        runes: ({ filename }) =>
          filename.split(/[/\\]/).includes("node_modules") ? undefined : true,
      },
      // a static page on R2, so routes live in the URL's hash
      adapter: adapter({ strict: true }),
      router: { type: "hash" },
    }),
    localBuild,
  ],
});
