// Lightweight local dev server for BreachLens.
// Serves the static frontend from /public and routes /api/scan and /api/chat to
// the Netlify v2 functions (Web Request/Response), preserving streaming.
// No Netlify CLI / edge-function bootstrap needed.
//
// Run:  node --env-file=.env scripts/dev-server.mjs
//   (or without --env-file to exercise the deterministic fallback)

import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import scan from "../netlify/functions/scan.js";
import chat from "../netlify/functions/chat.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");
const PORT = process.env.PORT || 8888;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
};

// Read the raw request body into a Buffer.
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", () => resolve(Buffer.alloc(0)));
  });
}

// Convert a Node request into a Web Request, invoke the function, and pipe the
// (possibly streaming) Web Response back to the Node response.
async function handleFunction(handler, req, res) {
  const bodyBuf = await readBody(req);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === "string") headers.set(k, v);
    else if (Array.isArray(v)) headers.set(k, v.join(", "));
  }

  const request = new Request(`http://localhost:${PORT}${req.url}`, {
    method: req.method,
    headers,
    body: ["GET", "HEAD"].includes(req.method) ? undefined : bodyBuf,
  });

  let response;
  try {
    response = await handler(request);
  } catch (e) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Function crashed: " + e.message }));
    return;
  }

  const outHeaders = {};
  response.headers.forEach((v, k) => (outHeaders[k] = v));
  res.writeHead(response.status, outHeaders);

  if (!response.body) {
    res.end();
    return;
  }

  // Stream the ReadableStream body chunk-by-chunk so NDJSON progress flushes live.
  const reader = response.body.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
  } catch (_) {
    /* client disconnected */
  }
  res.end();
}

async function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split("?")[0]);
  if (urlPath === "/" || urlPath === "") urlPath = "/index.html";

  let filePath = path.join(PUBLIC_DIR, urlPath);
  // prevent path traversal
  if (!filePath.startsWith(PUBLIC_DIR)) filePath = path.join(PUBLIC_DIR, "index.html");

  try {
    const data = await readFile(filePath);
    const ext = path.extname(filePath);
    res.writeHead(200, { "content-type": MIME[ext] || "application/octet-stream" });
    res.end(data);
  } catch (_) {
    // SPA fallback
    try {
      const fallback = await readFile(path.join(PUBLIC_DIR, "index.html"));
      res.writeHead(200, { "content-type": MIME[".html"] });
      res.end(fallback);
    } catch (e) {
      res.writeHead(404);
      res.end("Not found");
    }
  }
}

const server = http.createServer(async (req, res) => {
  const pathname = req.url.split("?")[0];
  if (pathname === "/api/scan") return handleFunction(scan, req, res);
  if (pathname === "/api/chat") return handleFunction(chat, req, res);
  return serveStatic(req, res);
});

server.listen(PORT, () => {
  const key = process.env.OPENAI_API_KEY ? "OPENAI_API_KEY set ✓" : "no OPENAI_API_KEY (deterministic fallback)";
  console.log(`\n  BreachLens dev server running:  http://localhost:${PORT}`);
  console.log(`  ${key}\n`);
});
