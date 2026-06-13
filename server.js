import { createReadStream, existsSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";
import { createServer } from "node:http";
import {
  createUser,
  leaderboardFor,
  loginUser,
  publicUser,
  readJson,
  saveUserData,
  tokenFromRequest,
  userFromToken
} from "./lib/store.js";

const rootDir = resolve(".");
const port = Number(process.env.PORT || 4173);

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mp3": "audio/mpeg",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml"
};

function sendJson(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload));
}

async function handleApi(request, response, pathname) {
  if (request.method === "POST" && pathname === "/api/register") {
    const body = await readJson(request);
    return sendJson(response, 200, await createUser(body));
  }

  if (request.method === "POST" && pathname === "/api/login") {
    const body = await readJson(request);
    return sendJson(response, 200, await loginUser(body));
  }

  if (request.method === "GET" && pathname === "/api/me") {
    const user = await userFromToken(tokenFromRequest(request));
    if (!user) return sendJson(response, 401, { error: "Nicht eingeloggt." });
    return sendJson(response, 200, { user: publicUser(user) });
  }

  if (request.method === "POST" && pathname === "/api/save") {
    const body = await readJson(request);
    await saveUserData(tokenFromRequest(request), body);
    return sendJson(response, 200, { ok: true });
  }

  if (request.method === "GET" && pathname.startsWith("/api/leaderboard/")) {
    const mode = pathname.split("/").pop();
    return sendJson(response, 200, { rows: await leaderboardFor(mode) });
  }

  sendJson(response, 404, { error: "API nicht gefunden." });
}

function serveStatic(request, response, pathname) {
  const safePath = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, "");
  const requestedPath = safePath === "/" ? "/index.html" : safePath;
  const filePath = resolve(join(rootDir, requestedPath));
  if (!filePath.startsWith(rootDir) || !existsSync(filePath)) {
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
    return;
  }
  response.writeHead(200, { "content-type": mimeTypes[extname(filePath)] || "application/octet-stream" });
  createReadStream(filePath).pipe(response);
}

createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname.startsWith("/api/")) {
      await handleApi(request, response, url.pathname);
      return;
    }
    serveStatic(request, response, url.pathname);
  } catch (error) {
    console.error(error);
    sendJson(response, error.status || 500, { error: error.message || "Serverfehler." });
  }
}).listen(port, "0.0.0.0", () => {
  console.log(`Neon Slingshot läuft auf http://localhost:${port}`);
});
