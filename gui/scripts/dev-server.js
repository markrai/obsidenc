const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const uiRoot = path.resolve(__dirname, "..", "ui");
const port = Number.parseInt(process.env.PORT ?? "1420", 10);
const host = process.env.HOST ?? "127.0.0.1";

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".png":
      return "image/png";
    case ".svg":
      return "image/svg+xml";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}

function safeResolve(requestUrl) {
  const url = new URL(requestUrl, `http://${host}:${port}`);
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return null;
  }

  if (pathname === "/" || pathname === "") {
    pathname = "/index.html";
  }

  const relative = pathname.replace(/^\/+/, "");
  const resolved = path.resolve(uiRoot, relative);
  if (!resolved.startsWith(uiRoot + path.sep) && resolved !== uiRoot) {
    return null;
  }
  return resolved;
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Method Not Allowed");
    return;
  }

  const filePath = safeResolve(req.url ?? "/");
  if (!filePath) {
    res.statusCode = 400;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Bad Request");
    return;
  }

  fs.stat(filePath, (statErr, stat) => {
    if (statErr || !stat.isFile()) {
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Not Found");
      return;
    }

    res.statusCode = 200;
    res.setHeader("Content-Type", contentType(filePath));
    res.setHeader("Cache-Control", "no-store");

    if (req.method === "HEAD") {
      res.end();
      return;
    }

    const stream = fs.createReadStream(filePath);
    stream.on("error", () => {
      res.statusCode = 500;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Internal Server Error");
    });
    stream.pipe(res);
  });
});

server.listen(port, host, () => {
  // eslint-disable-next-line no-console
  console.log(`UI dev server: http://${host}:${port} (root: ${uiRoot})`);
});

