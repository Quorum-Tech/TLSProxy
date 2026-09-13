// Serves one page that makes every kind of request Chrome makes, over HTTP/2 (TLS) and
// HTTP/1.1, and records each request's header names and the values that differ by kind,
// in the order they arrived. Usage: node capture.mjs <out.json>
import http2 from "node:http2";
import http from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
const out = process.argv[2] ?? "capture.json";
const seen = [];
const KEEP = /^(:method|:path|referer|x-custom|accept|sec-fetch-.*|priority|content-type|origin|upgrade-insecure-requests|cache-control|pragma|purpose|sec-purpose)$/i;
const page = (origin, cross) => `<!doctype html><html><head><title>cap</title>
<link rel="stylesheet" href="/style.css"><script src="/script.js"></script>
<link rel="preload" href="/font.woff2" as="font" type="font/woff2" crossorigin></head>
<body><h1>capture</h1><img src="/image.png"><img src="${cross}/cross.png"><iframe src="/frame"></iframe>
<img src="/r/img"><iframe src="/r/frame"></iframe><iframe src="${cross}/cross-frame"></iframe>
<script type="module" src="/module.js"></script>
<script>
fetch("/api/fetch");
fetch("/r/fetch").catch(() => {});
fetch("/api/fetch-json", { headers: { accept: "application/json" } });
fetch("${cross}/api/fetch-cross", { mode: "cors" }).catch(() => {});
fetch("/api/fetch-custom", { headers: { "x-custom": "1" } });
fetch("/api/fetch-json-custom", { headers: { accept: "application/json", "x-custom": "1" } });
fetch("${cross}/api/post-cross", { method: "POST", mode: "cors", headers: { "content-type": "text/plain" }, body: "x" }).catch(() => {});
const x = new XMLHttpRequest(); x.open("GET", "/api/xhr"); x.send();
fetch("/api/post", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
setTimeout(() => { location.href = "/next"; }, 1500);
</script></body></html>`;
const record = (proto, names, values) => {
  const path = values[":path"] ?? values.path;
  seen.push({ proto, path, names, values: Object.fromEntries(Object.entries(values).filter(([k]) => KEEP.test(k))) });
};
let flushed = false;
const flush = () => { if (flushed) return; flushed = true; writeFileSync(out, JSON.stringify(seen, null, 1)); };
const body = (path, origin, cross) => {
  if (path === "/" ) return ["text/html", page(origin, cross)];
  if (path === "/next") return ["text/html", "<p>next</p>"];
  if (["/frame", "/after-frame", "/cross-frame", "/after-nav"].includes(path)) return ["text/html", "<p>frame</p>"];
  if (path.endsWith(".css")) return ["text/css", "body{font-family:x}"];
  if (path.endsWith(".js")) return ["application/javascript", "void 0"];
  if (path.endsWith(".png")) return ["image/png", Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAMAASsJTYQAAAAASUVORK5CYII=", "base64")];
  if (path.endsWith(".woff2")) return ["font/woff2", Buffer.alloc(8)];
  return ["application/json", "{}"];
};
const cookie = ["s=1; Path=/; SameSite=Lax; Secure", "t=2; Path=/"];
// same-origin addresses that redirect to another site, to record what Chrome sends after a redirect
const redirectFor = (path, cross) => ({ "/r/img": cross + "/after-img.png", "/r/fetch": cross + "/api/after-fetch", "/r/frame": cross + "/after-frame", "/r/nav": cross + "/after-nav" })[path];
const h2port = Number(process.env.H2PORT), h1port = Number(process.env.H1PORT);
const h2 = http2.createSecureServer({ key: readFileSync("key.pem"), cert: readFileSync("cert.pem"), allowHTTP1: false });
h2.on("stream", (stream, headers, flags, raw) => {
  const names = []; for (let i = 0; i < raw.length; i += 2) names.push(raw[i]);
  record("h2", names, headers);
  const loc = redirectFor(headers[":path"], `https://127.0.0.1:${h2port}`);
  if (loc) {
    stream.respond({ ":status": 302, location: loc, "access-control-allow-origin": "*", "cache-control": "no-store" });
    stream.end();
    return;
  }
  const [type, b] = body(headers[":path"], `https://localhost:${h2port}`, `https://127.0.0.1:${h2port}`);
  stream.respond({ ":status": 200, "content-type": type, "set-cookie": cookie, "access-control-allow-origin": "*", "cache-control": "no-store" });
  stream.end(b);
});
h2.listen(h2port, "127.0.0.1");
const h1 = http.createServer((req, res) => {
  const names = []; for (let i = 0; i < req.rawHeaders.length; i += 2) names.push(req.rawHeaders[i]);
  const values = { path: req.url, ...Object.fromEntries(Object.entries(req.headers)) };
  record("h1", names, values);
  const loc = redirectFor(req.url, `http://127.0.0.1:${h1port}`);
  if (loc) {
    res.writeHead(302, { location: loc, "access-control-allow-origin": "*", "cache-control": "no-store" });
    res.end();
    return;
  }
  const [type, b] = body(req.url, `http://localhost:${h1port}`, `http://127.0.0.1:${h1port}`);
  res.writeHead(200, { "content-type": type, "set-cookie": cookie.map((c) => c.replace("; Secure", "")), "access-control-allow-origin": "*", "cache-control": "no-store" });
  res.end(b);
});
h1.listen(h1port, "127.0.0.1");
setTimeout(() => { flush(); process.exit(0); }, Number(process.env.WAIT ?? 20000));
process.on("SIGTERM", () => { flush(); process.exit(0); });
