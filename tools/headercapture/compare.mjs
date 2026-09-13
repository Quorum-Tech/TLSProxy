// Sends every request kind through TLSProxy to the capture servers and compares the header
// names, in order and as spelled, with what real Chrome sent for the same request.
//   node compare.mjs <chrome capture label> <tlsproxy base url>
import { spawn } from "node:child_process";
import { readFileSync, existsSync, rmSync } from "node:fs";

const label = process.argv[2] ?? "c153";
const tlsproxy = process.argv[3] ?? "http://127.0.0.1:7799";
const cases = [
  // path, preset, method, body, script headers, cookie, cross-origin
  ["/", "navigate"],
  ["/style.css", "style", "GET", null, {}, true],
  ["/script.js", "script", "GET", null, {}, true],
  ["/font.woff2", "font", "GET", null, {}, true],
  ["/image.png", "image", "GET", null, {}, true],
  ["/module.js", "module", "GET", null, {}, true],
  ["/api/fetch", "fetch", "GET", null, {}, true],
  ["/api/fetch-json", "fetch", "GET", null, { accept: "application/json" }, true],
  ["/api/fetch-custom", "fetch", "GET", null, { "x-custom": "1" }, true],
  ["/api/fetch-json-custom", "fetch", "GET", null, { accept: "application/json", "x-custom": "1" }, true],
  ["/api/xhr", "xhr", "GET", null, {}, true],
  ["/api/post", "fetch", "POST", "{}", { "content-type": "application/json" }, true],
  ["/frame", "iframe", "GET", null, {}, true],
  ["/cross.png", "image", "GET", null, {}, false, true],
  ["/api/fetch-cross", "fetch", "GET", null, {}, false, true],
  ["/api/post-cross", "fetch", "POST", "x", { "content-type": "text/plain" }, false, true],
  // followed redirects to another site: compared at the address the redirect led to
  ["/r/img", "image", "GET", null, {}, true, false, "/after-img.png"],
  ["/r/fetch", "fetch", "GET", null, {}, true, false, "/api/after-fetch"],
  ["/r/frame", "iframe", "GET", null, {}, true, false, "/after-frame"],
  ["/cross-frame", "iframe", "GET", null, {}, false, true],
  // a typed address (no referer, no cookie yet) that redirects to another site
  ["/r/nav", "navigate", "GET", null, {}, false, false, "/after-nav"],
];

let failures = 0;
for (const proto of ["h2", "h1"]) {
  const chrome = JSON.parse(readFileSync(`cap-${label}-${proto}.json`, "utf8"));
  const h2port = 40000 + Math.floor(Math.random() * 9000), h1port = h2port + 1;
  const out = `tlsproxy-${proto}.json`;
  if (existsSync(out)) rmSync(out);
  const server = spawn("node", ["capture.mjs", out], { env: { ...process.env, H2PORT: String(h2port), H1PORT: String(h1port), WAIT: "12000" }, stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 800));
  const base = proto === "h2" ? `https://localhost:${h2port}` : `http://localhost:${h1port}`;
  const cross = proto === "h2" ? `https://127.0.0.1:${h2port}` : `http://127.0.0.1:${h1port}`;
  for (const [path, preset, method = "GET", body = null, headers = {}, cookie = false, isCross = false, redirectedTo = null] of cases) {
    const url = (isCross ? cross : base) + path;
    const req = { url, preset, method, isolated: true, followRedirects: !!redirectedTo, timeoutSeconds: 10,
      headers: { ...headers, ...(cookie ? { cookie: "s=1; t=2" } : {}) },
      ...(preset === "navigate" ? {} : { referer: base + "/" }), ...(body !== null ? { body } : {}) };
    const r = await fetch(tlsproxy + "/proxy", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(req) });
    if (r.status >= 400 && r.status !== 404) { console.log(proto, path, "TLSProxy answered", r.status, await r.text()); failures++; }
    else await r.arrayBuffer();
  }
  server.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 300));
  // capture.mjs writes on exit or after WAIT; give it the signal-free path by waiting for the file
  for (let i = 0; i < 60 && !existsSync(out); i++) await new Promise((r) => setTimeout(r, 250));
  if (!existsSync(out)) {
    // killed before writing: restart the whole run with a flush on SIGTERM
    console.log(proto, "no capture written");
    failures++;
    continue;
  }
  const ours = JSON.parse(readFileSync(out, "utf8"));
  for (const [first, , , , , , , redirectedTo] of cases) {
    const path = redirectedTo ?? first;
    const c = chrome.find((x) => x.path === path), o = ours.find((x) => x.path === path);
    if (!c || !o) { console.log(proto, path.padEnd(22), !c ? "not in Chrome capture" : "not received from TLSProxy"); failures++; continue; }
    const same = JSON.stringify(c.names) === JSON.stringify(o.names);
    // An image's priority is decided after layout: Chrome sends "u=2, i" by default and raises an
    // image it finds in view to "u=1, i" (the capture has both), so either is Chrome's.
    const imagePriority = (k) => k === "priority" && c.values["sec-fetch-dest"] === "image" &&
      ["u=2, i", "u=1, i"].includes(c.values.priority) && ["u=2, i", "u=1, i"].includes(o.values.priority);
    const valueDiffs = ["accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "sec-fetch-storage-access", "priority", "content-type", "upgrade-insecure-requests"]
      .filter((k) => (c.values[k] ?? null) !== (o.values[k] ?? null) && !imagePriority(k))
      .map((k) => `${k}: chrome ${JSON.stringify(c.values[k])} ours ${JSON.stringify(o.values[k])}`);
    const refShape = (v) => (v ?? "").replace(/:\d+/, ":PORT");
    if (refShape(c.values.referer) !== refShape(o.values.referer)) valueDiffs.push(`referer: chrome ${c.values.referer} ours ${o.values.referer}`);
    if (!!c.values.origin !== !!o.values.origin) valueDiffs.push(`origin present: chrome ${!!c.values.origin} ours ${!!o.values.origin}`);
    else if ((c.values.origin === "null") !== (o.values.origin === "null")) valueDiffs.push(`origin: chrome ${c.values.origin} ours ${o.values.origin}`);
    if (same && valueDiffs.length === 0) console.log(proto, path.padEnd(22), "match");
    else {
      failures++;
      console.log(proto, path.padEnd(22), same ? "names match, values differ" : "ORDER DIFFERS");
      if (!same) console.log("   chrome", c.names.join(","), "\n   ours  ", o.names.join(","));
      for (const d of valueDiffs) console.log("  ", d);
    }
  }
}
console.log(failures ? `${failures} difference(s)` : "every request kind matches Chrome");
process.exit(failures ? 1 : 0);
