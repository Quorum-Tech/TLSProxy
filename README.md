# TLSProxy

An HTTP API that fetches a URL the way Chrome does: Chrome's TLS hello and HTTP/2
settings (bogdanfinn/tls-client), and Chrome's headers in Chrome's order for the kind
of request being made. It is not a CONNECT proxy; a caller POSTs what it wants fetched.

## Running

```
TLSPROXY_ADDR=127.0.0.1:7738            # where to listen (default 127.0.0.1:7738)
TLSPROXY_UPSTREAM_PROXY=http://u:p@h:p  # optional: the proxy a request with "proxy": true goes through
go build -o tlsproxy . && ./tlsproxy
```

`TLSPROXY_INSECURE_SKIP_VERIFY=1` turns certificate checks off. It exists only for the
header capture check below, against a local server with a self-signed certificate; never
set it on a server that fetches pages.

## POST /proxy

```json
{
  "url": "https://example.com/pricing",
  "preset": "navigate",
  "referer": "",
  "method": "GET",
  "headers": { "Accept-Language": "de-DE,de;q=0.9" },
  "body": "",
  "isolated": true,
  "followRedirects": false,
  "timeoutSeconds": 12,
  "proxy": false
}
```

- `preset` is the kind of request, each with Chrome's own header set, order, `Accept`
  and `priority`: `navigate` (an address typed into the address bar), `iframe`, `style`,
  `script`, `module` (a module script), `font`, `image`, `fetch` and `xhr`. Only `fetch`
  and `xhr` may carry a body. With no preset the original fixed headers are sent.
- `referer` is the page the request comes from. It sets `Sec-Fetch-Site`, `Referer`
  (Chrome's default policy, strict-origin-when-cross-origin) and `Origin` where Chrome
  sends it. Leave it empty for a typed navigation.
- `headers` replace a preset header's value in place. For `fetch` and `xhr`, headers
  the preset does not have (and `accept` or `content-type`) are placed where Chrome puts
  headers a page script sets. A `cookie` goes in Chrome's cookie slot.
- `isolated` uses a cookie jar for this request alone instead of the shared one.
- `followRedirects` (default true) set to false hands a redirect back with its `Location`.
- `proxy`: `false` or absent goes out directly; `true` uses `TLSPROXY_UPSTREAM_PROXY`; a
  string is a proxy URL for this request alone (`http`, `https`, `socks5` or `socks5h`,
  with host and port).

The response is the site's status, headers and body (decompressed). `X-Tlsproxy-Route`
says how the request went out: `direct`, `upstream` or `request`; a caller that asked for
a proxy should check it. A failure is `502` with `{"error": true, "message": …}`, where the
message is `proxied_request_failed` or `response_too_large` (over 32 MB). A bad request is
`400` with `unknown_preset`, `method_not_allowed_for_preset`, `bad_referer`, `bad_proxy`,
`no_upstream_proxy`, `bad_url` or `no_url_provided`. Errors never contain a proxy URL.

## Keeping up with Chrome

`chromeMajor` in `headers.go` and the TLS profile in `tls.go` describe one Chrome
release. On each stable release:

1. Compare the TLS and HTTP/2 fingerprints: load `https://tls.peet.ws/api/all` in the
   new Chrome and through TLSProxy (`preset: navigate`), and check `tls.ja4` and
   `http2.akamai_fingerprint` are equal. If JA4 differs, pick the tls-client profile
   whose JA4 matches.
2. Capture Chrome's headers for every request kind and compare them with TLSProxy's:

   ```
   cd tools/headercapture
   ./run.sh "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" c<major>
   TLSPROXY_ADDR=127.0.0.1:7799 TLSPROXY_INSECURE_SKIP_VERIFY=1 ../../tlsproxy &
   node compare.mjs c<major> http://127.0.0.1:7799
   ```

   `run.sh` serves one page that makes each kind of request (with cookies, a referer,
   cross-site requests, script-set headers and POSTs) over HTTP/2 and HTTP/1.1, loads it
   in headless Chrome and records every request's headers as they arrived.
   `compare.mjs` sends the same requests through TLSProxy and reports any header whose
   name, order, spelling or value differs from Chrome's.

Checked on 2026-09-13 against Chrome 153.0.8010.36 (Chrome for Testing Stable): JA4
`t13d1517h2_8daaf6152771_cb7bf5808d99` with tls-client's `Chrome_152` profile, and every
request kind matching over both protocols.

Known limits: `priority` is left out for `http://` addresses, where Chrome always uses
HTTP/1.1 and sends none; an `https://` server that only speaks HTTP/1.1 still receives it.
An image's priority is Chrome's default (`u=2, i`); Chrome raises one it finds in view to
`u=1, i` after layout.
