package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bogdanfinn/fhttp/cookiejar"
)

func init() { cookies, _ = cookiejar.New(nil) }

func call(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	ProxyHandler(rec, httptest.NewRequest("POST", "/proxy", bytes.NewReader(b)))
	return rec
}

func TestSecChUaMatchesRealChrome(t *testing.T) {
	for major, want := range map[int]string{
		124: `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
		131: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
		153: `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`,  // captured from Chrome 153
		154: `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`, // what the deployed build sent
	} {
		if got := secChUa(major); got != want {
			t.Errorf("Chrome %d: got %s, want %s", major, got, want)
		}
	}
}

func TestSiteRefererAndOrigin(t *testing.T) {
	u := func(s string) *url.URL { v, _ := url.Parse(s); return v }
	page := u("https://www.example.co.uk/pricing?plan=pro#faq")
	cases := []struct {
		target, site, referer string
	}{
		{"https://www.example.co.uk/api/prices", "same-origin", "https://www.example.co.uk/pricing?plan=pro"},
		{"https://cdn.example.co.uk/app.js", "same-site", "https://www.example.co.uk/"},
		{"https://cdn.other.co.uk/app.js", "cross-site", "https://www.example.co.uk/"},
		{"http://www.example.co.uk/old", "cross-site", ""}, // https page to http: no referer, and another scheme is another site
	}
	for _, c := range cases {
		if got := siteOf(page, u(c.target), false); got != c.site {
			t.Errorf("site %s: got %s want %s", c.target, got, c.site)
		}
		if got := refererValue(page, u(c.target)); got != c.referer {
			t.Errorf("referer %s: got %q want %q", c.target, got, c.referer)
		}
	}
	if siteOf(nil, u("https://example.com/"), true) != "none" {
		t.Error("a typed navigation is site none")
	}
	h, err := presetHeaders("fetch", u("https://api.other.com/v1"), "POST", "https://www.example.co.uk/app", map[string]string{"Content-Type": "application/json"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Origin") != "https://www.example.co.uk" || h.Get("Sec-Fetch-Site") != "cross-site" || h.Get("Referer") != "https://www.example.co.uk/" {
		t.Errorf("cross-site POST: origin %q site %q referer %q", h.Get("Origin"), h.Get("Sec-Fetch-Site"), h.Get("Referer"))
	}
	if _, err := presetHeaders("image", u("https://example.com/a.png"), "POST", "", nil, nil); err != errPresetMethod {
		t.Errorf("an image with a body: %v", err)
	}
	if _, err := presetHeaders("script", u("https://example.com/a.js"), "GET", "javascript:alert(1)", nil, nil); err != errBadReferer {
		t.Errorf("a referer that is not a web address: %v", err)
	}
}

func TestProxyField(t *testing.T) {
	cases := []struct {
		raw, upstream, url, route string
		err                       error
	}{
		{"", "", "", "direct", nil},
		{"false", "http://u:p@up:1", "", "direct", nil},
		{"null", "", "", "direct", nil},
		{"true", "http://u:p@up:1", "http://u:p@up:1", "upstream", nil},
		{"true", "", "", "", errNoUpstream},
		{`"http://user:p%40ss@us.gate.example:10000"`, "", "http://user:p%40ss@us.gate.example:10000", "request", nil},
		{`"socks5://gate.example:1080"`, "", "socks5://gate.example:1080", "request", nil},
		{`"ftp://gate.example:21"`, "", "", "", errBadProxy},
		{`"http://gate.example"`, "", "", "", errBadProxy}, // no port
		{`"http://gate.example:1/path"`, "", "", "", errBadProxy},
		{`5`, "", "", "", errBadProxy},
	}
	for _, c := range cases {
		url, route, err := proxyFor(json.RawMessage(c.raw), c.upstream)
		if url != c.url || route != c.route || err != c.err {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)", c.raw, url, route, err, c.url, c.route, c.err)
		}
	}
}

// A raw listener, so the header order on the wire is what is checked.
func TestNavigateSendsChromeHeadersInOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rd := bufio.NewReader(c)
		var names []string
		for {
			line, err := rd.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			if i := strings.Index(line, ":"); i > 0 && !strings.HasPrefix(line, "GET ") {
				names = append(names, line[:i]) // as spelled on the wire
			}
		}
		got <- names
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()
	rec := call(t, map[string]any{"url": "http://" + ln.Addr().String() + "/", "preset": "navigate", "isolated": true, "headers": map[string]string{"Accept-Language": "de"}})
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	names := <-got
	// Chrome 153 typing an http:// address, captured from a raw socket: Host and Connection
	// first, client hints lower case, the rest Title-Case, and no priority on HTTP/1.1
	want := []string{"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"}
	var filtered []string
	for _, n := range names {
		if !strings.EqualFold(n, "content-length") {
			filtered = append(filtered, n)
		}
	}
	if strings.Join(filtered, ",") != strings.Join(want, ",") {
		t.Errorf("header order and spelling\n got %v\nwant %v", filtered, want)
	}
	if rec.Header().Get("X-Tlsproxy-Route") != "direct" {
		t.Errorf("route %q", rec.Header().Get("X-Tlsproxy-Route"))
	}
}

func TestRedirectHandedBackWhenNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		w.Write([]byte("next"))
	}))
	defer srv.Close()
	rec := call(t, map[string]any{"url": srv.URL + "/", "preset": "navigate", "isolated": true, "followRedirects": false})
	if rec.Code != 302 || rec.Header().Get("Location") != "/next" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = call(t, map[string]any{"url": srv.URL + "/", "preset": "navigate", "isolated": true})
	if rec.Code != 200 || rec.Body.String() != "next" {
		t.Fatalf("followed: status %d body %q", rec.Code, rec.Body.String())
	}
}

func TestCompressedBodyIsDecompressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("<html>hello</html>"))
		gz.Close()
	}))
	defer srv.Close()
	rec := call(t, map[string]any{"url": srv.URL, "preset": "navigate", "isolated": true})
	if rec.Body.String() != "<html>hello</html>" || rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("body %q encoding %q", rec.Body.String(), rec.Header().Get("Content-Encoding"))
	}
}

// A per-request proxy URL really carries the request, and says so.
func TestRequestProxyCarriesTheRequest(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("from the target"))
	}))
	defer target.Close()
	// a tunnelling proxy: CONNECT, then bytes both ways
	var sawAuth, sawMethod string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth, sawMethod = r.Header.Get("Proxy-Authorization"), r.Method
		if r.Method != http.MethodConnect {
			http.Error(w, "tunnel only", 405)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		c, buf, _ := w.(http.Hijacker).Hijack()
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { io.Copy(up, buf); up.Close() }()
		io.Copy(c, up)
		c.Close()
	}))
	defer proxy.Close()
	addr := strings.TrimPrefix(proxy.URL, "http://")
	rec := call(t, map[string]any{"url": target.URL + "/page", "preset": "navigate", "isolated": true, "proxy": "http://kerf:s%3Acret@" + addr})
	if rec.Code != 200 || rec.Body.String() != "from the target" {
		t.Fatalf("status %d body %q (proxy saw %s)", rec.Code, rec.Body.String(), sawMethod)
	}
	if sawMethod != http.MethodConnect {
		t.Errorf("the proxy saw %q, not a tunnel", sawMethod)
	}
	if rec.Header().Get("X-Tlsproxy-Route") != "request" {
		t.Errorf("route %q", rec.Header().Get("X-Tlsproxy-Route"))
	}
	if sawAuth == "" {
		t.Error("the proxy saw no credentials")
	}
}

// A preset request follows a redirect itself and sends what Chrome sends at the new address:
// the site judged across the chain, the page's own Origin (a same-origin address redirecting
// away does not taint it: Chrome 153 sent it so), the referer trimmed to its origin, and no
// cookie meant for the first address.
func TestPresetRedirectRecomputesFetchMetadata(t *testing.T) {
	var got http.Header
	after := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("after"))
	}))
	defer after.Close()
	crossURL := strings.Replace(after.URL, "127.0.0.1", "localhost", 1) + "/after"
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossURL, http.StatusFound)
	}))
	defer first.Close()
	rec := call(t, map[string]any{"url": first.URL + "/r", "preset": "fetch", "referer": first.URL + "/page", "isolated": true,
		"headers": map[string]string{"cookie": "session=secret"}})
	if rec.Code != 200 || rec.Body.String() != "after" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if got.Get("Sec-Fetch-Site") != "cross-site" || got.Get("Origin") != first.URL || got.Get("Referer") != first.URL+"/" || got.Get("Cookie") != "" {
		t.Errorf("after a cross-site redirect: site %q origin %q referer %q cookie %q",
			got.Get("Sec-Fetch-Site"), got.Get("Origin"), got.Get("Referer"), got.Get("Cookie"))
	}
}

// Origin becomes "null" only when a redirect goes from an address outside the page's origin
// to another address outside it (Fetch's tainted origin).
func TestTaintedOriginAfterRedirectBetweenOtherOrigins(t *testing.T) {
	u := func(s string) *url.URL { v, _ := url.Parse(s); return v }
	page := "https://app.example.com/dashboard"
	h, err := presetHeaders("fetch", u("https://c.other.net/data"), "GET", page, nil, []*url.URL{u("https://b.elsewhere.org/r")})
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Origin") != "null" {
		t.Errorf("redirect between two other origins: origin %q", h.Get("Origin"))
	}
	h, _ = presetHeaders("fetch", u("https://c.other.net/data"), "GET", page, nil, []*url.URL{u("https://app.example.com/r")})
	if h.Get("Origin") != "https://app.example.com" {
		t.Errorf("same-origin address redirecting away: origin %q", h.Get("Origin"))
	}
}

func TestTokenAndBinding(t *testing.T) {
	old := token
	token = "s3cret"
	defer func() { token = old }()
	h := guard(ProxyHandler)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/proxy", strings.NewReader(`{}`)))
	if rec.Code != 401 {
		t.Errorf("no token: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/proxy", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != 400 { // past the guard: no_url_provided
		t.Errorf("with the token: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range []struct {
		addr, tok, allow string
		ok               bool
	}{
		{"127.0.0.1:7738", "", "", true},
		{"localhost:7738", "", "", true},
		{"[::1]:7738", "", "", true},
		{"0.0.0.0:7738", "", "", false},
		{":7738", "", "", false},
		{"172.17.0.1:7738", "", "", false},
		{"172.17.0.1:7738", "t", "", true},
		{"172.17.0.1:7738", "", "1", true},
	} {
		if err := bindAllowed(c.addr, c.tok, c.allow); (err == nil) != c.ok {
			t.Errorf("%s token=%q allow=%q: %v", c.addr, c.tok, c.allow, err)
		}
	}
}

func TestOversizedRequestIsRefused(t *testing.T) {
	big := `{"url":"http://example.com/","body":"` + strings.Repeat("a", maxRequest) + `"}`
	rec := httptest.NewRecorder()
	ProxyHandler(rec, httptest.NewRequest("POST", "/proxy", strings.NewReader(big)))
	if rec.Code != 413 || !strings.Contains(rec.Body.String(), "request_too_large") {
		t.Errorf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestFailuresAreJSONAndNeverEchoTheProxy(t *testing.T) {
	rec := call(t, map[string]any{"url": "http://127.0.0.1:1/", "preset": "navigate", "isolated": true, "timeoutSeconds": 3, "proxy": "http://kerf:hunter2@127.0.0.1:1"})
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), `"error":true`) {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Error("credential in the error")
	}
	if rec := call(t, map[string]any{"url": "http://example.com/", "proxy": true}); upstreamProxy == "" && rec.Code != 400 {
		t.Errorf("proxy true without an upstream: %d", rec.Code)
	}
	if rec := call(t, map[string]any{"url": "http://example.com/", "preset": "sideways"}); rec.Code != 400 {
		t.Errorf("unknown preset: %d", rec.Code)
	}
}
