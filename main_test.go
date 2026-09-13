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
		153: `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`, // captured from Chrome 153
		154: `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`,  // what the deployed build sent
	} {
		if got := secChUa(major); got != want {
			t.Errorf("Chrome %d: got %s, want %s", major, got, want)
		}
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
				names = append(names, strings.ToLower(line[:i]))
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
	want := []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"}
	var filtered []string
	for _, n := range names {
		if n != "host" && n != "connection" && n != "content-length" {
			filtered = append(filtered, n)
		}
	}
	if strings.Join(filtered, ",") != strings.Join(want, ",") {
		t.Errorf("header order\n got %v\nwant %v", filtered, want)
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
