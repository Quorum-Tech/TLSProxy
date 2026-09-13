package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	up "net/url"
	"os"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
)

var (
	mu            sync.Mutex
	cookies       *cookiejar.Jar
	requestedURLS []string
)

// upstreamProxy is the proxy a request asking for `"proxy": true` goes
// through, from TLSPROXY_UPSTREAM_PROXY. It holds a credential: never logged.
var upstreamProxy = strings.TrimSpace(os.Getenv("TLSPROXY_UPSTREAM_PROXY"))

// insecureSkipVerify accepts any certificate, for checking header order against a local
// capture server with a self-signed certificate. Never set it on a server that fetches pages.
var insecureSkipVerify = os.Getenv("TLSPROXY_INSECURE_SKIP_VERIFY") == "1"

// token, when set, is required as "Authorization: Bearer <token>" on every endpoint. Anyone
// who can reach TLSProxy can make it fetch any address (internal ones included) and read the
// shared cookie jar, so a server listening beyond loopback must set one, or say plainly
// with TLSPROXY_ALLOW_UNAUTHENTICATED=1 that something else (a firewall) guards it.
var token = os.Getenv("TLSPROXY_TOKEN")

const (
	// maxRequest caps a request to TLSProxy; a larger one is refused, never cut short
	maxRequest = 1 << 20
	// maxRedirects is Chrome's own limit on a redirect chain
	maxRedirects = 20
)

var errTooManyRedirects = errors.New("too_many_redirects")

var redirectStatus = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// guard requires the token, when one is set.
func guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			fail(w, 401, "unauthorized")
			return
		}
		h(w, r)
	}
}

// bindAllowed refuses an address beyond loopback with no token, unless allowUnauthenticated is "1".
func bindAllowed(addr, tok, allowUnauthenticated string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if loopback || tok != "" || allowUnauthenticated == "1" {
		return nil
	}
	return errors.New("TLSPROXY_ADDR " + addr + " is reachable beyond this machine and TLSPROXY_TOKEN is empty: set a token, or set TLSPROXY_ALLOW_UNAUTHENTICATED=1 if a firewall already limits who can reach it")
}

func withoutHeader(h map[string]string, name string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if !strings.EqualFold(k, name) {
			out[k] = v
		}
	}
	return out
}

// sendFollowing sends the request. A preset request follows its redirects itself: Chrome
// works out Sec-Fetch-Site, Referer, Origin and the cookie again for every hop, from where
// that hop goes, and a client following redirects on its own would resend the first hop's.
func sendFollowing(data proxyRequest, target *up.URL, headers fhttp.Header, payload []byte, o sendOptions) ([]byte, fhttp.Header, int, error) {
	method := strings.ToUpper(data.Method)
	if data.Preset == "" {
		return SendTLSRequest(method, data.URL, headers, payload, o)
	}
	follow := o.followRedirects
	o.followRedirects = false
	custom := data.Headers
	hop := target
	var chain []*up.URL
	for n := 0; ; n++ {
		response, resHeaders, status, err := SendTLSRequest(method, hop.String(), headers, payload, o)
		if err != nil || !follow || !redirectStatus[status] {
			return response, resHeaders, status, err
		}
		loc := resHeaders.Get("Location")
		next, perr := hop.Parse(loc)
		if loc == "" || perr != nil || (next.Scheme != "http" && next.Scheme != "https") {
			return response, resHeaders, status, nil
		}
		if n+1 >= maxRedirects {
			return nil, nil, 500, errTooManyRedirects
		}
		// as a browser does: a 303, or a 301 or 302 answering a POST, is followed with a GET and no body
		if (status == 303 && method != "HEAD") || ((status == 301 || status == 302) && method == "POST") {
			method, payload = "GET", nil
			custom = withoutHeader(custom, "content-type")
		}
		chain = append(chain, hop)
		hop = next
		if headers, err = presetHeaders(data.Preset, hop, method, data.Referer, custom, chain); err != nil {
			return nil, nil, 500, err
		}
	}
}

// legacyHeaders are the original fixed headers, for requests that name no preset.
func legacyHeaders(host string, custom map[string]string, dontIncludeOptionalHeaders bool) fhttp.Header {
	headers := fhttp.Header{
		"authority":          {host},
		"accept":             {"application/json, text/plain, */*"},
		"origin":             {"https://" + host + "/"},
		"referer":            {"https://" + host + "/"},
		"sec-ch-ua":          {secChUa(chromeMajor)},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"macOS"`},
		"sec-fetch-dest":     {"empty"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-site":     {"same-site"},
		"user-agent":         {userAgent(chromeMajor)},
	}
	if dontIncludeOptionalHeaders {
		headers = fhttp.Header{"user-agent": {userAgent(chromeMajor)}}
	}
	for k, v := range custom {
		headers[k] = []string{v}
	}
	return headers
}

type proxyRequest struct {
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers"`
	Payload        string            `json:"payload"`
	Body           string            `json:"body"`
	UseBaseHeaders bool              `json:"useBaseHeaders"`
	// Chrome's headers, in Chrome's order, for one kind of request: "navigate" (a page typed
	// into the address bar), "iframe", "style", "script", "module", "font", "image",
	// "fetch" or "xhr". Only fetch and xhr may carry a body.
	Preset string `json:"preset"`
	// the page the request comes from, for Sec-Fetch-Site, Referer and Origin; empty for a typed navigation
	Referer string `json:"referer"`
	// a cookie jar for this request alone, instead of the shared one
	Isolated bool `json:"isolated"`
	// default true; false hands a redirect back with its Location
	FollowRedirects *bool `json:"followRedirects"`
	TimeoutSeconds  int   `json:"timeoutSeconds"`
	// false or absent: direct. true: TLSPROXY_UPSTREAM_PROXY. A string: that proxy URL,
	// for this request only (http, https or socks5, with host and port).
	Proxy json.RawMessage `json:"proxy"`
}

var errNoUpstream = errors.New("no_upstream_proxy")
var errBadProxy = errors.New("bad_proxy")

// proxyFor resolves a request's proxy field to a URL (empty for direct) and
// the route reported back in X-Tlsproxy-Route: direct, upstream or request.
func proxyFor(raw json.RawMessage, upstream string) (string, string, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "false" {
		return "", "direct", nil
	}
	if s == "true" {
		if upstream == "" {
			return "", "", errNoUpstream
		}
		return upstream, "upstream", nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", "", errBadProxy
	}
	u, err := up.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" || u.Port() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", "", errBadProxy
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", "", errBadProxy
	}
	return u.String(), "request", nil
}

func fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"error": true, "message": message})
	w.Write(b)
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 400, "invalid_request_method")
		return
	}
	// one byte past the cap tells an oversized request from one that is exactly the cap
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest+1))
	if err != nil {
		fail(w, 400, "bad_request_body")
		return
	}
	if len(body) > maxRequest {
		fail(w, 413, "request_too_large")
		return
	}
	var data proxyRequest
	if err := json.Unmarshal(body, &data); err != nil {
		fail(w, 400, "request_parse_failed")
		return
	}
	if data.URL == "" {
		fail(w, 400, "no_url_provided")
		return
	}
	target, err := up.Parse(data.URL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		fail(w, 400, "bad_url")
		return
	}
	if data.Method == "" {
		data.Method = "GET"
	}
	if data.Payload == "" {
		data.Payload = data.Body
	}
	if data.Payload != "" && data.Method == "GET" {
		data.Method = "POST"
	}
	proxyURL, route, err := proxyFor(data.Proxy, upstreamProxy)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}

	var headers fhttp.Header
	if data.Preset != "" {
		if headers, err = presetHeaders(data.Preset, target, strings.ToUpper(data.Method), data.Referer, data.Headers, nil); err != nil {
			fail(w, 400, err.Error())
			return
		}
	} else {
		headers = legacyHeaders(target.Host, data.Headers, data.UseBaseHeaders)
	}

	o := sendOptions{timeoutSeconds: data.TimeoutSeconds, followRedirects: true, proxyURL: proxyURL, insecure: insecureSkipVerify}
	if o.timeoutSeconds <= 0 {
		o.timeoutSeconds = 30
	}
	if o.timeoutSeconds > 120 {
		o.timeoutSeconds = 120
	}
	if data.FollowRedirects != nil {
		o.followRedirects = *data.FollowRedirects
	}
	if data.Isolated {
		// one jar for every hop of this request, and for no other request
		o.jar, _ = cookiejar.New(nil)
	} else {
		mu.Lock()
		o.jar = cookies
		seen := false
		for _, u := range requestedURLS {
			if u == data.URL {
				seen = true
				break
			}
		}
		if !seen {
			requestedURLS = append(requestedURLS, data.URL)
		}
		mu.Unlock()
	}

	var payload []byte
	if data.Payload != "" {
		payload = []byte(data.Payload)
	}
	response, resHeaders, status, err := sendFollowing(data, target, headers, payload, o)
	if err != nil {
		w.Header().Set("X-Tlsproxy-Route", route)
		// the reason, never the proxy URL: it carries a credential
		log.Printf("request failed: route=%s host=%s", route, target.Host)
		if errors.Is(err, errTooLarge) {
			fail(w, 502, "response_too_large")
			return
		}
		if errors.Is(err, errTooManyRedirects) {
			fail(w, 502, "too_many_redirects")
			return
		}
		fail(w, 502, "proxied_request_failed")
		return
	}
	for k, vs := range resHeaders {
		// the site's own copy of our route header is dropped: the route is ours to report
		if strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "X-Tlsproxy-Route") || len(vs) == 0 {
			continue
		}
		w.Header().Set(k, vs[0])
	}
	w.Header().Set("X-Tlsproxy-Route", route)
	w.WriteHeader(status)
	w.Write(response)
}

func GetAllCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 400, "invalid_request_method")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	cookiesMap := map[string][]*fhttp.Cookie{}
	for _, raw := range requestedURLS {
		parsedURL, err := up.Parse(raw)
		if err != nil {
			continue
		}
		cookiesMap[raw] = cookies.Cookies(parsedURL)
	}
	data, err := json.Marshal(cookiesMap)
	if err != nil {
		fail(w, 500, "cookies_parse_failed")
		return
	}
	w.WriteHeader(200)
	w.Write(data)
}

func GetCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 400, "invalid_request_method")
		return
	}
	// one byte past the cap tells an oversized request from one that is exactly the cap
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest+1))
	if err != nil {
		fail(w, 400, "bad_request_body")
		return
	}
	if len(body) > maxRequest {
		fail(w, 413, "request_too_large")
		return
	}
	var data struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		fail(w, 400, "request_parse_failed")
		return
	}
	if data.URL == "" {
		fail(w, 400, "no_url_provided")
		return
	}
	parsedURL, err := up.Parse(data.URL)
	if err != nil {
		fail(w, 400, "bad_url")
		return
	}
	mu.Lock()
	cs := cookies.Cookies(parsedURL)
	mu.Unlock()
	if cs == nil {
		w.WriteHeader(200)
		w.Write([]byte(`[]`))
		return
	}
	out, err := json.Marshal(cs)
	if err != nil {
		fail(w, 500, "cookies_parse_failed")
		return
	}
	w.WriteHeader(200)
	w.Write(out)
}

func ResetCookies(w http.ResponseWriter, r *http.Request) {
	cj, err := cookiejar.New(nil)
	if err != nil {
		fail(w, 500, "cookie_reset_failed")
		return
	}
	mu.Lock()
	cookies = cj
	requestedURLS = nil
	mu.Unlock()
	w.WriteHeader(200)
	w.Write([]byte(`{"error": false, "message": "cookies_reset"}`))
}

func main() {
	cookies, _ = cookiejar.New(nil)
	addr := os.Getenv("TLSPROXY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:7738"
	}
	if err := bindAllowed(addr, token, os.Getenv("TLSPROXY_ALLOW_UNAUTHENTICATED")); err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/proxy", guard(ProxyHandler))
	http.HandleFunc("/reset-cookies", guard(ResetCookies))
	http.HandleFunc("/get-cookies", guard(GetCookies))
	http.HandleFunc("/get-all-cookies", guard(GetAllCookies))
	log.Printf("tlsproxy on %s, chrome %d, upstream proxy %t, token %t", addr, chromeMajor, upstreamProxy != "", token != "")
	if insecureSkipVerify {
		log.Printf("WARNING: TLSPROXY_INSECURE_SKIP_VERIFY=1, certificates are not checked; for header capture tests only")
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}
