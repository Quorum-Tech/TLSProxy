package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
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
		"user-agent":         {navigateHeaders(chromeMajor)[4].value},
	}
	if dontIncludeOptionalHeaders {
		headers = fhttp.Header{"user-agent": {navigateHeaders(chromeMajor)[4].value}}
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
	// "navigate": Chrome's headers for a page typed into the address bar, in Chrome's order
	Preset string `json:"preset"`
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		fail(w, 400, "bad_request_body")
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
		if headers, err = presetHeaders(data.Preset, data.Headers); err != nil {
			fail(w, 400, "unknown_preset")
			return
		}
	} else {
		headers = legacyHeaders(target.Host, data.Headers, data.UseBaseHeaders)
	}

	o := sendOptions{timeoutSeconds: data.TimeoutSeconds, followRedirects: true, proxyURL: proxyURL}
	if o.timeoutSeconds <= 0 {
		o.timeoutSeconds = 30
	}
	if o.timeoutSeconds > 120 {
		o.timeoutSeconds = 120
	}
	if data.FollowRedirects != nil {
		o.followRedirects = *data.FollowRedirects
	}
	if !data.Isolated {
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
	response, resHeaders, status, err := SendTLSRequest(strings.ToUpper(data.Method), data.URL, headers, payload, o)
	w.Header().Set("X-Tlsproxy-Route", route)
	if err != nil {
		// the reason, never the proxy URL: it carries a credential
		log.Printf("request failed: route=%s host=%s", route, target.Host)
		fail(w, 502, "proxied_request_failed")
		return
	}
	for k, vs := range resHeaders {
		if strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length") || len(vs) == 0 {
			continue
		}
		w.Header().Set(k, vs[0])
	}
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		fail(w, 400, "bad_request_body")
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
	http.HandleFunc("/proxy", ProxyHandler)
	http.HandleFunc("/reset-cookies", ResetCookies)
	http.HandleFunc("/get-cookies", GetCookies)
	http.HandleFunc("/get-all-cookies", GetAllCookies)
	log.Printf("tlsproxy on %s, chrome %d, upstream proxy %t", addr, chromeMajor, upstreamProxy != "")
	log.Fatal(http.ListenAndServe(addr, nil))
}
