package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/publicsuffix"
)

// chromeMajor is the Chrome version the headers claim: current stable (Chrome for
// Testing's Stable channel, 153.0.8010.36 on 2026-09-13; 154 was at a 0.5% rollout).
// The TLS profile in tls.go must send the hello that version sends; raise both with
// each stable release and re-check against a real Chrome (see README: header capture).
const chromeMajor = 153

// secChUa is Chrome's greased brand list, built the way Chromium builds it
// (GetGreasedUserAgentBrandVersion): the major version seeds the fake brand's
// punctuation, its version, and where each brand sits. Checked against real
// Chrome 124, 131 and 153.
func secChUa(major int) string {
	chars := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	versions := []string{"8", "99", "24"}
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	grease := fmt.Sprintf(`"Not%sA%sBrand";v="%s"`, chars[major%len(chars)], chars[(major+1)%len(chars)], versions[major%len(versions)])
	order := orders[major%len(orders)]
	brands := make([]string, 3)
	brands[order[0]] = grease
	brands[order[1]] = fmt.Sprintf(`"Chromium";v="%d"`, major)
	brands[order[2]] = fmt.Sprintf(`"Google Chrome";v="%d"`, major)
	return strings.Join(brands, ", ")
}

func userAgent(major int) string {
	return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", major)
}

const (
	acceptDocument = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	acceptStyle    = "text/css,*/*;q=0.1"
	acceptImage    = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
	acceptAny      = "*/*"
)

// A kind of request Chrome makes, as captured from Chrome 153 on macOS over HTTP/2 and
// HTTP/1.1 (a page that loads each kind, recorded in arrival order by a raw server).
type requestKind struct {
	navigation    bool   // a document or frame: Chrome's navigation header set and order
	dest, mode    string // Sec-Fetch-Dest, Sec-Fetch-Mode
	accept        string
	priority      string // HTTP/2 only: Chrome sends no priority header on HTTP/1.1
	userActivated bool   // Sec-Fetch-User: ?1, a navigation the user started
	earlyOrigin   bool   // a CORS-mode resource (font, module script): Origin always, before the client hints
	scripted      bool   // fetch/XHR: a page script may send a body and set its own headers
}

var kinds = map[string]requestKind{
	"navigate": {navigation: true, dest: "document", mode: "navigate", accept: acceptDocument, priority: "u=0, i", userActivated: true},
	"iframe":   {navigation: true, dest: "iframe", mode: "navigate", accept: acceptDocument, priority: "u=0, i"},
	"style":    {dest: "style", mode: "no-cors", accept: acceptStyle, priority: "u=0"},
	"script":   {dest: "script", mode: "no-cors", accept: acceptAny, priority: "u=1"},
	"module":   {dest: "script", mode: "cors", accept: acceptAny, priority: "u=1", earlyOrigin: true},
	"font":     {dest: "font", mode: "cors", accept: acceptAny, priority: "u=1", earlyOrigin: true},
	"image":    {dest: "image", mode: "no-cors", accept: acceptImage, priority: "u=2, i"},
	"fetch":    {dest: "empty", mode: "cors", accept: acceptAny, priority: "u=1, i", scripted: true},
	"xhr":      {dest: "empty", mode: "cors", accept: acceptAny, priority: "u=1, i", scripted: true},
}

var (
	errUnknownPreset = errors.New("unknown_preset")
	errPresetMethod  = errors.New("method_not_allowed_for_preset")
	errBadReferer    = errors.New("bad_referer")
)

type header struct{ name, value string }

func defaultPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && defaultPort(a) == defaultPort(b)
}

// registrable is a host's site: its registrable domain (example.co.uk), or the host itself
// for an address or a name with no public suffix.
func registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if net.ParseIP(host) != nil {
		return host
	}
	if site, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return site
	}
	return host
}

// siteOf is Sec-Fetch-Site. With no referer a navigation was typed ("none"); any other
// request with no referer is taken as the page's own.
func siteOf(ref, target *url.URL, navigation bool) string {
	switch {
	case ref == nil && navigation:
		return "none"
	case ref == nil || sameOrigin(ref, target):
		return "same-origin"
	case ref.Scheme == target.Scheme && registrable(ref.Hostname()) == registrable(target.Hostname()):
		return "same-site"
	default:
		return "cross-site"
	}
}

// refererValue applies Chrome's default policy, strict-origin-when-cross-origin: the whole
// address to the same origin, the origin alone elsewhere, nothing from https to http.
func refererValue(ref, target *url.URL) string {
	if ref == nil || (ref.Scheme == "https" && target.Scheme == "http") {
		return ""
	}
	if sameOrigin(ref, target) {
		r := *ref
		r.Fragment, r.RawFragment, r.User = "", "", nil
		return r.String()
	}
	return ref.Scheme + "://" + ref.Host + "/"
}

// presetHeaders builds a request as Chrome sends one of the kinds above: its headers and
// their order, with names spelled as Chrome writes them on HTTP/1.1 (client hints and
// script-set names in lower case, the rest Title-Case; HTTP/2 lower-cases them all).
//
// referer is the page the request comes from ("" for a typed navigation). It sets
// Sec-Fetch-Site, Referer and, where Chrome sends it, Origin. custom headers replace a
// preset header's value in place; for fetch and XHR, the ones a script sets itself
// (accept, content-type, anything else) sit where Chrome puts script-set headers.
// A cookie header goes in Chrome's cookie slot.
//
// chain is the addresses already visited on the way to target when a redirect led here (nil
// for the first request). Chrome judges Sec-Fetch-Site across the whole chain, sends Origin
// as "null" once a hop has crossed origins, and a cookie the caller set for the first address
// is not sent to another origin.
func presetHeaders(preset string, target *url.URL, method, referer string, custom map[string]string, chain []*url.URL) (fhttp.Header, error) {
	k, ok := kinds[preset]
	if !ok {
		return nil, errUnknownPreset
	}
	hasBody := method != "GET" && method != "HEAD"
	if hasBody && !k.scripted {
		return nil, errPresetMethod
	}
	var ref *url.URL
	if referer != "" {
		r, err := url.Parse(referer)
		if err != nil || r.Host == "" || (r.Scheme != "http" && r.Scheme != "https") {
			return nil, errBadReferer
		}
		ref = r
	}

	// the caller's headers by lower-case name; keys sorted so a repeated name is decided the same way every time
	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	given := map[string]string{}
	for _, name := range keys {
		given[strings.ToLower(name)] = custom[name]
	}
	take := func(name string) (string, bool) {
		v, ok := given[name]
		delete(given, name)
		return v, ok
	}
	value := func(name, fallback string) string {
		if v, ok := take(strings.ToLower(name)); ok {
			return v
		}
		return fallback
	}

	// every address of the request, the first one first
	urls := append(append([]*url.URL{}, chain...), target)
	// the page a request comes from; with none, the first address stands in for it
	base := ref
	if base == nil {
		base = urls[0]
	}
	site := siteOf(ref, target, k.navigation)
	if site != "none" {
		// the most cross-site of every hop
		rank := map[string]int{"same-origin": 0, "same-site": 1, "cross-site": 2}
		for _, u := range urls {
			if s := siteOf(base, u, false); rank[s] > rank[site] {
				site = s
			}
		}
	}
	// Fetch's tainted origin: a redirect from an address outside the page's origin to another
	// one outside it makes Origin "null". A same-origin address redirecting away does not (Chrome
	// 153 sent the page's origin after exactly that redirect).
	tainted := false
	crossedOrigin := false // some hop changed origin
	for i := 1; i < len(urls); i++ {
		if !sameOrigin(base, urls[i]) && !sameOrigin(base, urls[i-1]) {
			tainted = true
		}
		if !sameOrigin(urls[i-1], urls[i]) {
			crossedOrigin = true
		}
	}
	refValue := refererValue(ref, target)
	origin := base.Scheme + "://" + base.Host
	if tainted {
		origin = "null"
	}
	lateOrigin := k.scripted && (hasBody || !sameOrigin(base, target))
	storageAccess := k.mode == "no-cors" && !k.navigation && site == "cross-site"

	var list []header
	add := func(name, v string) { list = append(list, header{name, v}) }
	cookie, hasCookie := take("cookie")
	if hasCookie && !sameOrigin(urls[0], target) {
		// the caller's cookie belongs to the first address, not to wherever a redirect went
		hasCookie = false
	}
	scriptAccept, hasScriptAccept := "", false
	scriptType, hasScriptType := "", false
	if k.scripted {
		scriptAccept, hasScriptAccept = take("accept")
		scriptType, hasScriptType = take("content-type")
	}

	if k.navigation {
		hints := func() {
			add("sec-ch-ua", value("sec-ch-ua", secChUa(chromeMajor)))
			add("sec-ch-ua-mobile", value("sec-ch-ua-mobile", "?0"))
			add("sec-ch-ua-platform", value("sec-ch-ua-platform", `"macOS"`))
		}
		// Chrome removes the client hints when a navigation is redirected to another origin
		// and adds them back after the fetch metadata (captured from Chrome 153)
		if !crossedOrigin {
			hints()
		}
		add("Upgrade-Insecure-Requests", value("Upgrade-Insecure-Requests", "1"))
		add("User-Agent", value("User-Agent", userAgent(chromeMajor)))
		add("Accept", value("Accept", k.accept))
		add("Sec-Fetch-Site", value("Sec-Fetch-Site", site))
		add("Sec-Fetch-Mode", value("Sec-Fetch-Mode", k.mode))
		if k.userActivated {
			add("Sec-Fetch-User", value("Sec-Fetch-User", "?1"))
		}
		add("Sec-Fetch-Dest", value("Sec-Fetch-Dest", k.dest))
		if k.dest == "iframe" && site == "cross-site" {
			// a cross-site frame reports its storage access, as a cross-site subresource does
			add("Sec-Fetch-Storage-Access", value("Sec-Fetch-Storage-Access", "active"))
		}
		if crossedOrigin {
			hints()
		}
	} else {
		if k.earlyOrigin {
			add("Origin", value("Origin", origin))
		}
		add("sec-ch-ua-platform", value("sec-ch-ua-platform", `"macOS"`))
		add("User-Agent", value("User-Agent", userAgent(chromeMajor)))
		if hasScriptAccept {
			add("accept", scriptAccept)
		}
		add("sec-ch-ua", value("sec-ch-ua", secChUa(chromeMajor)))
		if hasScriptType {
			add("content-type", scriptType)
		}
		add("sec-ch-ua-mobile", value("sec-ch-ua-mobile", "?0"))
		if !hasScriptAccept {
			add("Accept", value("Accept", k.accept))
		}
		if lateOrigin {
			add("Origin", value("Origin", origin))
		}
		add("Sec-Fetch-Site", value("Sec-Fetch-Site", site))
		add("Sec-Fetch-Mode", value("Sec-Fetch-Mode", k.mode))
		add("Sec-Fetch-Dest", value("Sec-Fetch-Dest", k.dest))
		if storageAccess {
			// default settings allow third-party cookies, so Chrome reports its storage access as active
			add("Sec-Fetch-Storage-Access", value("Sec-Fetch-Storage-Access", "active"))
		}
	}
	if v := value("Referer", refValue); v != "" {
		add("Referer", v)
	}
	add("Accept-Encoding", value("Accept-Encoding", "gzip, deflate, br, zstd"))
	add("Accept-Language", value("Accept-Language", "en-US,en;q=0.9"))
	if hasCookie {
		add("Cookie", cookie)
	}
	// plain http is always HTTP/1.1, where Chrome sends no priority
	priority, hasPriority := take("priority")
	if target.Scheme != "http" {
		if !hasPriority {
			priority = k.priority
		}
		add("priority", priority)
	}

	// A script's own headers come first, after Host and Connection, in the order it set them;
	// a map has none, so they are sorted. Chrome sends them spelled as the script wrote them,
	// which for a name given in any case here is lower case.
	extra := make([]string, 0, len(given))
	for name := range given {
		extra = append(extra, name)
	}
	sort.Strings(extra)

	h := fhttp.Header{}
	// Host and Connection lead on HTTP/1.1 (HTTP/2 carries :authority and drops Connection);
	// a body's Content-Length follows them, as Chrome sends it
	order := []string{"host", "connection"}
	h["Connection"] = []string{"keep-alive"}
	if hasBody {
		order = append(order, "content-length")
	}
	for _, name := range extra {
		h[name] = []string{given[name]}
		order = append(order, name)
	}
	for _, x := range list {
		h[x.name] = []string{x.value}
		order = append(order, strings.ToLower(x.name))
	}
	if !hasCookie {
		// a cookie the shared jar adds still lands in Chrome's slot
		i := len(order)
		if target.Scheme != "http" {
			i--
		}
		order = append(order[:i], append([]string{"cookie"}, order[i:]...)...)
	}
	h[fhttp.HeaderOrderKey] = order
	h[fhttp.PHeaderOrderKey] = chromePseudoOrder
	return h, nil
}

// Chrome's pseudo-header order on HTTP/2.
var chromePseudoOrder = []string{":method", ":authority", ":scheme", ":path"}
