package main

import (
	"fmt"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
)

// chromeMajor is the Chrome version the headers claim: current stable. The
// TLS profile in tls.go must send the hello that version sends; raise this with
// each stable release and re-check the hello against a real Chrome on
// tls.peet.ws (JA4 and the HTTP/2 fingerprint).
const chromeMajor = 154

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

type header struct{ name, value string }

// navigateHeaders are a top-level navigation typed into the address bar, in
// the order Chrome sends them (captured from Chrome 153 on macOS against
// tls.peet.ws; the order has been stable since the priority header arrived in
// Chrome 124).
func navigateHeaders(major int) []header {
	return []header{
		{"sec-ch-ua", secChUa(major)},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"macOS"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", major)},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	}
}

// Chrome's pseudo-header order on HTTP/2.
var chromePseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

// presetHeaders builds a request's headers from a preset, in order. A header
// the caller sets replaces the preset's value in place; one the preset lacks
// goes on the end. Names are lower-cased, as HTTP/2 sends them.
func presetHeaders(preset string, custom map[string]string) (fhttp.Header, error) {
	var base []header
	switch preset {
	case "navigate":
		base = navigateHeaders(chromeMajor)
	default:
		return nil, fmt.Errorf("unknown preset %q", preset)
	}
	h := fhttp.Header{}
	order := make([]string, 0, len(base)+len(custom))
	seen := map[string]bool{}
	for _, b := range base {
		v := b.value
		for k, cv := range custom {
			if strings.EqualFold(k, b.name) {
				v = cv
			}
		}
		h[b.name] = []string{v}
		order = append(order, b.name)
		seen[b.name] = true
	}
	extra := make([]string, 0)
	for k := range custom {
		if !seen[strings.ToLower(k)] {
			extra = append(extra, k)
		}
	}
	sortStrings(extra)
	for _, k := range extra {
		n := strings.ToLower(k)
		h[n] = []string{custom[k]}
		order = append(order, n)
	}
	h[fhttp.HeaderOrderKey] = order
	h[fhttp.PHeaderOrderKey] = chromePseudoOrder
	return h, nil
}

// a map's keys come out in random order; extra headers are sorted so a request is repeatable
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
