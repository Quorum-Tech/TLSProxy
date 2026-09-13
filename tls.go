package main

import (
	"bytes"
	"io"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// maxBody caps a response read into memory.
const maxBody = 32 << 20

type sendOptions struct {
	jar             *cookiejar.Jar
	timeoutSeconds  int
	followRedirects bool
	proxyURL        string // empty goes out directly
}

// SendTLSRequest sends one request with Chrome's TLS hello and HTTP/2
// settings. The proxy, if any, only carries the connection: the fingerprint
// is the same either way.
func SendTLSRequest(method string, url string, headers fhttp.Header, payload []byte, o sendOptions) ([]byte, fhttp.Header, int, error) {
	jar := o.jar
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(o.timeoutSeconds),
		// Chrome_152's JA4 is real Chrome 153's exactly (t13d1517h2_8daaf6152771_cb7bf5808d99, measured
		// on tls.peet.ws 2026-09-13); Chrome_150 lacks the extension Chrome now sends (0xca34)
		tls_client.WithClientProfile(profiles.Chrome_152),
		// Chrome shuffles its extensions on every connection
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithCookieJar(jar),
	}
	if !o.followRedirects {
		options = append(options, tls_client.WithNotFollowRedirects())
	}
	if o.proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(o.proxyURL))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, nil, 500, err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewBuffer(payload)
	}
	req, err := fhttp.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, 500, err
	}
	req.Header = headers
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, 500, err
	}
	defer res.Body.Close()
	rd := io.ReadCloser(res.Body)
	// a body we asked to have compressed (accept-encoding set by hand) arrives compressed
	if !res.Uncompressed && res.Header.Get("Content-Encoding") != "" {
		rd = fhttp.DecompressBody(res)
	}
	data, err := io.ReadAll(io.LimitReader(rd, maxBody))
	if err != nil {
		return nil, nil, 500, err
	}
	return data, res.Header, res.StatusCode, nil
}
