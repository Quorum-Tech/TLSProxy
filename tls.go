package main

import (
	"bytes"
	"errors"
	"io"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// maxBody caps a response read into memory. A larger body is an error, never a silent cut:
// a caller would otherwise read the first 32 MB of a page as the whole of it.
const maxBody = 32 << 20

var errTooLarge = errors.New("response_too_large")

type sendOptions struct {
	jar             *cookiejar.Jar
	timeoutSeconds  int
	followRedirects bool
	proxyURL        string // empty goes out directly
	insecure        bool   // accept any certificate: header capture tests only
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
	if o.insecure {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, nil, 500, err
	}
	// the client lives for this request alone: left open, its keep-alive connection (or
	// proxy tunnel) would sit idle until the transport's timeout, one per request
	defer client.CloseIdleConnections()
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
	// one byte past the cap tells a body that is exactly the cap from one that was cut off
	data, err := io.ReadAll(io.LimitReader(rd, maxBody+1))
	if err != nil {
		return nil, nil, 500, err
	}
	if len(data) > maxBody {
		return nil, nil, 500, errTooLarge
	}
	return data, res.Header, res.StatusCode, nil
}
