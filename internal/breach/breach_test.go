package breach

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	sha1Password = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8" // sha1("password")
)

func newTestServer(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/range/") {
			t.Errorf("path = %q, esperado /range/", r.URL.Path)
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.hc.Transport = srv.Client().Transport
	// point to the test server: override endpoint via a custom RoundTripper
	c.hc.Transport = &rt{base: srv.URL, next: srv.Client().Transport}
	return c
}

type rt struct {
	base string
	next http.RoundTripper
}

func (r *rt) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return r.next.RoundTrip(clone)
}

func TestCheckFound(t *testing.T) {
	// sha1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// prefijo k-anónimo 5BAA6, sufijo 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	c := newTestServer(t, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3010555\n")
	rep, err := c.Check("password")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Found {
		t.Error("debería aparecer en la filtración")
	}
	if rep.Count != 3010555 {
		t.Errorf("count = %d, esperado 3010555", rep.Count)
	}
	// hash consultado: prefix SHA-1 en minúsculas (hex.EncodeToString)
	if !strings.HasPrefix(rep.Hash, "5baa6") {
		t.Errorf("prefix sha1 corto: %s", rep.Hash)
	}
}

func TestCheckNotFound(t *testing.T) {
	c := newTestServer(t, "AAAAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\nBBBB0000000000000000000000000000:2\n")
	rep, err := c.Check("N0t-4-Real-Passw0rd-XyZ")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Found {
		t.Error("no debería encontrarse")
	}
}

func TestCheckTransportError(t *testing.T) {
	c := New()
	c.hc.Timeout = 20 // ms; connection refused quickly
	_, err := c.Check("password")
	if err == nil {
		t.Error("debería devolver error con transporte roto")
	}
}
