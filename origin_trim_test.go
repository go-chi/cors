package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedOriginsTrimSpace(t *testing.T) {
	c := New(Options{
		AllowedOrigins: []string{" http://example.com ", "", "http://foo.com"},
		AllowedMethods: []string{"GET"},
	})
	h := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	req.Header.Set("Origin", "http://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Fatalf("headers=%v", rr.Header())
	}
}
