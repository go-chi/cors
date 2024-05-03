package cors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("bar"))
})

var allHeaders = []string{
	"Vary",
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Credentials",
	"Access-Control-Max-Age",
	"Access-Control-Expose-Headers",
}

func assertHeaders(t *testing.T, resHeaders http.Header, expHeaders map[string]string) {
	for _, name := range allHeaders {
		got := strings.Join(resHeaders[name], ", ")
		want := expHeaders[name]
		if got != want {
			t.Errorf("Response header %q = %q, want %q", name, got, want)
		}
	}
}

func assertResponse(t *testing.T, res *httptest.ResponseRecorder, responseCode int) {
	if responseCode != res.Code {
		t.Errorf("assertResponse: expected response code to be %d but got %d. ", responseCode, res.Code)
	}
}

func customErrorHandler(w http.ResponseWriter, _ *http.Request, cors Cors, err error) bool {
	_, ok := err.(Error)
	if ok {
		cors.logf("%v", err)
		res := struct {
			Message string `json:"message"`
		}{
			Message: "CORS error: " + err.Error(),
		}
		switch {
		case errors.Is(err, &PreflightNotOptionMethodError{}):
			fallthrough
		case errors.Is(err, &PreflightNotAllowedMethodError{}):
			fallthrough
		case errors.Is(err, &ActualMethodNotAllowedError{}):
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
		if err := json.NewEncoder(w).Encode(res); err != nil {
			cors.logf("CORS error encoding failed: %v", err)
		}
		return false
	}
	res := struct {
		Message string `json:"message"`
	}{
		Message: "CORS error: An unexpected error has occurred",
	}
	if err := json.NewEncoder(w).Encode(res); err != nil {
		cors.logf("CORS error encoding failed: %v", err)
	}
	return false
}

func TestSpec(t *testing.T) {
	cases := []struct {
		name       string
		options    Options
		method     string
		reqHeaders map[string]string
		resHeaders map[string]string
		resCode    int
	}{
		{
			"NoConfig",
			Options{
				// Intentionally left blank.
			},
			"GET",
			map[string]string{},
			map[string]string{
				"Vary": "Origin",
			},
			http.StatusOK,
		},
		{
			"OnlyCustomErrorHandler",
			Options{
				ErrorHandler: customErrorHandler,
			},
			"GET",
			map[string]string{},
			map[string]string{
				"Vary": "Origin",
			},
			http.StatusForbidden,
		},
		{
			"MatchAllOrigin",
			Options{
				AllowedOrigins: []string{"*"},
			},
			"GET",
			map[string]string{
				"Origin": "http://foobar.com",
			},
			map[string]string{
				"Vary":                        "Origin",
				"Access-Control-Allow-Origin": "*",
			},
			http.StatusOK,
		},
		{
			"MatchAllOriginWithCustomErrorHandler",
			Options{
				AllowedOrigins: []string{"*"},
				ErrorHandler:   customErrorHandler,
			},
			"GET",
			map[string]string{
				"Origin": "http://foobar.com",
			},
			map[string]string{
				"Vary":                        "Origin",
				"Access-Control-Allow-Origin": "*",
			},
			http.StatusOK,
		},
		{
			"MatchAllOriginWithCredentials",
			Options{
				AllowedOrigins:   []string{"*"},
				AllowCredentials: true,
			},
			"GET",
			map[string]string{
				"Origin": "http://foobar.com",
			},
			map[string]string{
				"Vary":                             "Origin",
				"Access-Control-Allow-Origin":      "*",
				"Access-Control-Allow-Credentials": "true",
			},
			http.StatusOK,
		},
		{
			"AllowedOrigin",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
			},
			"GET",
			map[string]string{
				"Origin": "http://foobar.com",
			},
			map[string]string{
				"Vary":                        "Origin",
				"Access-Control-Allow-Origin": "http://foobar.com",
			},
			http.StatusOK,
		},
		{
			"WildcardOrigin",
			Options{
				AllowedOrigins: []string{"http://*.bar.com"},
			},
			"GET",
			map[string]string{
				"Origin": "http://foo.bar.com",
			},
			map[string]string{
				"Vary":                        "Origin",
				"Access-Control-Allow-Origin": "http://foo.bar.com",
			},
			http.StatusOK,
		},
		{
			"DisallowedOrigin",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
			},
			"GET",
			map[string]string{
				"Origin": "http://barbaz.com",
			},
			map[string]string{
				"Vary": "Origin",
			},
			http.StatusOK,
		},
		{
			"DisallowedOriginWithCustomErrorHandler",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				ErrorHandler:   customErrorHandler,
			},
			"GET",
			map[string]string{
				"Origin": "http://barbaz.com",
			},
			map[string]string{
				"Vary": "Origin",
			},
			http.StatusForbidden,
		},
		{
			"DisallowedWildcardOrigin",
			Options{
				AllowedOrigins: []string{"http://*.bar.com"},
			},
			"GET",
			map[string]string{
				"Origin": "http://foo.baz.com",
			},
			map[string]string{
				"Vary": "Origin",
			},
			http.StatusOK,
		},
		{
			"AllowedOriginFuncMatch",
			Options{
				AllowOriginFunc: func(r *http.Request, o string) bool {
					return regexp.MustCompile("^http://foo").MatchString(o) && r.Header.Get("Authorization") == "secret"
				},
			},
			"GET",
			map[string]string{
				"Origin":        "http://foobar.com",
				"Authorization": "secret",
			},
			map[string]string{
				"Vary":                        "Origin",
				"Access-Control-Allow-Origin": "http://foobar.com",
			},
			http.StatusOK,
		},
		{
			"AllowOriginFuncNotMatch",
			Options{
				AllowOriginFunc: func(r *http.Request, o string) bool {
					return regexp.MustCompile("^http://foo").MatchString(o) && r.Header.Get("Authorization") == "secret"
				},
			},
			"GET",
			map[string]string{
				"Origin":        "http://foobar.com",
				"Authorization": "not-secret",
			},
			map[string]string{
				"Vary": "Origin",
			},
			http.StatusOK,
		},
		{
			"MaxAge",
			Options{
				AllowedOrigins: []string{"http://example.com/"},
				AllowedMethods: []string{"GET"},
				MaxAge:         10,
			},
			"OPTIONS",
			map[string]string{
				"Origin":                        "http://example.com/",
				"Access-Control-Request-Method": "GET",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "http://example.com/",
				"Access-Control-Allow-Methods": "GET",
				"Access-Control-Max-Age":       "10",
			},
			http.StatusOK,
		},
		{
			"AllowedMethod",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedMethods: []string{"PUT", "DELETE"},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                        "http://foobar.com",
				"Access-Control-Request-Method": "PUT",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "http://foobar.com",
				"Access-Control-Allow-Methods": "PUT",
			},
			http.StatusOK,
		},
		{
			"DisallowedMethod",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedMethods: []string{"PUT", "DELETE"},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                        "http://foobar.com",
				"Access-Control-Request-Method": "PATCH",
			},
			map[string]string{
				"Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
			},
			http.StatusOK,
		},
		{
			"DisallowedMethodWithCustomErrorHandler",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedMethods: []string{"PUT", "DELETE"},
				ErrorHandler:   customErrorHandler,
			},
			"OPTIONS",
			map[string]string{
				"Origin":                        "http://foobar.com",
				"Access-Control-Request-Method": "PATCH",
			},
			map[string]string{
				"Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
			},
			http.StatusMethodNotAllowed,
		},
		{
			"AllowedHeaders",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedHeaders: []string{"X-Header-1", "x-header-2"},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                         "http://foobar.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "X-Header-2, X-HEADER-1",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "http://foobar.com",
				"Access-Control-Allow-Methods": "GET",
				"Access-Control-Allow-Headers": "X-Header-2, X-Header-1",
			},
			http.StatusOK,
		},
		{
			"DefaultAllowedHeaders",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedHeaders: []string{},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                         "http://foobar.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "Content-Type",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "http://foobar.com",
				"Access-Control-Allow-Methods": "GET",
				"Access-Control-Allow-Headers": "Content-Type",
			},
			http.StatusOK,
		},
		{
			"AllowedWildcardHeader",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedHeaders: []string{"*"},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                         "http://foobar.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "X-Header-2, X-HEADER-1",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "http://foobar.com",
				"Access-Control-Allow-Methods": "GET",
				"Access-Control-Allow-Headers": "X-Header-2, X-Header-1",
			},
			http.StatusOK,
		},
		{
			"DisallowedHeader",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				AllowedHeaders: []string{"X-Header-1", "x-header-2"},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                         "http://foobar.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "X-Header-3, X-Header-1",
			},
			map[string]string{
				"Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
			},
			http.StatusOK,
		},
		{
			"OriginHeader",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
			},
			"OPTIONS",
			map[string]string{
				"Origin":                         "http://foobar.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "origin",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "http://foobar.com",
				"Access-Control-Allow-Methods": "GET",
				"Access-Control-Allow-Headers": "Origin",
			},
			http.StatusOK,
		},
		{
			"ExposedHeader",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
				ExposedHeaders: []string{"X-Header-1", "x-header-2"},
			},
			"GET",
			map[string]string{
				"Origin": "http://foobar.com",
			},
			map[string]string{
				"Vary":                          "Origin",
				"Access-Control-Allow-Origin":   "http://foobar.com",
				"Access-Control-Expose-Headers": "X-Header-1, X-Header-2",
			},
			http.StatusOK,
		},
		{
			"AllowedCredentials",
			Options{
				AllowedOrigins:   []string{"http://foobar.com"},
				AllowCredentials: true,
			},
			"OPTIONS",
			map[string]string{
				"Origin":                        "http://foobar.com",
				"Access-Control-Request-Method": "GET",
			},
			map[string]string{
				"Vary":                             "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":      "http://foobar.com",
				"Access-Control-Allow-Methods":     "GET",
				"Access-Control-Allow-Credentials": "true",
			},
			http.StatusOK,
		},
		{
			"OptionPassthrough",
			Options{
				OptionsPassthrough: true,
			},
			"OPTIONS",
			map[string]string{
				"Origin":                        "http://foobar.com",
				"Access-Control-Request-Method": "GET",
			},
			map[string]string{
				"Vary":                         "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET",
			},
			http.StatusOK,
		},
		{
			"NonPreflightOptions",
			Options{
				AllowedOrigins: []string{"http://foobar.com"},
			},
			"OPTIONS",
			map[string]string{
				"Origin": "http://foobar.com",
			},
			map[string]string{
				"Vary":                        "Origin",
				"Access-Control-Allow-Origin": "http://foobar.com",
			},
			http.StatusOK,
		},
	}
	for i := range cases {
		tc := cases[i]
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.options)

			req, _ := http.NewRequest(tc.method, "http://example.com/foo", nil)
			for name, value := range tc.reqHeaders {
				req.Header.Add(name, value)
			}

			t.Run("Handler", func(t *testing.T) {
				res := httptest.NewRecorder()
				s.Handler(testHandler).ServeHTTP(res, req)
				assertHeaders(t, res.Header(), tc.resHeaders)
				assertResponse(t, res, tc.resCode)
			})
		})
	}
}

func TestDebug(t *testing.T) {
	s := New(Options{
		Debug: true,
	})

	if s.Log == nil {
		t.Error("Logger not created when debug=true")
	}
}

func TestDefault(t *testing.T) {
	s := New(Options{})
	if s.Log != nil {
		t.Error("c.log should be nil when Default")
	}
	if !s.allowedOriginsAll {
		t.Error("c.allowedOriginsAll should be true when Default")
	}
	if s.allowedHeaders == nil {
		t.Error("c.allowedHeaders should be nil when Default")
	}
	if s.allowedMethods == nil {
		t.Error("c.allowedMethods should be nil when Default")
	}
	if s.errorHandler == nil {
		t.Error("c.errorHandler must not be nil when Default")
	}
}

func TestHandlePreflightInvalidOriginAbortion(t *testing.T) {
	s := New(Options{
		AllowedOrigins: []string{"http://foo.com"},
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	s.handlePreflight(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
	})
}

func TestHandlePreflightInvalidOriginAbortionWithErrorHandler(t *testing.T) {
	s := New(Options{
		AllowedOrigins: []string{"http://foo.com"},
		ErrorHandler:   customErrorHandler,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	s.handlePreflight(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
	})
	assertResponse(t, res, http.StatusForbidden)
}

func TestHandlePreflightNoOptionsAbortion(t *testing.T) {
	s := New(Options{
		// Intentionally left blank.
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s.handlePreflight(res, req)

	assertHeaders(t, res.Header(), map[string]string{})
}

func TestHandlePreflightOnlyErrorHandleOptionAbortion(t *testing.T) {
	s := New(Options{
		ErrorHandler: customErrorHandler,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s.handlePreflight(res, req)

	assertHeaders(t, res.Header(), map[string]string{})
	assertResponse(t, res, http.StatusMethodNotAllowed)
}

func TestHandleActualRequestInvalidOriginAbortion(t *testing.T) {
	s := New(Options{
		AllowedOrigins: []string{"http://foo.com"},
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	s.handleActualRequest(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary": "Origin",
	})
}

func TestHandleActualRequestInvalidOriginAbortionWithErrorHandler(t *testing.T) {
	s := New(Options{
		AllowedOrigins: []string{"http://foo.com"},
		ErrorHandler:   customErrorHandler,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	s.handleActualRequest(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary": "Origin",
	})
	assertResponse(t, res, http.StatusForbidden)
}

func TestHandleActualRequestInvalidMethodAbortion(t *testing.T) {
	s := New(Options{
		AllowedMethods:   []string{"POST"},
		AllowCredentials: true,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	s.handleActualRequest(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary": "Origin",
	})
}

func TestHandleActualRequestInvalidMethodAbortionWithErrorHandler(t *testing.T) {
	s := New(Options{
		AllowedMethods:   []string{"POST"},
		AllowCredentials: true,
		ErrorHandler:     customErrorHandler,
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Add("Origin", "http://example.com/")

	s.handleActualRequest(res, req)

	assertHeaders(t, res.Header(), map[string]string{
		"Vary": "Origin",
	})
	assertResponse(t, res, http.StatusMethodNotAllowed)
}

func TestIsMethodAllowedReturnsFalseWithNoMethods(t *testing.T) {
	s := New(Options{
		// Intentionally left blank.
	})
	s.allowedMethods = []string{}
	if s.isMethodAllowed("") {
		t.Error("IsMethodAllowed should return false when c.allowedMethods is nil.")
	}
}

func TestIsMethodAllowedReturnsTrueWithOptions(t *testing.T) {
	s := New(Options{
		// Intentionally left blank.
	})
	if !s.isMethodAllowed("OPTIONS") {
		t.Error("IsMethodAllowed should return true when c.allowedMethods is nil.")
	}
}
