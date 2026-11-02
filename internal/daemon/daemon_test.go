package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestVersion(t *testing.T) {
	rec := httptest.NewRecorder()
	Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
