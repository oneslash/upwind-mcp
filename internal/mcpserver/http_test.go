package mcpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"upwind-mcp/internal/config"
)

func TestRequireStaticBearerToken(t *testing.T) {
	protected := RequireStaticBearerToken("secret-token")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "invalid", authHeader: "Bearer nope", wantStatus: http.StatusUnauthorized},
		{name: "valid", authHeader: "Bearer secret-token", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestNewHTTPHandlerRequiresBearerToken(t *testing.T) {
	cfg := &config.Config{
		Region:         "us",
		RequestTimeout: 5 * time.Second,
		HTTPAddr:       config.DefaultHTTPAddr,
		HTTPPath:       config.DefaultHTTPPath,
	}

	_, err := NewHTTPHandler(New(cfg), cfg)
	if err == nil {
		t.Fatal("NewHTTPHandler() error = nil, want error")
	}
}

func TestNewHTTPHandlerAcceptsBearerToken(t *testing.T) {
	cfg := &config.Config{
		Region:          "us",
		RequestTimeout:  5 * time.Second,
		HTTPAddr:        config.DefaultHTTPAddr,
		HTTPPath:        config.DefaultHTTPPath,
		HTTPBearerToken: "local-test-token",
	}

	_, err := NewHTTPHandler(New(cfg), cfg)
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
}

func TestServeHTTPRejectsPublicBindWithoutFlag(t *testing.T) {
	cfg := &config.Config{
		Region:          "us",
		RequestTimeout:  5 * time.Second,
		HTTPAddr:        "0.0.0.0:8080",
		HTTPPath:        config.DefaultHTTPPath,
		HTTPBearerToken: "local-test-token",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := ServeHTTP(ctx, mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0.0.1"}, nil), cfg, HTTPOptions{})
	if err == nil {
		t.Fatal("ServeHTTP() error = nil, want error")
	}
}
