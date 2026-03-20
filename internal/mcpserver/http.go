package mcpserver

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"upwind-mcp/internal/config"
)

type HTTPOptions struct {
	AllowPublicBind bool
}

func RunStdio(ctx context.Context, server *mcp.Server) error {
	err := server.Run(ctx, &mcp.StdioTransport{})
	if err == nil {
		slog.Info("stdio transport stopped")
	}
	return err
}

func ServeHTTP(ctx context.Context, server *mcp.Server, cfg *config.Config, opts HTTPOptions) error {
	if err := validateHTTPBind(cfg.HTTPAddr, opts.AllowPublicBind); err != nil {
		return err
	}

	handler, err := NewHTTPHandler(server, cfg)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8 * 1024,
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	err = httpServer.ListenAndServe()
	if err == nil || err == http.ErrServerClosed {
		slog.Info("HTTP server stopped")
		return nil
	}
	return err
}

func NewHTTPHandler(server *mcp.Server, cfg *config.Config) (http.Handler, error) {
	if strings.TrimSpace(cfg.HTTPBearerToken) == "" {
		return nil, fmt.Errorf("UPWIND_MCP_HTTP_BEARER_TOKEN is required for HTTP mode")
	}

	streamable := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		_ = r
		return server
	}, &mcp.StreamableHTTPOptions{
		SessionTimeout: 5 * time.Minute,
	})

	mux := http.NewServeMux()
	mux.Handle(cfg.HTTPPath, RequireStaticBearerToken(cfg.HTTPBearerToken)(streamable))
	return mux, nil
}

func RequireStaticBearerToken(expectedToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
			if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}

			token := strings.TrimSpace(authHeader[len("Bearer "):])
			if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "invalid bearer token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func validateHTTPBind(addr string, allowPublic bool) error {
	if allowPublic {
		return nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid HTTP address %q: %w", addr, err)
	}

	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}

	return fmt.Errorf("refusing non-loopback HTTP bind %q without --public-bind", addr)
}
