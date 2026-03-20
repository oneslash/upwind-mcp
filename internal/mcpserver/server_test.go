package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"upwind-mcp/internal/config"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("UPWIND_MCP_STDIO_HELPER") != "1" {
		return
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if err := RunStdio(context.Background(), New(cfg)); err != nil {
		t.Fatalf("RunStdio() error = %v", err)
	}
	os.Exit(0)
}

func TestServerStartsWithoutUpwindCredentials(t *testing.T) {
	cfg := &config.Config{
		Region:         "us",
		RequestTimeout: 5 * time.Second,
		HTTPAddr:       config.DefaultHTTPAddr,
		HTTPPath:       config.DefaultHTTPPath,
	}

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	server := New(cfg)
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	defer func() { _ = serverSession.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer func() { _ = clientSession.Close() }()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "upwind_search_assets",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error for missing credentials")
	}
}

func TestStdioIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"UPWIND_MCP_STDIO_HELPER=1",
		"UPWIND_REGION=us",
	)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer func() { _ = session.Close() }()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("expected at least one tool")
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "upwind_server_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatal("status tool returned tool error over stdio")
	}
}

func TestStreamableHTTPIntegration(t *testing.T) {
	cfg := &config.Config{
		Region:          "us",
		RequestTimeout:  5 * time.Second,
		HTTPAddr:        config.DefaultHTTPAddr,
		HTTPPath:        config.DefaultHTTPPath,
		HTTPBearerToken: "local-test-token",
	}

	handler, err := NewHTTPHandler(New(cfg), cfg)
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()

	httpClient := &http.Client{
		Transport: bearerRoundTripper{
			token: "local-test-token",
			base:  http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   httpServer.URL + cfg.HTTPPath,
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer func() { _ = session.Close() }()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "upwind_server_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatal("status tool returned tool error")
	}
}

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (rt bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+rt.token)

	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}
