package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromEnvDefaults(t *testing.T) {
	t.Setenv("UPWIND_REGION", "")
	t.Setenv("UPWIND_BASE_URL", "")
	t.Setenv("UPWIND_REQUEST_TIMEOUT", "")
	t.Setenv("UPWIND_MCP_HTTP_ADDR", "")
	t.Setenv("UPWIND_MCP_HTTP_PATH", "")
	t.Setenv("UPWIND_MCP_HTTP_BEARER_TOKEN", "")
	t.Setenv("UPWIND_ORGANIZATION_ID", "")
	t.Setenv("UPWIND_CLIENT_ID", "")
	t.Setenv("UPWIND_CLIENT_SECRET", "")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}

	if cfg.Region != DefaultRegion {
		t.Fatalf("Region = %q, want %q", cfg.Region, DefaultRegion)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Fatalf("RequestTimeout = %v, want %v", cfg.RequestTimeout, DefaultRequestTimeout)
	}
	if cfg.HTTPAddr != DefaultHTTPAddr {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, DefaultHTTPAddr)
	}
	if cfg.HTTPPath != DefaultHTTPPath {
		t.Fatalf("HTTPPath = %q, want %q", cfg.HTTPPath, DefaultHTTPPath)
	}
	if cfg.AuthURL != DefaultAuthURL {
		t.Fatalf("AuthURL = %q, want %q", cfg.AuthURL, DefaultAuthURL)
	}
}

func TestLoadFromEnvParsesOverrides(t *testing.T) {
	t.Setenv("UPWIND_REGION", "eu")
	t.Setenv("UPWIND_BASE_URL", "https://example.internal/api/")
	t.Setenv("UPWIND_REQUEST_TIMEOUT", "45s")
	t.Setenv("UPWIND_MCP_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("UPWIND_MCP_HTTP_PATH", "custom/mcp")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}

	if cfg.Region != "eu" {
		t.Fatalf("Region = %q, want eu", cfg.Region)
	}
	if cfg.BaseURL != "https://example.internal/api/" {
		t.Fatalf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.RequestTimeout != 45*time.Second {
		t.Fatalf("RequestTimeout = %v, want 45s", cfg.RequestTimeout)
	}
	if cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.HTTPPath != "/custom/mcp" {
		t.Fatalf("HTTPPath = %q, want /custom/mcp", cfg.HTTPPath)
	}
}

func TestLoadFromEnvLoadsDotEnv(t *testing.T) {
	tempDir := t.TempDir()
	chdir(t, tempDir)

	if err := os.WriteFile(filepath.Join(tempDir, ".env"), []byte("UPWIND_REGION=eu\nUPWIND_CLIENT_ID=dotenv-client\nUPWIND_REQUEST_TIMEOUT=15s\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(.env) returned error: %v", err)
	}

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}

	if cfg.Region != "eu" {
		t.Fatalf("Region = %q, want eu", cfg.Region)
	}
	if cfg.ClientID != "dotenv-client" {
		t.Fatalf("ClientID = %q, want dotenv-client", cfg.ClientID)
	}
	if cfg.RequestTimeout != 15*time.Second {
		t.Fatalf("RequestTimeout = %v, want 15s", cfg.RequestTimeout)
	}
}

func TestLoadFromEnvDoesNotOverrideProcessEnvWithDotEnv(t *testing.T) {
	tempDir := t.TempDir()
	chdir(t, tempDir)

	if err := os.WriteFile(filepath.Join(tempDir, ".env"), []byte("UPWIND_REGION=eu\nUPWIND_CLIENT_ID=dotenv-client\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(.env) returned error: %v", err)
	}

	t.Setenv("UPWIND_REGION", "me")
	t.Setenv("UPWIND_CLIENT_ID", "process-client")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}

	if cfg.Region != "me" {
		t.Fatalf("Region = %q, want me", cfg.Region)
	}
	if cfg.ClientID != "process-client" {
		t.Fatalf("ClientID = %q, want process-client", cfg.ClientID)
	}
}

func TestLoadFromEnvReloadsDotEnvWithoutMutatingProcessEnv(t *testing.T) {
	tempDir := t.TempDir()
	chdir(t, tempDir)

	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte("UPWIND_CLIENT_ID=first-client\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(.env) returned error: %v", err)
	}

	first, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if first.ClientID != "first-client" {
		t.Fatalf("first ClientID = %q, want first-client", first.ClientID)
	}

	if err := os.WriteFile(envPath, []byte("UPWIND_CLIENT_ID=second-client\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(.env) returned error: %v", err)
	}

	second, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if second.ClientID != "second-client" {
		t.Fatalf("second ClientID = %q, want second-client", second.ClientID)
	}
}

func TestEffectiveBaseURLAndAudience(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantURL string
		wantErr bool
	}{
		{name: "default us", cfg: Config{Region: "us"}, wantURL: "https://api.upwind.io"},
		{name: "eu", cfg: Config{Region: "eu"}, wantURL: "https://api.eu.upwind.io"},
		{name: "me", cfg: Config{Region: "me"}, wantURL: "https://api.me.upwind.io"},
		{name: "override", cfg: Config{BaseURL: "https://proxy.example.com/base/"}, wantURL: "https://proxy.example.com/base"},
		{name: "invalid region", cfg: Config{Region: "nope"}, wantErr: true},
		{name: "invalid override", cfg: Config{BaseURL: "://bad"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, err := tt.cfg.EffectiveBaseURL()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("EffectiveBaseURL() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("EffectiveBaseURL() error = %v", err)
			}
			if gotURL != tt.wantURL {
				t.Fatalf("EffectiveBaseURL() = %q, want %q", gotURL, tt.wantURL)
			}

			audience, err := tt.cfg.OAuthAudience()
			if err != nil {
				t.Fatalf("OAuthAudience() error = %v", err)
			}
			if audience != tt.wantURL {
				t.Fatalf("OAuthAudience() = %q, want %q", audience, tt.wantURL)
			}
		})
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%q) returned error: %v", dir, err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory to %q: %v", wd, err)
		}
	})
}
