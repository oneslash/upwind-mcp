package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	DefaultRegion         = "us"
	DefaultRequestTimeout = 30 * time.Second
	DefaultHTTPAddr       = "127.0.0.1:8080"
	DefaultHTTPPath       = "/mcp"
	DefaultAuthURL        = "https://auth.upwind.io/oauth/token"
)

type Config struct {
	Region          string
	BaseURL         string
	OrganizationID  string
	ClientID        string
	ClientSecret    string
	RequestTimeout  time.Duration
	HTTPAddr        string
	HTTPPath        string
	HTTPBearerToken string
	AuthURL         string
}

func LoadFromEnv() (*Config, error) {
	envFile, err := loadDotEnv(".env")
	if err != nil {
		return nil, err
	}

	requestTimeout := DefaultRequestTimeout
	if raw := strings.TrimSpace(getenv("UPWIND_REQUEST_TIMEOUT", envFile)); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("parse UPWIND_REQUEST_TIMEOUT: %w", err)
		}
		requestTimeout = parsed
	}

	cfg := &Config{
		Region:          normalizeRegion(getenv("UPWIND_REGION", envFile)),
		BaseURL:         strings.TrimSpace(getenv("UPWIND_BASE_URL", envFile)),
		OrganizationID:  strings.TrimSpace(getenv("UPWIND_ORGANIZATION_ID", envFile)),
		ClientID:        strings.TrimSpace(getenv("UPWIND_CLIENT_ID", envFile)),
		ClientSecret:    strings.TrimSpace(getenv("UPWIND_CLIENT_SECRET", envFile)),
		RequestTimeout:  requestTimeout,
		HTTPAddr:        defaultIfEmpty(strings.TrimSpace(getenv("UPWIND_MCP_HTTP_ADDR", envFile)), DefaultHTTPAddr),
		HTTPPath:        normalizeHTTPPath(getenv("UPWIND_MCP_HTTP_PATH", envFile)),
		HTTPBearerToken: strings.TrimSpace(getenv("UPWIND_MCP_HTTP_BEARER_TOKEN", envFile)),
		AuthURL:         DefaultAuthURL,
	}

	return cfg, nil
}

func loadDotEnv(filename string) (map[string]string, error) {
	values, err := godotenv.Read(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", filename, err)
	}

	return values, nil
}

func getenv(key string, fallback map[string]string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback[key]
}

func (c *Config) EffectiveBaseURL() (string, error) {
	if c.BaseURL != "" {
		baseURL, err := normalizeURL(c.BaseURL)
		if err != nil {
			return "", fmt.Errorf("invalid UPWIND_BASE_URL: %w", err)
		}
		return baseURL, nil
	}

	switch normalizeRegion(c.Region) {
	case "us":
		return "https://api.upwind.io", nil
	case "eu":
		return "https://api.eu.upwind.io", nil
	case "me":
		return "https://api.me.upwind.io", nil
	default:
		return "", fmt.Errorf("unsupported UPWIND_REGION %q", c.Region)
	}
}

func (c *Config) OAuthAudience() (string, error) {
	return c.EffectiveBaseURL()
}

func (c *Config) MissingUpwindEnvVars() []string {
	var missing []string
	if c.OrganizationID == "" {
		missing = append(missing, "UPWIND_ORGANIZATION_ID")
	}
	if c.ClientID == "" {
		missing = append(missing, "UPWIND_CLIENT_ID")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "UPWIND_CLIENT_SECRET")
	}
	return missing
}

func normalizeRegion(region string) string {
	region = strings.TrimSpace(strings.ToLower(region))
	if region == "" {
		return DefaultRegion
	}
	return region
}

func normalizeHTTPPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultHTTPPath
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(raw, "/"))
	if cleaned == "." {
		return DefaultHTTPPath
	}
	return cleaned
}

func normalizeURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("URL must include scheme and host")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
