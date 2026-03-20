package upwind

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"upwind-mcp/internal/config"
)

const testAccessToken = "static-token"

func TestTokenCachingAndRefresh(t *testing.T) {
	var authCalls atomic.Int32
	currentTime := time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)
	var apiBaseURL string

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := authCalls.Add(1)
		_ = r.ParseForm()
		if got := r.Form.Get("audience"); got != apiBaseURL {
			t.Fatalf("audience = %q, want %s", got, apiBaseURL)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-" + string(rune('0'+call)),
			"expires_in":   60,
			"token_type":   "Bearer",
		})
	}))
	defer authServer.Close()

	var apiCalls atomic.Int32
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := apiCalls.Add(1)
		wantToken := "Bearer token-1"
		if call == 3 {
			wantToken = "Bearer token-2"
		}
		if got := r.Header.Get("Authorization"); got != wantToken {
			t.Fatalf("Authorization = %q, want %q", got, wantToken)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":    []any{},
			"metadata": map[string]any{"next_cursor": "next-1"},
		})
	}))
	defer apiServer.Close()
	apiBaseURL = apiServer.URL

	cfg := &config.Config{
		BaseURL:        apiServer.URL,
		AuthURL:        authServer.URL,
		OrganizationID: "org_123",
		ClientID:       "client",
		ClientSecret:   "secret",
		RequestTimeout: 5 * time.Second,
	}
	client := NewClient(cfg, WithNowFunc(func() time.Time { return currentTime }))

	ctx := context.Background()
	if _, err := client.ListThreatStories(ctx, ListThreatStoriesInput{}); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	currentTime = currentTime.Add(20 * time.Second)
	if _, err := client.ListThreatStories(ctx, ListThreatStoriesInput{}); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	currentTime = currentTime.Add(15 * time.Second)
	if _, err := client.ListThreatStories(ctx, ListThreatStoriesInput{}); err != nil {
		t.Fatalf("third call failed: %v", err)
	}

	if got := authCalls.Load(); got != 2 {
		t.Fatalf("auth calls = %d, want 2", got)
	}
	if got := apiCalls.Load(); got != 3 {
		t.Fatalf("api calls = %d, want 3", got)
	}
}

func TestSearchAssetsMappingAndCursor(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v2/organizations/org_123/inventory/catalog/assets/search" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "25" {
			t.Fatalf("limit = %q", got)
		}
		if got := r.URL.Query().Get("cursor"); got != "cur-1" {
			t.Fatalf("cursor = %q", got)
		}
		body := decodeJSONBody(t, r.Body)
		conditions := body["conditions"].([]any)
		if len(conditions) != 1 {
			t.Fatalf("conditions len = %d", len(conditions))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":    []any{map[string]any{"id": "a1"}},
			"metadata": map[string]any{"next_cursor": "cur-2"},
		})
	})

	result, err := client.SearchAssets(context.Background(), SearchAssetsInput{
		PaginationInput: PaginationInput{Limit: 25, Cursor: "cur-1"},
		Conditions: []SearchCondition{{
			Field:    "label",
			Operator: "eq",
			Value:    []any{"aws_ec2_instance"},
		}},
	})
	if err != nil {
		t.Fatalf("SearchAssets() error = %v", err)
	}
	if result.NextCursor != "cur-2" {
		t.Fatalf("NextCursor = %q, want cur-2", result.NextCursor)
	}
}

func TestSearchThreatStoriesMapping(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/organizations/org_123/threats/stories/search" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("sort"); got != "update_time:desc" {
			t.Fatalf("sort = %q", got)
		}
		body := decodeJSONBody(t, r.Body)
		if len(body["conditions"].([]any)) != 1 {
			t.Fatalf("expected one condition")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":    []any{map[string]any{"id": "story-1"}},
			"metadata": map[string]any{"next_cursor": "story-next"},
		})
	})

	result, err := client.SearchThreatStories(context.Background(), SearchThreatStoriesInput{
		PaginationInput: PaginationInput{Limit: 10, Cursor: "story-cur"},
		Sort:            "update_time:desc",
		Conditions: []SearchCondition{{
			Field:    "severity",
			Operator: "eq",
			Value:    []any{"high"},
		}},
	})
	if err != nil {
		t.Fatalf("SearchThreatStories() error = %v", err)
	}
	if result.NextCursor != "story-next" {
		t.Fatalf("NextCursor = %q", result.NextCursor)
	}
}

func TestListVulnerabilityFindingsMappingAndLinkCursor(t *testing.T) {
	inUse := true
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/organizations/org_123/vulnerability-findings" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("per-page") != "50" || query.Get("page-token") != "page-1" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		if query.Get("in-use") != "true" || query.Get("severity") != "critical" || query.Get("cve-id") != "CVE-2026-0001" {
			t.Fatalf("unexpected vulnerability filters: %s", r.URL.RawQuery)
		}
		w.Header().Set("Link", `<https://api.example.com/v1/organizations/org_123/vulnerability-findings?page-token=page-2>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	})

	result, err := client.ListVulnerabilityFindings(context.Background(), ListVulnerabilityFindingsInput{
		PaginationInput: PaginationInput{Limit: 50, Cursor: "page-1"},
		InUse:           &inUse,
		Severity:        "critical",
		CVEID:           "CVE-2026-0001",
	})
	if err != nil {
		t.Fatalf("ListVulnerabilityFindings() error = %v", err)
	}
	if result.NextCursor != "page-2" {
		t.Fatalf("NextCursor = %q, want page-2", result.NextCursor)
	}
}

func TestListConfigurationFindingsMappingAndBodyCursor(t *testing.T) {
	includeTags := true
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("per-page") != "100" {
			t.Fatalf("per-page = %q", query.Get("per-page"))
		}
		if query.Get("cloud-account-tags") != "env=prod,team=platform" {
			t.Fatalf("cloud-account-tags = %q", query.Get("cloud-account-tags"))
		}
		if query.Get("include-cloud-account-tags") != "true" {
			t.Fatalf("include-cloud-account-tags = %q", query.Get("include-cloud-account-tags"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resourceFindings": []any{},
			"pagination": map[string]any{
				"nextPageToken": []any{"cfg-next"},
			},
		})
	})

	result, err := client.ListConfigurationFindings(context.Background(), ListConfigurationFindingsInput{
		PaginationInput:         PaginationInput{Limit: 100},
		CloudAccountTags:        []string{"env=prod", "team=platform"},
		IncludeCloudAccountTags: &includeTags,
	})
	if err != nil {
		t.Fatalf("ListConfigurationFindings() error = %v", err)
	}
	if result.NextCursor != "cfg-next" {
		t.Fatalf("NextCursor = %q, want cfg-next", result.NextCursor)
	}
}

func TestGetSBOMPackageDetailsEscapesPath(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/v1/organizations/org_123/sbom-packages/github.com%2Fopenai%2Fpkg/1.0.0-beta%2B1"
		if r.URL.EscapedPath() != wantPath {
			t.Fatalf("EscapedPath = %q, want %q", r.URL.EscapedPath(), wantPath)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "pkg"})
	})

	if _, err := client.GetSBOMPackageDetails(context.Background(), GetSBOMPackageDetailsInput{
		PackageName: "github.com/openai/pkg",
		Version:     "1.0.0-beta+1",
	}); err != nil {
		t.Fatalf("GetSBOMPackageDetails() error = %v", err)
	}
}

func TestListAssetSchemasWithoutMetadataLeavesNextCursorEmpty(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/organizations/org_123/inventory/schema" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Fatalf("limit = %q, want 10", got)
		}
		if got := r.URL.Query().Get("cursor"); got != "schema-cur" {
			t.Fatalf("cursor = %q, want schema-cur", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []any{map[string]any{"label": "aws_ec2_instance"}},
		})
	})

	result, err := client.ListAssetSchemas(context.Background(), ListAssetSchemasInput{
		PaginationInput: PaginationInput{Limit: 10, Cursor: "schema-cur"},
	})
	if err != nil {
		t.Fatalf("ListAssetSchemas() error = %v", err)
	}
	if result.NextCursor != "" {
		t.Fatalf("NextCursor = %q, want empty", result.NextCursor)
	}
}

func TestGetThreatStoryPreservesWrappedResponse(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/organizations/org_123/threats/stories/story-1" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []any{map[string]any{"id": "story-1"}},
		})
	})

	result, err := client.GetThreatStory(context.Background(), GetThreatStoryInput{StoryID: "story-1"})
	if err != nil {
		t.Fatalf("GetThreatStory() error = %v", err)
	}

	payload, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("result.Data type = %T, want map[string]any", result.Data)
	}
	if _, ok := payload["items"]; !ok {
		t.Fatalf("wrapped response missing items key: %#v", payload)
	}
}

func TestListAPISecurityEndpointsMapping(t *testing.T) {
	hasInternetIngress := true
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("per-page") != "20" || query.Get("page-token") != "api-cur" {
			t.Fatalf("unexpected pagination: %s", r.URL.RawQuery)
		}
		if query.Get("authentication-state") != "AUTHENTICATED,UNAUTHENTICATED" {
			t.Fatalf("authentication-state = %q", query.Get("authentication-state"))
		}
		if query.Get("has-internet-ingress") != "true" || query.Get("domain") != "api.example.com" {
			t.Fatalf("unexpected filters: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":    []any{},
			"metadata": map[string]any{"next_cursor": "api-next"},
		})
	})

	result, err := client.ListAPISecurityEndpoints(context.Background(), ListAPISecurityEndpointsInput{
		PaginationInput:     PaginationInput{Limit: 20, Cursor: "api-cur"},
		AuthenticationState: "AUTHENTICATED,UNAUTHENTICATED",
		HasInternetIngress:  &hasInternetIngress,
		Domain:              "api.example.com",
	})
	if err != nil {
		t.Fatalf("ListAPISecurityEndpoints() error = %v", err)
	}
	if result.NextCursor != "api-next" {
		t.Fatalf("NextCursor = %q, want api-next", result.NextCursor)
	}
}

func newTestClient(t *testing.T, apiHandler func(http.ResponseWriter, *http.Request)) *Client {
	t.Helper()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": testAccessToken,
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(authServer.Close)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAccessToken {
			t.Fatalf("Authorization = %q, want Bearer %s", got, testAccessToken)
		}
		apiHandler(w, r)
	}))
	t.Cleanup(apiServer.Close)

	return NewClient(&config.Config{
		BaseURL:        apiServer.URL,
		AuthURL:        authServer.URL,
		OrganizationID: "org_123",
		ClientID:       "client",
		ClientSecret:   "secret",
		RequestTimeout: 5 * time.Second,
	})
}

func decodeJSONBody(t *testing.T, body io.ReadCloser) map[string]any {
	t.Helper()
	defer body.Close()

	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return out
}
