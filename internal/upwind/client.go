package upwind

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"upwind-mcp/internal/config"
)

const tokenRefreshLeeway = 30 * time.Second

type Result struct {
	Summary    string
	Data       any
	NextCursor string
}

type Client struct {
	cfg        *config.Config
	httpClient *http.Client
	now        func() time.Time

	mu    sync.Mutex
	token *cachedToken
}

type cachedToken struct {
	AccessToken string
	Expiry      time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

func WithNowFunc(now func() time.Time) Option {
	return func(c *Client) {
		c.now = now
	}
}

func NewClient(cfg *config.Config, opts ...Option) *Client {
	client := &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
		now: time.Now,
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func (c *Client) ListAssetSchemas(ctx context.Context, input ListAssetSchemasInput) (*Result, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v2/organizations/{organization-id}/inventory/schema"), queryFromPagination(input.PaginationInput, v2PaginationMode), nil)
	if err != nil {
		return nil, err
	}
	return listResult("asset schemas", resp.Data, ""), nil
}

func (c *Client) GetAssetSchema(ctx context.Context, input GetAssetSchemaInput) (*Result, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v2/organizations/{organization-id}/inventory/schema/{label-name}", input.LabelName), nil, nil)
	if err != nil {
		return nil, err
	}
	return getResult("asset schema", resp.Data), nil
}

func (c *Client) SearchAssets(ctx context.Context, input SearchAssetsInput) (*Result, error) {
	body := map[string]any{}
	if len(input.Conditions) > 0 {
		body["conditions"] = input.Conditions
	}
	resp, err := c.doJSON(ctx, http.MethodPost, c.orgPath("/v2/organizations/{organization-id}/inventory/catalog/assets/search"), queryFromPagination(input.PaginationInput, v2PaginationMode), body)
	if err != nil {
		return nil, err
	}
	return searchResult("assets", resp.Data, resp.NextCursor), nil
}

func (c *Client) GetAsset(ctx context.Context, input GetAssetInput) (*Result, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v2/organizations/{organization-id}/inventory/catalog/assets/{id}", input.AssetID), nil, nil)
	if err != nil {
		return nil, err
	}
	return getResult("asset", resp.Data), nil
}

func (c *Client) ListThreatStories(ctx context.Context, input ListThreatStoriesInput) (*Result, error) {
	query := queryFromPagination(input.PaginationInput, v2PaginationMode)
	addString(query, "sort", input.Sort)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v2/organizations/{organization-id}/threats/stories"), query, nil)
	if err != nil {
		return nil, err
	}
	return listResult("threat stories", resp.Data, resp.NextCursor), nil
}

func (c *Client) SearchThreatStories(ctx context.Context, input SearchThreatStoriesInput) (*Result, error) {
	query := queryFromPagination(input.PaginationInput, v2PaginationMode)
	addString(query, "sort", input.Sort)
	body := map[string]any{}
	if len(input.Conditions) > 0 {
		body["conditions"] = input.Conditions
	}
	resp, err := c.doJSON(ctx, http.MethodPost, c.orgPath("/v2/organizations/{organization-id}/threats/stories/search"), query, body)
	if err != nil {
		return nil, err
	}
	return searchResult("threat stories", resp.Data, resp.NextCursor), nil
}

func (c *Client) GetThreatStory(ctx context.Context, input GetThreatStoryInput) (*Result, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v2/organizations/{organization-id}/threats/stories/{story-id}", input.StoryID), nil, nil)
	if err != nil {
		return nil, err
	}
	return getResult("threat story", resp.Data), nil
}

func (c *Client) ListVulnerabilityFindings(ctx context.Context, input ListVulnerabilityFindingsInput) (*Result, error) {
	query := queryFromPagination(input.PaginationInput, v1CursorPaginationMode)
	addString(query, "cloud-account-id", input.CloudAccountID)
	addBoolPtr(query, "in-use", input.InUse)
	addBoolPtr(query, "exploitable", input.Exploitable)
	addBoolPtr(query, "fix-available", input.FixAvailable)
	addBoolPtr(query, "ingress-active-communication", input.IngressActiveCommunication)
	addBoolPtr(query, "internet-exposure", input.InternetExposure)
	addString(query, "severity", input.Severity)
	addString(query, "epss-severity", input.EPSSSeverity)
	addString(query, "cve-id", input.CVEID)
	addString(query, "namespace", input.Namespace)
	addString(query, "image-name", input.ImageName)
	addString(query, "upwind-asset-id", input.UpwindAssetID)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/vulnerability-findings"), query, nil)
	if err != nil {
		return nil, err
	}
	return listResult("vulnerability findings", resp.Data, resp.NextCursor), nil
}

func (c *Client) GetVulnerabilityFinding(ctx context.Context, input GetVulnerabilityFindingInput) (*Result, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/vulnerability-findings/{finding-id}", input.FindingID), nil, nil)
	if err != nil {
		return nil, err
	}
	return getResult("vulnerability finding", resp.Data), nil
}

func (c *Client) ListConfigurationFindings(ctx context.Context, input ListConfigurationFindingsInput) (*Result, error) {
	query := queryFromPagination(input.PaginationInput, v1CursorPaginationMode)
	addString(query, "min-last-seen-time", input.MinLastSeenTime)
	addString(query, "max-last-seen-time", input.MaxLastSeenTime)
	addString(query, "status", input.Status)
	addString(query, "severity", input.Severity)
	addString(query, "upwind-asset-id", input.UpwindAssetID)
	addString(query, "resource-name", input.ResourceName)
	addString(query, "check-title", input.CheckTitle)
	addString(query, "check-id", input.CheckID)
	addString(query, "framework-id", input.FrameworkID)
	addString(query, "framework-title", input.FrameworkTitle)
	addCommaSeparated(query, "cloud-account-tags", input.CloudAccountTags)
	addBoolPtr(query, "include-cloud-account-tags", input.IncludeCloudAccountTags)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/configuration-findings"), query, nil)
	if err != nil {
		return nil, err
	}
	return listResult("configuration findings", resp.Data, resp.NextCursor), nil
}

func (c *Client) GetConfigurationFinding(ctx context.Context, input GetConfigurationFindingInput) (*Result, error) {
	query := url.Values{}
	addBoolPtr(query, "include-cloud-account-tags", input.IncludeCloudAccountTags)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/configuration-findings/{finding-id}", input.FindingID), query, nil)
	if err != nil {
		return nil, err
	}
	return getResult("configuration finding", resp.Data), nil
}

func (c *Client) ListConfigurationFrameworks(ctx context.Context, input ListConfigurationFrameworksInput) (*Result, error) {
	page, err := pageFromCursor(input.Cursor)
	if err != nil {
		return nil, err
	}

	query := queryFromPagination(input.PaginationInput, v1PagePaginationMode)
	query.Set("page", strconv.Itoa(page))
	addRepeated(query, "framework-ids", input.FrameworkIDs)
	addRepeated(query, "cloud-providers", input.CloudProviders)
	addString(query, "status", input.Status)
	addString(query, "min-create-time", input.MinCreateTime)
	addString(query, "max-create-time", input.MaxCreateTime)
	addString(query, "min-update-time", input.MinUpdateTime)
	addString(query, "max-update-time", input.MaxUpdateTime)
	addString(query, "min-last-scan-time", input.MinLastScanTime)
	addString(query, "max-last-scan-time", input.MaxLastScanTime)
	addIntPtr(query, "min-score-value", input.MinScoreValue)
	addIntPtr(query, "max-score-value", input.MaxScoreValue)
	addRepeated(query, "types", input.Types)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/configuration-frameworks"), query, nil)
	if err != nil {
		return nil, err
	}
	nextCursor := syntheticNextPageCursor(page, paginationLimit(input.Limit, 100), resp.Data)
	return listResult("configuration frameworks", resp.Data, nextCursor), nil
}

func (c *Client) GetConfigurationFramework(ctx context.Context, input GetConfigurationFrameworkInput) (*Result, error) {
	result, err := c.ListConfigurationFrameworks(ctx, ListConfigurationFrameworksInput{
		PaginationInput: PaginationInput{Limit: 1},
		FrameworkIDs:    []string{input.FrameworkID},
	})
	if err != nil {
		return nil, err
	}

	items, ok := result.Data.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("configuration framework %q not found", input.FrameworkID)
	}

	return getResult("configuration framework", items[0]), nil
}

func (c *Client) ListConfigurationRules(ctx context.Context, input ListConfigurationRulesInput) (*Result, error) {
	page, err := pageFromCursor(input.Cursor)
	if err != nil {
		return nil, err
	}

	query := queryFromPagination(input.PaginationInput, v1PagePaginationMode)
	query.Set("page", strconv.Itoa(page))
	addString(query, "framework", input.Framework)
	addString(query, "name", input.Name)
	addBoolPtr(query, "has-findings", input.HasFindings)
	addString(query, "min-create-time", input.MinCreateTime)
	addString(query, "max-create-time", input.MaxCreateTime)
	addString(query, "min-update-time", input.MinUpdateTime)
	addString(query, "max-update-time", input.MaxUpdateTime)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/configuration-rules"), query, nil)
	if err != nil {
		return nil, err
	}
	nextCursor := syntheticNextPageCursor(page, paginationLimit(input.Limit, 100), resp.Data)
	return listResult("configuration rules", resp.Data, nextCursor), nil
}

func (c *Client) ListSBOMPackages(ctx context.Context, input ListSBOMPackagesInput) (*Result, error) {
	query := url.Values{}
	addString(query, "cloud-account-id", input.CloudAccountID)
	addString(query, "framework", input.Framework)
	addString(query, "image-name", input.ImageName)
	addString(query, "package-name", input.PackageName)
	addString(query, "package-manager", input.PackageManager)
	addString(query, "package-license", input.PackageLicense)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/sbom-packages"), query, nil)
	if err != nil {
		return nil, err
	}
	return listResult("SBOM packages", resp.Data, ""), nil
}

func (c *Client) GetSBOMPackageDetails(ctx context.Context, input GetSBOMPackageDetailsInput) (*Result, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/sbom-packages/{package-name}/{version}", input.PackageName, input.Version), nil, nil)
	if err != nil {
		return nil, err
	}
	return getResult("SBOM package details", resp.Data), nil
}

func (c *Client) ListAPISecurityEndpoints(ctx context.Context, input ListAPISecurityEndpointsInput) (*Result, error) {
	query := queryFromPagination(input.PaginationInput, v1CursorPaginationMode)
	addString(query, "method", input.Method)
	addString(query, "authentication-state", input.AuthenticationState)
	addBoolPtr(query, "has-internet-ingress", input.HasInternetIngress)
	addBoolPtr(query, "has-vulnerability", input.HasVulnerability)
	addBoolPtr(query, "has-sensitive-data", input.HasSensitiveData)
	addString(query, "cloud-account-id", input.CloudAccountID)
	addString(query, "cloud-provider", input.CloudProvider)
	addString(query, "resource-type", input.ResourceType)
	addString(query, "cloud-organization-id", input.CloudOrganizationID)
	addString(query, "cloud-organization-unit-id", input.CloudOrganizationUnitID)
	addString(query, "domain", input.Domain)
	addString(query, "cluster-id", input.ClusterID)
	addString(query, "namespace", input.Namespace)
	resp, err := c.doJSON(ctx, http.MethodGet, c.orgPath("/v1/organizations/{organization-id}/apisecurity-endpoints"), query, nil)
	if err != nil {
		return nil, err
	}
	return listResult("API security endpoints", resp.Data, resp.NextCursor), nil
}

func (c *Client) doJSON(ctx context.Context, method, endpointPath string, query url.Values, requestBody any) (*Result, error) {
	if err := c.validateConfigured(); err != nil {
		return nil, err
	}

	baseURL, err := c.cfg.EffectiveBaseURL()
	if err != nil {
		return nil, err
	}

	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	requestURL, err := joinURL(baseURL, endpointPath, query)
	if err != nil {
		return nil, err
	}

	var body io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, endpointPath, err)
	}
	defer resp.Body.Close()

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("Upwind API %s %s returned %d: %s", method, endpointPath, resp.StatusCode, compactBody(responseBytes))
	}

	var payload any
	if len(bytes.TrimSpace(responseBytes)) > 0 {
		if err := json.Unmarshal(responseBytes, &payload); err != nil {
			return nil, fmt.Errorf("decode response body: %w", err)
		}
	} else {
		payload = map[string]any{}
	}

	return &Result{
		Data:       payload,
		NextCursor: extractNextCursor(payload, resp.Header),
	}, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	now := c.now()

	c.mu.Lock()
	if c.token != nil && now.Add(tokenRefreshLeeway).Before(c.token.Expiry) {
		token := c.token.AccessToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	token, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
	return token.AccessToken, nil
}

func (c *Client) fetchToken(ctx context.Context) (*cachedToken, error) {
	audience, err := c.cfg.OAuthAudience()
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("audience", audience)
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.AuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch OAuth token: %w", err)
	}
	defer resp.Body.Close()

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read OAuth token response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("OAuth token request returned %d: %s", resp.StatusCode, compactBody(responseBytes))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(responseBytes, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode OAuth token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("OAuth token response did not include access_token")
	}

	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}

	return &cachedToken{
		AccessToken: tokenResp.AccessToken,
		Expiry:      c.now().Add(expiresIn),
	}, nil
}

func (c *Client) validateConfigured() error {
	missing := c.cfg.MissingUpwindEnvVars()
	if len(missing) > 0 {
		return fmt.Errorf("missing required Upwind environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *Client) orgPath(template string, segments ...string) string {
	values := append([]string{c.cfg.OrganizationID}, segments...)
	for _, value := range values {
		start := strings.Index(template, "{")
		end := strings.Index(template, "}")
		if start < 0 || end < 0 || end <= start {
			break
		}
		template = template[:start] + pathEscape(value) + template[end+1:]
	}
	return template
}

func joinURL(baseURL, endpointPath string, query url.Values) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rawPath := strings.TrimRight(parsed.EscapedPath(), "/") + endpointPath
	if rawPath == "" {
		rawPath = "/"
	}
	unescapedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return "", fmt.Errorf("unescape path: %w", err)
	}
	parsed.Path = unescapedPath
	parsed.RawPath = rawPath
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func pathEscape(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), "+", "%2B")
}

type paginationMode int

const (
	v2PaginationMode paginationMode = iota
	v1CursorPaginationMode
	v1PagePaginationMode
)

func queryFromPagination(input PaginationInput, mode paginationMode) url.Values {
	query := url.Values{}
	switch mode {
	case v2PaginationMode:
		if input.Limit > 0 {
			query.Set("limit", strconv.Itoa(input.Limit))
		}
		addString(query, "cursor", input.Cursor)
	case v1CursorPaginationMode:
		if input.Limit > 0 {
			query.Set("per-page", strconv.Itoa(input.Limit))
		}
		addString(query, "page-token", input.Cursor)
	case v1PagePaginationMode:
		if input.Limit > 0 {
			query.Set("per-page", strconv.Itoa(input.Limit))
		}
	}
	return query
}

func addString(query url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
}

func addBoolPtr(query url.Values, key string, value *bool) {
	if value != nil {
		query.Set(key, strconv.FormatBool(*value))
	}
}

func addIntPtr(query url.Values, key string, value *int) {
	if value != nil {
		query.Set(key, strconv.Itoa(*value))
	}
}

func addRepeated(query url.Values, key string, values []string) {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			query.Add(key, trimmed)
		}
	}
}

func addCommaSeparated(query url.Values, key string, values []string) {
	var filtered []string
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	if len(filtered) > 0 {
		query.Set(key, strings.Join(filtered, ","))
	}
}

func extractNextCursor(payload any, headers http.Header) string {
	if cursor := nextCursorFromLinkHeader(headers.Get("Link")); cursor != "" {
		return cursor
	}

	object, ok := payload.(map[string]any)
	if !ok {
		return ""
	}

	if metadata, ok := object["metadata"].(map[string]any); ok {
		if cursor := scalarString(metadata["next_cursor"]); cursor != "" {
			return cursor
		}
	}

	if pagination, ok := object["pagination"].(map[string]any); ok {
		if cursor := scalarString(pagination["next_cursor"]); cursor != "" {
			return cursor
		}
		if cursor := scalarString(pagination["nextPageToken"]); cursor != "" {
			return cursor
		}
	}

	return ""
}

func nextCursorFromLinkHeader(headerValue string) string {
	for _, part := range strings.Split(headerValue, ",") {
		part = strings.TrimSpace(part)
		if part == "" || !strings.Contains(part, `rel="next"`) {
			continue
		}

		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end <= start+1 {
			continue
		}

		linkURL, err := url.Parse(part[start+1 : end])
		if err != nil {
			continue
		}
		for _, key := range []string{"page-token", "cursor"} {
			if cursor := linkURL.Query().Get(key); cursor != "" {
				return cursor
			}
		}
	}
	return ""
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		if len(typed) == 1 {
			return fmt.Sprint(typed[0])
		}
		if len(typed) > 1 {
			payload, err := json.Marshal(typed)
			if err == nil {
				return string(payload)
			}
		}
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	}
	return ""
}

func pageFromCursor(cursor string) (int, error) {
	if strings.TrimSpace(cursor) == "" {
		return 1, nil
	}
	page, err := strconv.Atoi(cursor)
	if err != nil || page < 1 {
		return 0, fmt.Errorf("invalid page cursor %q", cursor)
	}
	return page, nil
}

func syntheticNextPageCursor(currentPage, limit int, payload any) string {
	if limit <= 0 {
		return ""
	}
	if countItems(payload) < limit {
		return ""
	}
	return strconv.Itoa(currentPage + 1)
}

func paginationLimit(limit, fallback int) int {
	if limit > 0 {
		return limit
	}
	return fallback
}

func countItems(payload any) int {
	switch typed := payload.(type) {
	case []any:
		return len(typed)
	case map[string]any:
		for _, key := range []string{"items", "resourceFindings"} {
			if items, ok := typed[key].([]any); ok {
				return len(items)
			}
		}
	}
	return -1
}

func listResult(subject string, payload any, nextCursor string) *Result {
	summary := "Listed " + subject + "."
	if count := countItems(payload); count >= 0 {
		summary = fmt.Sprintf("Listed %d %s.", count, subject)
	}
	return &Result{
		Summary:    summary,
		Data:       payload,
		NextCursor: nextCursor,
	}
}

func searchResult(subject string, payload any, nextCursor string) *Result {
	summary := "Searched " + subject + "."
	if count := countItems(payload); count >= 0 {
		summary = fmt.Sprintf("Matched %d %s.", count, subject)
	}
	return &Result{
		Summary:    summary,
		Data:       payload,
		NextCursor: nextCursor,
	}
}

func getResult(subject string, payload any) *Result {
	return &Result{
		Summary: "Retrieved " + subject + ".",
		Data:    payload,
	}
}

func compactBody(body []byte) string {
	const maxLen = 512
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "empty response body"
	}
	if len(trimmed) > maxLen {
		return trimmed[:maxLen] + "..."
	}
	return trimmed
}
