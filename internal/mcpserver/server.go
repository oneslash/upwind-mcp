package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"upwind-mcp/internal/config"
	"upwind-mcp/internal/upwind"
)

const version = "0.1.0"

func New(cfg *config.Config) *mcp.Server {
	client := upwind.NewClient(cfg)
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "upwind-mcp",
		Title:   "Upwind MCP",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Use these read-only Upwind tools to inspect inventory, threat stories, vulnerability findings, configuration findings, SBOM packages, and API security metadata.",
	})

	addStatusTool(server, cfg)
	addReadOnlyTool(server, "upwind_list_asset_schemas", "List Upwind inventory asset schemas.", client.ListAssetSchemas)
	addReadOnlyTool(server, "upwind_get_asset_schema", "Get a specific Upwind asset schema by label.", client.GetAssetSchema)
	addReadOnlyTool(server, "upwind_search_assets", "Search Upwind inventory assets with filter conditions.", client.SearchAssets)
	addReadOnlyTool(server, "upwind_get_asset", "Get an Upwind asset by ID.", client.GetAsset)
	addReadOnlyTool(server, "upwind_list_threat_stories", "List Upwind threat stories.", client.ListThreatStories)
	addReadOnlyTool(server, "upwind_search_threat_stories", "Search Upwind threat stories with filter conditions.", client.SearchThreatStories)
	addReadOnlyTool(server, "upwind_get_threat_story", "Get an Upwind threat story by ID.", client.GetThreatStory)
	addReadOnlyTool(server, "upwind_list_vulnerability_findings", "List Upwind vulnerability findings.", client.ListVulnerabilityFindings)
	addReadOnlyTool(server, "upwind_get_vulnerability_finding", "Get an Upwind vulnerability finding by ID.", client.GetVulnerabilityFinding)
	addReadOnlyTool(server, "upwind_list_configuration_findings", "List Upwind configuration findings.", client.ListConfigurationFindings)
	addReadOnlyTool(server, "upwind_get_configuration_finding", "Get an Upwind configuration finding by ID.", client.GetConfigurationFinding)
	addReadOnlyTool(server, "upwind_list_configuration_frameworks", "List Upwind configuration frameworks.", client.ListConfigurationFrameworks)
	addReadOnlyTool(server, "upwind_get_configuration_framework", "Get an Upwind configuration framework by ID.", client.GetConfigurationFramework)
	addReadOnlyTool(server, "upwind_list_configuration_rules", "List Upwind configuration rules.", client.ListConfigurationRules)
	addReadOnlyTool(server, "upwind_list_sbom_packages", "List Upwind SBOM packages.", client.ListSBOMPackages)
	addReadOnlyTool(server, "upwind_get_sbom_package_details", "Get Upwind SBOM package details.", client.GetSBOMPackageDetails)
	addReadOnlyTool(server, "upwind_list_api_security_endpoints", "List Upwind API security endpoints.", client.ListAPISecurityEndpoints)

	return server
}

func addStatusTool(server *mcp.Server, cfg *config.Config) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "upwind_server_status",
		Description: "Report effective Upwind configuration status, available transports, and any missing required Upwind environment variables.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, req *mcp.CallToolRequest, input upwind.EmptyInput) (*mcp.CallToolResult, map[string]any, error) {
		_ = ctx
		_ = req

		baseURL, baseErr := cfg.EffectiveBaseURL()
		audience, audienceErr := cfg.OAuthAudience()

		output := map[string]any{
			"summary":                 statusSummary(cfg),
			"region":                  cfg.Region,
			"effective_base_url":      valueOrError(baseURL, baseErr),
			"oauth_audience":          valueOrError(audience, audienceErr),
			"available_transports":    []string{"stdio", "streamable-http"},
			"missing_upwind_env_vars": cfg.MissingUpwindEnvVars(),
			"upwind_configured":       len(cfg.MissingUpwindEnvVars()) == 0,
			"http": map[string]any{
				"address":           cfg.HTTPAddr,
				"path":              cfg.HTTPPath,
				"bearer_configured": cfg.HTTPBearerToken != "",
				"requires_bearer":   true,
			},
		}

		return textOnlyResult(output["summary"].(string)), output, nil
	})
}

func addReadOnlyTool[In any](server *mcp.Server, name, description string, fn func(context.Context, In) (*upwind.Result, error)) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        name,
		Description: description,
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, req *mcp.CallToolRequest, input In) (*mcp.CallToolResult, map[string]any, error) {
		_ = req

		result, err := fn(ctx, input)
		if err != nil {
			return nil, nil, err
		}

		output := map[string]any{
			"summary":         result.Summary,
			"upwind_response": result.Data,
		}
		if result.NextCursor != "" {
			output["next_cursor"] = result.NextCursor
		}

		return textOnlyResult(result.Summary), output, nil
	})
}

func readOnlyAnnotations() *mcp.ToolAnnotations {
	openWorld := true
	return &mcp.ToolAnnotations{
		IdempotentHint: true,
		OpenWorldHint:  &openWorld,
		ReadOnlyHint:   true,
	}
}

func textOnlyResult(summary string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: summary},
		},
	}
}

func statusSummary(cfg *config.Config) string {
	missing := cfg.MissingUpwindEnvVars()
	if len(missing) == 0 {
		return "Upwind MCP is configured for API calls."
	}
	return fmt.Sprintf("Upwind MCP is missing required Upwind environment variables: %s.", strings.Join(missing, ", "))
}

func valueOrError(value string, err error) any {
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return value
}
