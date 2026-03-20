package upwind

type EmptyInput struct{}

type PaginationInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of items to return"`
	Cursor string `json:"cursor,omitempty" jsonschema:"pagination cursor from a previous response"`
}

type SearchCondition struct {
	Field    string `json:"field,omitempty" jsonschema:"field name to filter on"`
	Operator string `json:"operator" jsonschema:"comparison operator such as eq, in, gt, gte, lt, lte, exists, or contains"`
	Value    []any  `json:"value,omitempty" jsonschema:"values to compare against"`
}

type ListAssetSchemasInput struct {
	PaginationInput
}

type GetAssetSchemaInput struct {
	LabelName string `json:"label_name" jsonschema:"asset label name, such as aws_ec2_instance"`
}

type SearchAssetsInput struct {
	PaginationInput
	Conditions []SearchCondition `json:"conditions,omitempty" jsonschema:"list of search filter conditions"`
}

type GetAssetInput struct {
	AssetID string `json:"asset_id" jsonschema:"Upwind asset identifier"`
}

type ListThreatStoriesInput struct {
	PaginationInput
	Sort string `json:"sort,omitempty" jsonschema:"sort expression such as update_time:desc"`
}

type SearchThreatStoriesInput struct {
	PaginationInput
	Sort       string            `json:"sort,omitempty" jsonschema:"sort expression such as update_time:desc"`
	Conditions []SearchCondition `json:"conditions,omitempty" jsonschema:"list of search filter conditions"`
}

type GetThreatStoryInput struct {
	StoryID string `json:"story_id" jsonschema:"Upwind threat story identifier"`
}

type ListVulnerabilityFindingsInput struct {
	PaginationInput
	CloudAccountID             string `json:"cloud_account_id,omitempty" jsonschema:"filter by cloud account identifier"`
	InUse                      *bool  `json:"in_use,omitempty" jsonschema:"filter to packages currently in use"`
	Exploitable                *bool  `json:"exploitable,omitempty" jsonschema:"filter to findings with a known exploit"`
	FixAvailable               *bool  `json:"fix_available,omitempty" jsonschema:"filter to findings with a fix available"`
	IngressActiveCommunication *bool  `json:"ingress_active_communication,omitempty" jsonschema:"filter to resources with active internet ingress communication"`
	InternetExposure           *bool  `json:"internet_exposure,omitempty" jsonschema:"filter to resources with internet exposure"`
	Severity                   string `json:"severity,omitempty" jsonschema:"CVSS severity such as high or critical"`
	EPSSSeverity               string `json:"epss_severity,omitempty" jsonschema:"EPSS severity such as low or critical"`
	CVEID                      string `json:"cve_id,omitempty" jsonschema:"CVE identifier such as CVE-2025-1234"`
	Namespace                  string `json:"namespace,omitempty" jsonschema:"Kubernetes namespace"`
	ImageName                  string `json:"image_name,omitempty" jsonschema:"container image name"`
	UpwindAssetID              string `json:"upwind_asset_id,omitempty" jsonschema:"Upwind asset identifier"`
}

type GetVulnerabilityFindingInput struct {
	FindingID string `json:"finding_id" jsonschema:"vulnerability finding identifier"`
}

type ListConfigurationFindingsInput struct {
	PaginationInput
	MinLastSeenTime         string   `json:"min_last_seen_time,omitempty" jsonschema:"minimum ISO8601 last seen timestamp"`
	MaxLastSeenTime         string   `json:"max_last_seen_time,omitempty" jsonschema:"maximum ISO8601 last seen timestamp"`
	Status                  string   `json:"status,omitempty" jsonschema:"finding status such as FAIL, PASS, or ALL"`
	Severity                string   `json:"severity,omitempty" jsonschema:"finding severity such as HIGH or CRITICAL"`
	UpwindAssetID           string   `json:"upwind_asset_id,omitempty" jsonschema:"Upwind asset identifier"`
	ResourceName            string   `json:"resource_name,omitempty" jsonschema:"resource name filter"`
	CheckTitle              string   `json:"check_title,omitempty" jsonschema:"configuration check title"`
	CheckID                 string   `json:"check_id,omitempty" jsonschema:"configuration check identifier"`
	FrameworkID             string   `json:"framework_id,omitempty" jsonschema:"configuration framework identifier"`
	FrameworkTitle          string   `json:"framework_title,omitempty" jsonschema:"configuration framework title"`
	CloudAccountTags        []string `json:"cloud_account_tags,omitempty" jsonschema:"cloud account tags in key=value form"`
	IncludeCloudAccountTags *bool    `json:"include_cloud_account_tags,omitempty" jsonschema:"include cloud account tags in the response"`
}

type GetConfigurationFindingInput struct {
	FindingID               string `json:"finding_id" jsonschema:"configuration finding identifier"`
	IncludeCloudAccountTags *bool  `json:"include_cloud_account_tags,omitempty" jsonschema:"include cloud account tags in the response"`
}

type ListConfigurationFrameworksInput struct {
	PaginationInput
	FrameworkIDs    []string `json:"framework_ids,omitempty" jsonschema:"framework identifiers to filter on"`
	CloudProviders  []string `json:"cloud_providers,omitempty" jsonschema:"cloud providers to filter on"`
	Status          string   `json:"status,omitempty" jsonschema:"framework status such as ENABLED or DISABLED"`
	MinCreateTime   string   `json:"min_create_time,omitempty" jsonschema:"minimum ISO8601 create timestamp"`
	MaxCreateTime   string   `json:"max_create_time,omitempty" jsonschema:"maximum ISO8601 create timestamp"`
	MinUpdateTime   string   `json:"min_update_time,omitempty" jsonschema:"minimum ISO8601 update timestamp"`
	MaxUpdateTime   string   `json:"max_update_time,omitempty" jsonschema:"maximum ISO8601 update timestamp"`
	MinLastScanTime string   `json:"min_last_scan_time,omitempty" jsonschema:"minimum ISO8601 last scan timestamp"`
	MaxLastScanTime string   `json:"max_last_scan_time,omitempty" jsonschema:"maximum ISO8601 last scan timestamp"`
	MinScoreValue   *int     `json:"min_score_value,omitempty" jsonschema:"minimum framework score"`
	MaxScoreValue   *int     `json:"max_score_value,omitempty" jsonschema:"maximum framework score"`
	Types           []string `json:"types,omitempty" jsonschema:"framework types to filter on"`
}

type GetConfigurationFrameworkInput struct {
	FrameworkID string `json:"framework_id" jsonschema:"configuration framework identifier"`
}

type ListConfigurationRulesInput struct {
	PaginationInput
	Framework     string `json:"framework,omitempty" jsonschema:"framework filter"`
	Name          string `json:"name,omitempty" jsonschema:"rule name filter"`
	HasFindings   *bool  `json:"has_findings,omitempty" jsonschema:"filter by whether the rule has findings"`
	MinCreateTime string `json:"min_create_time,omitempty" jsonschema:"minimum ISO8601 create timestamp"`
	MaxCreateTime string `json:"max_create_time,omitempty" jsonschema:"maximum ISO8601 create timestamp"`
	MinUpdateTime string `json:"min_update_time,omitempty" jsonschema:"minimum ISO8601 update timestamp"`
	MaxUpdateTime string `json:"max_update_time,omitempty" jsonschema:"maximum ISO8601 update timestamp"`
}

type ListSBOMPackagesInput struct {
	CloudAccountID string `json:"cloud_account_id,omitempty" jsonschema:"filter by cloud account identifier"`
	Framework      string `json:"framework,omitempty" jsonschema:"package framework filter"`
	ImageName      string `json:"image_name,omitempty" jsonschema:"container image name filter"`
	PackageName    string `json:"package_name,omitempty" jsonschema:"package name filter"`
	PackageManager string `json:"package_manager,omitempty" jsonschema:"package manager filter"`
	PackageLicense string `json:"package_license,omitempty" jsonschema:"package license filter"`
}

type GetSBOMPackageDetailsInput struct {
	PackageName string `json:"package_name" jsonschema:"package name"`
	Version     string `json:"version" jsonschema:"package version"`
}

type ListAPISecurityEndpointsInput struct {
	PaginationInput
	Method                  string `json:"method,omitempty" jsonschema:"HTTP method filter such as GET or POST"`
	AuthenticationState     string `json:"authentication_state,omitempty" jsonschema:"authentication state such as AUTHENTICATED or UNAUTHENTICATED"`
	HasInternetIngress      *bool  `json:"has_internet_ingress,omitempty" jsonschema:"filter to endpoints with internet ingress exposure"`
	HasVulnerability        *bool  `json:"has_vulnerability,omitempty" jsonschema:"filter to endpoints with vulnerabilities"`
	HasSensitiveData        *bool  `json:"has_sensitive_data,omitempty" jsonschema:"filter to endpoints that handle sensitive data"`
	CloudAccountID          string `json:"cloud_account_id,omitempty" jsonschema:"cloud account identifier"`
	CloudProvider           string `json:"cloud_provider,omitempty" jsonschema:"cloud provider name"`
	ResourceType            string `json:"resource_type,omitempty" jsonschema:"resource type"`
	CloudOrganizationID     string `json:"cloud_organization_id,omitempty" jsonschema:"cloud organization identifier"`
	CloudOrganizationUnitID string `json:"cloud_organization_unit_id,omitempty" jsonschema:"cloud organization unit identifier"`
	Domain                  string `json:"domain,omitempty" jsonschema:"domain name filter"`
	ClusterID               string `json:"cluster_id,omitempty" jsonschema:"cluster identifier"`
	Namespace               string `json:"namespace,omitempty" jsonschema:"Kubernetes namespace"`
}
