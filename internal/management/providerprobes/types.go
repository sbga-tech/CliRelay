// Package providerprobes provides tenant-scoped connectivity and model discovery
// operations for saved provider configurations.
package providerprobes

import "errors"

var (
	// ErrInvalidIndex indicates that a saved provider index cannot identify a row.
	ErrInvalidIndex = errors.New("invalid index")
	// ErrProviderNotFound indicates that the selected saved provider row does not exist.
	ErrProviderNotFound = errors.New("provider not found")
	// ErrProviderBaseURLRequired indicates that the selected row has no probeable base URL.
	ErrProviderBaseURLRequired = errors.New("provider base_url is required")
	// ErrProviderCredentialRequired indicates that discovery lacks a stored credential.
	ErrProviderCredentialRequired = errors.New("provider credential is required")
	// ErrModelDiscoveryFailed intentionally hides upstream failure details.
	ErrModelDiscoveryFailed = errors.New("model discovery failed")
	// ErrUnsupportedProviderKind identifies an operation that does not support a provider kind.
	ErrUnsupportedProviderKind = errors.New("unsupported provider kind")
)

// CheckResult is the sanitized result of an unauthenticated saved-provider
// connectivity check. Any upstream HTTP response is reachable regardless of
// its status code.
type CheckResult struct {
	OK         bool   `json:"ok"`
	StatusCode *int   `json:"status_code,omitempty"`
	LatencyMs  int64  `json:"latency_ms"`
	Message    string `json:"message,omitempty"`
}

// Model is one normalized model discovered from a saved provider.
type Model struct {
	ID      string `json:"id"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// ModelResult contains the normalized, de-duplicated discovery result.
type ModelResult struct {
	Models []Model `json:"models"`
}
