package management

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/identity"
)

func TestReplacementManagementRoutesRemainTenantScopedAndPermissionLocked(t *testing.T) {
	ordinaryTenant := identity.Principal{
		EffectiveTenant: identity.Tenant{ID: "tenant-replacement-routes"},
		HomeTenant:      identity.Tenant{ID: "tenant-replacement-routes"},
	}
	for _, tc := range []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/v0/management/auth-files/quota", "auth_files.read"},
		{http.MethodPost, "/v0/management/auth-files/codex/reset-credit/consume", "auth_files.write"},
		{http.MethodPost, "/v0/management/gemini-api-key/check", "providers.test"},
		{http.MethodPost, "/v0/management/claude-api-key/check", "providers.test"},
		{http.MethodPost, "/v0/management/codex-api-key/check", "providers.test"},
		{http.MethodPost, "/v0/management/vertex-api-key/check", "providers.test"},
		{http.MethodPost, "/v0/management/bedrock-api-key/check", "providers.test"},
		{http.MethodGet, "/v0/management/claude-api-key/models", "providers.test"},
		{http.MethodGet, "/v0/management/codex-api-key/models", "providers.test"},
		{http.MethodGet, "/v0/management/openai-compatibility/models", "providers.test"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if !isTenantScopedManagementPath(tc.path) {
				t.Fatalf("isTenantScopedManagementPath(%q) = false", tc.path)
			}
			if deniesTenantResourceScope(ordinaryTenant, tc.path) {
				t.Fatalf("ordinary tenant denied tenant-scoped replacement route %q", tc.path)
			}
			if got := permissionForManagementRequest(tc.method, tc.path); got != tc.want {
				t.Fatalf("permissionForManagementRequest(%s, %q) = %q, want %q", tc.method, tc.path, got, tc.want)
			}
		})
	}
}
