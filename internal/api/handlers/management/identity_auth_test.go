package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/identity"
	postgresstore "github.com/router-for-me/CLIProxyAPI/v6/internal/storage/postgres"
)

func TestPermissionForManagementRequest(t *testing.T) {
	tests := []struct{ method, path, want string }{
		{http.MethodGet, "/v0/management/tenants", "platform.tenants.read"},
		{http.MethodPost, "/v0/management/tenants", "platform.tenants.create"},
		{http.MethodGet, "/v0/management/users", "tenant.users.read"},
		{http.MethodPut, "/v0/management/users/u/roles", "tenant.users.assign_roles"},
		{http.MethodPut, "/v0/management/roles/r/users", "tenant.users.assign_roles"},
		{http.MethodGet, "/v0/management/menus", "platform.menus.read"},
		{http.MethodPost, "/v0/management/menus", "platform.menus.update"},
		{http.MethodPatch, "/v0/management/menus/system.config", "platform.menus.update"},
		{http.MethodDelete, "/v0/management/menus/custom.menu", "platform.menus.update"},
		{http.MethodDelete, "/v0/management/usage/logs", "request_logs.delete"},
		{http.MethodGet, "/v0/management/usage/logs/1/content", "request_logs.content.read"},
		{http.MethodGet, "/v0/management/get-auth-status", "auth_files.oauth"},
		{http.MethodPost, "/v0/management/proxy-pool/check", "proxies.test"},
		{http.MethodPut, "/v0/management/config.yaml", "system.config.write"},
		// Sensitive logs must not fall through to system.config.read.
		{http.MethodGet, "/v0/management/request-error-logs", "system.logs.read"},
		{http.MethodGet, "/v0/management/request-error-logs/err.log", "system.logs.read"},
		{http.MethodGet, "/v0/management/request-log-by-id/abc", "system.logs.read"},
		{http.MethodGet, "/v0/management/logs", "system.logs.read"},
		// Clearing file logs requires an explicit delete permission.
		{http.MethodDelete, "/v0/management/logs", "system.logs.delete"},
		// Usage writes must not use monitor.read.
		{http.MethodPost, "/v0/management/usage/import", "system.config.write"},
		{http.MethodPost, "/v0/management/usage/auth-file-quota-snapshot", "auth_files.write"},
		{http.MethodGet, "/v0/management/usage", "monitor.read"},
		{http.MethodGet, "/v0/management/usage/export", "monitor.read"},
		// Config knobs that share prefixes with other resources.
		{http.MethodGet, "/v0/management/usage-statistics-enabled", "system.config.read"},
		{http.MethodPatch, "/v0/management/usage-statistics-enabled", "system.config.write"},
		{http.MethodPut, "/v0/management/logs-max-total-size-mb", "system.config.write"},
		{http.MethodGet, "/v0/management/request-log", "system.config.read"},
		{http.MethodPut, "/v0/management/request-log", "system.config.write"},
		{http.MethodGet, "/v0/management/ws-auth", "system.config.read"},
		// Fail closed: unmapped routes get no permission.
		{http.MethodGet, "/v0/management/totally-unknown-route", ""},
		{http.MethodPost, "/v0/management/totally-unknown-route", ""},
		// Account fingerprint APIs are auth-file scoped; global preset PUT stays platform-only.
		{http.MethodGet, "/v0/management/identity-fingerprint", "auth_files.read"},
		{http.MethodGet, "/v0/management/identity-fingerprint/account", "auth_files.read"},
		{http.MethodGet, "/v0/management/identity-fingerprint/codex/recommendations", "auth_files.read"},
		{http.MethodPut, "/v0/management/identity-fingerprint/account/policy", "auth_files.write"},
		{http.MethodDelete, "/v0/management/identity-fingerprint/account/profile", "auth_files.write"},
		{http.MethodDelete, "/v0/management/identity-fingerprint/learned", "auth_files.write"},
		{http.MethodPut, "/v0/management/identity-fingerprint", "system.config.write"},
	}
	for _, test := range tests {
		if got := permissionForManagementRequest(test.method, test.path); got != test.want {
			t.Errorf("permissionForManagementRequest(%s,%s)=%q want %q", test.method, test.path, got, test.want)
		}
	}
}

func TestServiceCredentialCannotAccessTenantGovernance(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewHandler(nil, "", nil)
	h.SetLocalPassword("management-key")
	t.Cleanup(h.Close)

	router := gin.New()
	router.Use(h.Middleware())
	reached := false
	router.GET("/v0/management/tenants", func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v0/management/tenants", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer management-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if reached {
		t.Fatal("service credential reached tenant governance handler")
	}
}

// TestLogsDeleteMiddlewareRequiresExplicitPermission drives real sessions
// through Handler.Middleware(): read-only DELETE is 403 and never reaches the
// handler; delete-capable DELETE and read-only GET both enter the handler.
func TestLogsDeleteMiddlewareRequiresExplicitPermission(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CLIRELAY_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CLIRELAY_POSTGRES_TEST_DSN is not set")
	}
	ctx := context.Background()
	db, err := postgresstore.OpenRuntimeDB(ctx, config.PostgresConfig{DSN: dsn, MaxOpenConns: 4, MaxIdleConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = db.ExecContext(ctx, `TRUNCATE audit_logs,user_sessions,user_roles,role_permissions,menus,users,roles,permissions,tenants CASCADE`); err != nil {
		t.Fatal(err)
	}

	service := identity.NewService(db)
	if err = service.Bootstrap(ctx, "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	// Pin the service on the handler so Middleware does not depend on process-global Default().
	h := NewHandler(nil, "", nil)
	h.identityService = service
	t.Cleanup(h.Close)

	// Platform roles that grant only the log permissions under test. CreateRole
	// rejects platform-scoped permissions, so seed via SQL like production would
	// for a custom platform operator role.
	type logUserFixture struct {
		username, password, userID, roleID string
		permissions                        []string
	}
	seedPlatformLogUser := func(fx logUserFixture) string {
		t.Helper()
		hash, hashErr := identity.HashPassword(fx.password)
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		if _, err = db.ExecContext(ctx, `
			INSERT INTO roles (id, tenant_id, code, name, description, scope, system_protected)
			VALUES (?, ?, ?, ?, '', 'platform', false)
		`, fx.roleID, identity.SystemTenantID, "platform_"+fx.username, fx.username+" role"); err != nil {
			t.Fatalf("seed role %s: %v", fx.username, err)
		}
		for _, perm := range fx.permissions {
			if _, err = db.ExecContext(ctx, `
				INSERT INTO role_permissions (role_id, permission_code) VALUES (?, ?)
			`, fx.roleID, perm); err != nil {
				t.Fatalf("seed role permission %s: %v", perm, err)
			}
		}
		if _, err = db.ExecContext(ctx, `
			INSERT INTO users (
			  id, tenant_id, username, username_normalized, display_name, password_hash,
			  status, must_change_password, password_changed_at, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, 'active', false, now(), now(), now())
		`, fx.userID, identity.SystemTenantID, fx.username, fx.username, fx.username, hash); err != nil {
			t.Fatalf("seed user %s: %v", fx.username, err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, fx.userID, fx.roleID); err != nil {
			t.Fatalf("seed user role %s: %v", fx.username, err)
		}
		login, loginErr := service.Login(ctx, fx.username, fx.password, false, "middleware-test")
		if loginErr != nil {
			t.Fatalf("login %s: %v", fx.username, loginErr)
		}
		return login.AccessToken
	}

	readToken := seedPlatformLogUser(logUserFixture{
		username:    "log-reader",
		password:    "reader-password-123",
		userID:      "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1",
		roleID:      "cccccccc-cccc-cccc-cccc-ccccccccccc1",
		permissions: []string{"system.logs.read"},
	})
	deleteToken := seedPlatformLogUser(logUserFixture{
		username:    "log-deleter",
		password:    "deleter-password-123",
		userID:      "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2",
		roleID:      "cccccccc-cccc-cccc-cccc-ccccccccccc2",
		permissions: []string{"system.logs.read", "system.logs.delete"},
	})

	serve := func(method, token string) (int, bool) {
		t.Helper()
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(h.Middleware())
		reached := false
		handler := func(c *gin.Context) {
			reached = true
			c.Status(http.StatusOK)
		}
		router.GET("/v0/management/logs", handler)
		router.DELETE("/v0/management/logs", handler)

		req := httptest.NewRequest(method, "/v0/management/logs", nil)
		req.RemoteAddr = "127.0.0.1:4321"
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, reached
	}

	if code, reached := serve(http.MethodDelete, readToken); code != http.StatusForbidden || reached {
		t.Fatalf("read-only DELETE: status=%d reached=%v, want 403 and handler not executed", code, reached)
	}
	if code, reached := serve(http.MethodGet, readToken); code != http.StatusOK || !reached {
		t.Fatalf("read-only GET: status=%d reached=%v, want 200 and handler executed", code, reached)
	}
	if code, reached := serve(http.MethodDelete, deleteToken); code != http.StatusOK || !reached {
		t.Fatalf("delete-capable DELETE: status=%d reached=%v, want 200 and handler executed", code, reached)
	}
}
