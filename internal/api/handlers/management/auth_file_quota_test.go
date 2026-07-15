package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/identity"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/management/authfilequota"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestAuthFileQuotaInputValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		handle  func(*Handler, *gin.Context)
		want    int
		message string
	}{
		{
			name:    "get missing auth index",
			method:  http.MethodGet,
			path:    "/auth-files/quota",
			handle:  (*Handler).GetAuthFileQuota,
			want:    http.StatusBadRequest,
			message: "auth_index is required",
		},
		{
			name:    "get auth manager unavailable",
			method:  http.MethodGet,
			path:    "/auth-files/quota?auth_index=auth-1",
			handle:  (*Handler).GetAuthFileQuota,
			want:    http.StatusServiceUnavailable,
			message: "auth manager unavailable",
		},
		{
			name:    "consume missing auth index",
			method:  http.MethodPost,
			path:    "/auth-files/codex/reset-credit/consume",
			body:    `{"auth_index":"  "}`,
			handle:  (*Handler).ConsumeCodexResetCredit,
			want:    http.StatusBadRequest,
			message: "auth_index is required",
		},
		{
			name:    "consume invalid body",
			method:  http.MethodPost,
			path:    "/auth-files/codex/reset-credit/consume",
			body:    `{`,
			handle:  (*Handler).ConsumeCodexResetCredit,
			want:    http.StatusBadRequest,
			message: "invalid body",
		},
		{
			name:    "consume auth manager unavailable",
			method:  http.MethodPost,
			path:    "/auth-files/codex/reset-credit/consume",
			body:    `{"auth_index":"auth-1"}`,
			handle:  (*Handler).ConsumeCodexResetCredit,
			want:    http.StatusServiceUnavailable,
			message: "auth manager unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			ctx.Request = request

			tt.handle(&Handler{}, ctx)
			assertAuthFileQuotaError(t, recorder, tt.want, tt.message)
		})
	}
}

func TestAuthFileQuotaErrorMapping(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		err     error
		want    int
		message string
	}{
		{"auth manager unavailable", authfilequota.ErrAuthManagerUnavailable, http.StatusServiceUnavailable, "auth manager unavailable"},
		{"auth not found", authfilequota.ErrAuthNotFound, http.StatusNotFound, "auth not found"},
		{"unsupported provider", authfilequota.ErrUnsupportedProvider, http.StatusBadRequest, "quota unsupported for auth provider"},
		{"missing token", authfilequota.ErrAuthTokenNotFound, http.StatusBadRequest, "auth token not found"},
		{"token refresh", authfilequota.ErrTokenRefresh, http.StatusBadGateway, "auth token refresh failed"},
		{"invalid response", authfilequota.ErrInvalidQuotaResponse, http.StatusBadGateway, "invalid quota response"},
		{"quota request", authfilequota.ErrQuotaRequest, http.StatusBadGateway, "quota request failed"},
		{"wrapped quota request", errors.Join(errors.New("upstream unavailable"), authfilequota.ErrQuotaRequest), http.StatusBadGateway, "quota request failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			(&Handler{}).writeAuthFileQuotaError(ctx, tt.err)
			assertAuthFileQuotaError(t, recorder, tt.want, tt.message)
		})
	}
}

func assertAuthFileQuotaError(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, wantError string) {
	t.Helper()
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, wantStatus, recorder.Body.String())
	}
	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error != wantError {
		t.Fatalf("error = %q, want %q", response.Error, wantError)
	}
}

type authFileQuotaHandlerStore struct{}

func (authFileQuotaHandlerStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (authFileQuotaHandlerStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	return auth.ID, nil
}
func (authFileQuotaHandlerStore) Delete(context.Context, string) error { return nil }

func registerAuthFileQuotaHandlerAuth(t *testing.T, manager *coreauth.Manager, auth *coreauth.Auth) *coreauth.Auth {
	t.Helper()
	registered, err := manager.Register(context.Background(), auth)
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}
	return registered
}

func performAuthFileQuotaRequest(t *testing.T, handler *Handler, tenantID, method, path, body string, endpoint gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set(managementPrincipalKey, identity.Principal{EffectiveTenant: identity.Tenant{ID: tenantID}})
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	ctx.Request = request
	endpoint(ctx)
	return recorder
}

func TestAuthFileQuotaHandlerScopesAuthToEffectiveTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var observedTokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/claude" || r.Method != http.MethodGet {
			t.Errorf("unexpected target %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		observedTokens = append(observedTokens, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"five_hour":{"utilization":25}}`))
	}))
	defer server.Close()

	manager := coreauth.NewManager(authFileQuotaHandlerStore{}, nil, nil)
	authA := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "tenant-a-auth", TenantID: "tenant-a", Provider: "claude", FileName: "tenant-a.json", Metadata: map[string]any{"access_token": "tenant-a-token"}})
	authB := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "tenant-b-auth", TenantID: "tenant-b", Provider: "claude", FileName: "tenant-b.json", Metadata: map[string]any{"access_token": "tenant-b-token"}})
	handler := &Handler{
		cfg:                       &config.Config{},
		authManager:               manager,
		authFileQuotaDependencies: authfilequota.Dependencies{Endpoints: authfilequota.Endpoints{ClaudeUsage: server.URL + "/claude"}},
	}

	foreign := performAuthFileQuotaRequest(t, handler, "tenant-b", http.MethodGet, "/auth-files/quota?auth_index="+authA.Index, "", handler.GetAuthFileQuota)
	assertAuthFileQuotaError(t, foreign, http.StatusNotFound, "auth not found")
	if len(observedTokens) != 0 {
		t.Fatalf("foreign auth caused upstream request with tokens %v", observedTokens)
	}

	owned := performAuthFileQuotaRequest(t, handler, "tenant-b", http.MethodGet, "/auth-files/quota?auth_index="+authB.Index, "", handler.GetAuthFileQuota)
	if owned.Code != http.StatusOK {
		t.Fatalf("owned quota status = %d body=%s", owned.Code, owned.Body.String())
	}
	var result authfilequota.QuotaResult
	if err := json.Unmarshal(owned.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode quota response: %v", err)
	}
	if result.Provider != "claude" || len(result.Items) != 1 || result.Items[0].Percent == nil || *result.Items[0].Percent != 75 {
		t.Fatalf("normalized quota response = %#v", result)
	}
	if !reflect.DeepEqual(observedTokens, []string{"Bearer tenant-b-token"}) {
		t.Fatalf("upstream authorization = %#v, want only tenant B", observedTokens)
	}
}

func TestAuthFileQuotaHandlerValidatesProviderAndCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := coreauth.NewManager(authFileQuotaHandlerStore{}, nil, nil)
	unsupported := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "unsupported", TenantID: "tenant-a", Provider: "other", FileName: "unsupported.json", Metadata: map[string]any{"access_token": "token"}})
	claudeKey := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "claude-key", TenantID: "tenant-a", Provider: "claude", FileName: "claude-key.json", Metadata: map[string]any{"api_key": "secret"}})
	missingToken := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "missing-token", TenantID: "tenant-a", Provider: "claude", FileName: "missing-token.json"})
	handler := &Handler{cfg: &config.Config{}, authManager: manager}

	for _, tt := range []struct {
		name    string
		index   string
		status  int
		message string
	}{
		{name: "unknown provider", index: unsupported.Index, status: http.StatusBadRequest, message: "quota unsupported for auth provider"},
		{name: "claude api key", index: claudeKey.Index, status: http.StatusBadRequest, message: "quota unsupported for auth provider"},
		{name: "missing token", index: missingToken.Index, status: http.StatusBadRequest, message: "auth token not found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := performAuthFileQuotaRequest(t, handler, "tenant-a", http.MethodGet, "/auth-files/quota?auth_index="+tt.index, "", handler.GetAuthFileQuota)
			assertAuthFileQuotaError(t, recorder, tt.status, tt.message)
		})
	}
}

func TestCodexResetCreditHandlerUsesFixedRequestAndServerUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var gotPath, gotMethod, gotAuthorization, redeemID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotAuthorization = r.Header.Get("Authorization")
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode reset request: %v", err)
		}
		if len(payload) != 1 {
			t.Errorf("reset request fields = %#v, want only redeem_request_id", payload)
		}
		redeemID, _ = payload["redeem_request_id"].(string)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	manager := coreauth.NewManager(authFileQuotaHandlerStore{}, nil, nil)
	auth := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "reset", TenantID: "tenant-a", Provider: "codex", FileName: "reset.json", Metadata: map[string]any{"access_token": "codex-token"}})
	handler := &Handler{
		cfg:                       &config.Config{},
		authManager:               manager,
		authFileQuotaDependencies: authfilequota.Dependencies{Endpoints: authfilequota.Endpoints{CodexConsumeResetCredit: server.URL + "/fixed-consume"}},
	}
	body := `{"auth_index":"` + auth.Index + `","url":"` + server.URL + `/attacker","method":"GET","headers":{"Authorization":"Bearer attacker"},"redeem_request_id":"attacker-id"}`
	recorder := performAuthFileQuotaRequest(t, handler, "tenant-a", http.MethodPost, "/auth-files/codex/reset-credit/consume", body, handler.ConsumeCodexResetCredit)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"status":"ok"}` {
		t.Fatalf("reset status/body = %d / %s", recorder.Code, recorder.Body.String())
	}
	if gotPath != "/fixed-consume" || gotMethod != http.MethodPost || gotAuthorization != "Bearer codex-token" {
		t.Fatalf("fixed reset request = %s %s %q", gotMethod, gotPath, gotAuthorization)
	}
	if redeemID == "attacker-id" {
		t.Fatal("handler forwarded attacker-supplied redeem ID")
	}
	if _, err := uuid.Parse(redeemID); err != nil {
		t.Fatalf("server redeem ID %q is not a UUID: %v", redeemID, err)
	}
}

func TestAuthFileQuotaHandlerSanitizesUpstreamFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name     string
		response string
		status   int
		message  string
	}{
		{name: "non success response", response: "private upstream diagnostic", status: http.StatusBadGateway, message: "quota request failed"},
		{name: "invalid success response", response: "not JSON", status: http.StatusOK, message: "invalid quota response"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()
			manager := coreauth.NewManager(authFileQuotaHandlerStore{}, nil, nil)
			auth := registerAuthFileQuotaHandlerAuth(t, manager, &coreauth.Auth{ID: "failure-" + tt.name, TenantID: "tenant-a", Provider: "claude", FileName: "failure-" + tt.name + ".json", Metadata: map[string]any{"access_token": "token"}})
			handler := &Handler{
				cfg:                       &config.Config{},
				authManager:               manager,
				authFileQuotaDependencies: authfilequota.Dependencies{Endpoints: authfilequota.Endpoints{ClaudeUsage: server.URL}},
			}
			recorder := performAuthFileQuotaRequest(t, handler, "tenant-a", http.MethodGet, "/auth-files/quota?auth_index="+auth.Index, "", handler.GetAuthFileQuota)
			assertAuthFileQuotaError(t, recorder, http.StatusBadGateway, tt.message)
			if strings.Contains(recorder.Body.String(), tt.response) {
				t.Fatalf("response leaked upstream body: %s", recorder.Body.String())
			}
		})
	}

}
