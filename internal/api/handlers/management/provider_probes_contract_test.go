package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/identity"
)

func TestProviderCheckHandlersCoverEverySavedProviderKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gemini", "/claude", "/codex", "/vertex", "/bedrock":
		default:
			t.Errorf("unexpected saved destination %q", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Custom") != "" {
			t.Errorf("probe leaked stored credentials or headers: %#v", r.Header)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	h := NewHandler(&config.Config{
		GeminiKey:          []config.GeminiKey{{APIKey: "gemini-secret", BaseURL: server.URL + "/gemini", Headers: map[string]string{"X-Custom": "no"}}},
		ClaudeKey:          []config.ClaudeKey{{APIKey: "claude-secret", BaseURL: server.URL + "/claude", Headers: map[string]string{"X-Custom": "no"}}},
		CodexKey:           []config.CodexKey{{APIKey: "codex-secret", BaseURL: server.URL + "/codex", Headers: map[string]string{"X-Custom": "no"}}},
		VertexCompatAPIKey: []config.VertexCompatKey{{APIKey: "vertex-secret", BaseURL: server.URL + "/vertex", Headers: map[string]string{"X-Custom": "no"}}},
		BedrockKey:         []config.BedrockKey{{AuthMode: config.BedrockAuthModeAPIKey, APIKey: "bedrock-secret", BaseURL: server.URL + "/bedrock", Headers: map[string]string{"X-Custom": "no"}}},
	}, "", nil)
	defer h.Close()

	for _, tc := range []struct {
		name    string
		path    string
		handler gin.HandlerFunc
	}{
		{"gemini", "/v0/management/gemini-api-key/check", h.CheckGeminiProvider},
		{"claude", "/v0/management/claude-api-key/check", h.CheckClaudeProvider},
		{"codex", "/v0/management/codex-api-key/check", h.CheckCodexProvider},
		{"vertex", "/v0/management/vertex-api-key/check", h.CheckVertexProvider},
		{"bedrock", "/v0/management/bedrock-api-key/check", h.CheckBedrockProvider},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(`{"index":0}`))
			ctx.Request.Header.Set("Content-Type", "application/json")
			tc.handler(ctx)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			var result struct {
				OK         bool `json:"ok"`
				StatusCode int  `json:"status_code"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !result.OK || result.StatusCode != http.StatusForbidden {
				t.Fatalf("result = %+v, want reachable 403", result)
			}
		})
	}
}

func TestProviderProbeHandlersUseRequestCachedOrdinaryTenantConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var systemHits, tenantHits atomic.Int32
	systemServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		systemHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer systemServer.Close()
	tenantServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tenantHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tenantServer.Close()

	h := NewHandler(&config.Config{GeminiKey: []config.GeminiKey{{APIKey: "system-secret", BaseURL: systemServer.URL}}}, "", nil)
	defer h.Close()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set(managementPrincipalKey, identity.Principal{EffectiveTenant: identity.Tenant{ID: "tenant-provider-probe"}})
	ctx.Set(providerTenantConfigKey, &config.Config{GeminiKey: []config.GeminiKey{{APIKey: "tenant-secret", BaseURL: tenantServer.URL}}})
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/gemini-api-key/check", bytes.NewBufferString(`{"index":0}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.CheckGeminiProvider(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := tenantHits.Load(); got != 1 {
		t.Fatalf("tenant saved destination calls = %d, want 1", got)
	}
	if got := systemHits.Load(); got != 0 {
		t.Fatalf("system saved destination calls = %d, tenant config was bypassed", got)
	}
	if body := recorder.Body.String(); body != `{"ok":true,"status_code":401,"latency_ms":0}` && !bytes.Contains(recorder.Body.Bytes(), []byte(`"status_code":401`)) {
		t.Fatalf("response = %s, want reachable tenant 401", body)
	}
}

func TestProviderModelDiscoveryHandlersSanitizeEveryUpstreamFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream-Secret", "do-not-leak")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`upstream detail must not escape`))
	}))
	defer server.Close()

	h := NewHandler(&config.Config{
		ClaudeKey: []config.ClaudeKey{{APIKey: "claude-secret", BaseURL: server.URL}},
		CodexKey:  []config.CodexKey{{APIKey: "codex-secret", BaseURL: server.URL}},
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:          "compat",
			BaseURL:       server.URL,
			APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "compat-secret"}},
		}},
	}, "", nil)
	defer h.Close()

	for _, tc := range []struct {
		name    string
		path    string
		handler gin.HandlerFunc
	}{
		{"claude", "/v0/management/claude-api-key/models?index=0", h.DiscoverClaudeProviderModels},
		{"codex", "/v0/management/codex-api-key/models?index=0", h.DiscoverCodexProviderModels},
		{"openai-compatible", "/v0/management/openai-compatibility/models?index=0", h.DiscoverOpenAICompatibilityModels},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.handler(ctx)
			if recorder.Code != http.StatusBadGateway || recorder.Body.String() != `{"error":"model discovery failed"}` {
				t.Fatalf("response = %d %s, want sanitized discovery failure", recorder.Code, recorder.Body.String())
			}
		})
	}
}
