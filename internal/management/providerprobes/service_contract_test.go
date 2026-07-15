package providerprobes

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/synthesizer"
)

func TestCheckSelectsExactSavedIndexForEverySupportedKind(t *testing.T) {
	seen := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path]++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	service := NewService(&config.Config{
		GeminiKey: []config.GeminiKey{
			{APIKey: "duplicate", BaseURL: server.URL + "/wrong-gemini"},
			{APIKey: "duplicate", BaseURL: server.URL + "/gemini"},
		},
		ClaudeKey: []config.ClaudeKey{
			{APIKey: "duplicate", BaseURL: server.URL + "/wrong-claude"},
			{APIKey: "duplicate", BaseURL: server.URL + "/claude"},
		},
		CodexKey: []config.CodexKey{
			{APIKey: "duplicate", BaseURL: server.URL + "/wrong-codex"},
			{APIKey: "duplicate", BaseURL: server.URL + "/codex"},
		},
		VertexCompatAPIKey: []config.VertexCompatKey{
			{APIKey: "duplicate", BaseURL: server.URL + "/wrong-vertex"},
			{APIKey: "duplicate", BaseURL: server.URL + "/vertex"},
		},
		BedrockKey: []config.BedrockKey{
			{AuthMode: config.BedrockAuthModeAPIKey, APIKey: "duplicate", BaseURL: server.URL + "/wrong-bedrock"},
			{AuthMode: config.BedrockAuthModeAPIKey, APIKey: "duplicate", BaseURL: server.URL + "/bedrock"},
		},
	})

	for _, tc := range []struct {
		name string
		kind synthesizer.ConfigProviderKind
		path string
	}{
		{"gemini", synthesizer.ConfigProviderKindGemini, "/gemini"},
		{"claude", synthesizer.ConfigProviderKindClaude, "/claude"},
		{"codex", synthesizer.ConfigProviderKindCodex, "/codex"},
		{"vertex", synthesizer.ConfigProviderKindVertex, "/vertex"},
		{"bedrock", synthesizer.ConfigProviderKindBedrock, "/bedrock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.Check(context.Background(), tc.kind, 1)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !result.OK || result.StatusCode == nil || *result.StatusCode != http.StatusNoContent {
				t.Fatalf("Check() = %+v, want reachable selected row", result)
			}
			if got := seen[tc.path]; got != 1 {
				t.Fatalf("selected path %s requests = %d, want 1", tc.path, got)
			}
		})
	}
	for _, wrong := range []string{"/wrong-gemini", "/wrong-claude", "/wrong-codex", "/wrong-vertex", "/wrong-bedrock"} {
		if got := seen[wrong]; got != 0 {
			t.Errorf("unselected path %s requests = %d", wrong, got)
		}
	}
}

func TestDiscoverModelsSelectsSavedRowsIncludingDisabledOpenAICompatibility(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wantKey string
		switch r.URL.Path {
		case "/claude/v1/models":
			wantKey = "claude-selected"
		case "/codex/v1/models":
			wantKey = "codex-selected"
		case "/compat/v1/models":
			wantKey = "compat-selected"
		default:
			t.Errorf("unexpected models destination %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantKey {
			t.Errorf("Authorization = %q, want selected credential", got)
		}
		if r.URL.Query().Get("selected") == "" {
			t.Errorf("query was not retained in %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"Selected-Model","owned_by":"selected"},{"id":"selected-model"}]}`))
	}))
	defer server.Close()

	service := NewService(&config.Config{
		ClaudeKey: []config.ClaudeKey{
			{APIKey: "claude-wrong", BaseURL: server.URL + "/wrong?selected=wrong"},
			{APIKey: "claude-selected", BaseURL: server.URL + "/claude/v1?selected=claude"},
		},
		CodexKey: []config.CodexKey{
			{APIKey: "codex-wrong", BaseURL: server.URL + "/wrong?selected=wrong"},
			{APIKey: "codex-selected", BaseURL: server.URL + "/codex/v1?selected=codex"},
		},
		OpenAICompatibility: []config.OpenAICompatibility{
			{Name: "wrong", BaseURL: server.URL + "/wrong?selected=wrong", APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "compat-wrong"}}},
			{
				Name:          "disabled-but-saved",
				Disabled:      true,
				BaseURL:       server.URL + "/compat/v1?selected=compat",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: " "}, {APIKey: "compat-selected", Disabled: true}},
			},
		},
	})

	for _, tc := range []struct {
		name        string
		kind        synthesizer.ConfigProviderKind
		wantOwnedBy string
	}{
		{"claude", synthesizer.ConfigProviderKindClaude, "claude"},
		{"codex", synthesizer.ConfigProviderKindCodex, "selected"},
		{"disabled OpenAI-compatible", synthesizer.ConfigProviderKindOpenAICompatibility, "selected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.DiscoverModels(context.Background(), tc.kind, 1)
			if err != nil {
				t.Fatalf("DiscoverModels() error = %v", err)
			}
			if len(result.Models) != 1 || result.Models[0].ID != "Selected-Model" || result.Models[0].OwnedBy != tc.wantOwnedBy {
				t.Fatalf("models = %+v, want normalized selected catalog", result.Models)
			}
		})
	}
}

func TestProviderProbeOperationsRejectUnsupportedAndInvalidSelections(t *testing.T) {
	service := NewService(&config.Config{
		GeminiKey: []config.GeminiKey{{BaseURL: "https://example.invalid"}},
		ClaudeKey: []config.ClaudeKey{{}},
		CodexKey:  []config.CodexKey{{}},
		OpenAICompatibility: []config.OpenAICompatibility{{
			APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key"}},
		}},
	})

	if _, err := service.Check(context.Background(), synthesizer.ConfigProviderKindOpenAICompatibility, 0); !errors.Is(err, ErrUnsupportedProviderKind) {
		t.Fatalf("OpenAI-compatible Check() error = %v, want unsupported", err)
	}
	if _, err := service.Check(context.Background(), synthesizer.ConfigProviderKind("unknown"), 0); !errors.Is(err, ErrUnsupportedProviderKind) {
		t.Fatalf("unknown Check() error = %v, want unsupported", err)
	}
	if _, err := service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindGemini, 0); !errors.Is(err, ErrUnsupportedProviderKind) {
		t.Fatalf("Gemini DiscoverModels() error = %v, want unsupported", err)
	}
	if _, err := service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindClaude, -1); !errors.Is(err, ErrInvalidIndex) {
		t.Fatalf("negative DiscoverModels() error = %v, want invalid index", err)
	}
	if _, err := service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindCodex, 1); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("out-of-range DiscoverModels() error = %v, want provider not found", err)
	}
	if _, err := service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindClaude, 0); !errors.Is(err, ErrProviderCredentialRequired) {
		t.Fatalf("blank Claude credential error = %v, want credential required", err)
	}
	if _, err := service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindOpenAICompatibility, 0); !errors.Is(err, ErrProviderBaseURLRequired) {
		t.Fatalf("blank OpenAI-compatible base error = %v, want base required", err)
	}
}

func TestCheckProxyResolutionUsesIDThenAuthThenConfiguredFallback(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	newProxy := func(hits *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.Method != http.MethodGet {
				t.Errorf("proxy method = %s, want GET", r.Method)
			}
			w.WriteHeader(http.StatusAccepted)
		}))
	}
	var idHits, authHits, globalHits atomic.Int32
	idProxy := newProxy(&idHits)
	defer idProxy.Close()
	authProxy := newProxy(&authHits)
	defer authProxy.Close()
	globalProxy := newProxy(&globalHits)
	defer globalProxy.Close()

	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want *atomic.Int32
	}{
		{
			name: "enabled proxy ID wins",
			cfg: &config.Config{
				SDKConfig: config.SDKConfig{ProxyURL: globalProxy.URL},
				ProxyPool: []config.ProxyPoolEntry{{ID: "selected", URL: idProxy.URL, Enabled: true}},
				GeminiKey: []config.GeminiKey{{BaseURL: target.URL, ProxyID: "selected", ProxyURL: authProxy.URL}},
			},
			want: &idHits,
		},
		{
			name: "auth proxy is fallback for unresolved ID",
			cfg: &config.Config{
				SDKConfig: config.SDKConfig{ProxyURL: globalProxy.URL},
				GeminiKey: []config.GeminiKey{{BaseURL: target.URL, ProxyID: "missing", ProxyURL: authProxy.URL}},
			},
			want: &authHits,
		},
		{
			name: "configured proxy is final fallback",
			cfg: &config.Config{
				SDKConfig: config.SDKConfig{ProxyURL: globalProxy.URL},
				GeminiKey: []config.GeminiKey{{BaseURL: target.URL}},
			},
			want: &globalHits,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.want.Load()
			result, err := NewService(tc.cfg).Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !result.OK || result.StatusCode == nil || *result.StatusCode != http.StatusAccepted {
				t.Fatalf("Check() = %+v, want proxy response", result)
			}
			if got := tc.want.Load(); got != before+1 {
				t.Fatalf("selected proxy calls = %d, want %d", got, before+1)
			}
		})
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("direct target calls = %d, proxy precedence was bypassed", got)
	}
}

func TestCheckHonorsTLSAndPreferIPv4TransportConfiguration(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tlsServer.Close()

	result, err := NewService(&config.Config{
		SDKConfig: config.SDKConfig{InsecureSkipVerify: true},
		GeminiKey: []config.GeminiKey{{BaseURL: tlsServer.URL}},
	}).Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil || !result.OK || result.StatusCode == nil || *result.StatusCode != http.StatusNoContent {
		t.Fatalf("TLS Check() = %+v, %v; want reachable test TLS server", result, err)
	}

	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	baseURL := "http://" + listener.Addr().String()

	ipv6Result, err := NewService(&config.Config{GeminiKey: []config.GeminiKey{{BaseURL: baseURL}}}).Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil || !ipv6Result.OK {
		t.Fatalf("default network Check() = %+v, %v; want IPv6 reachable", ipv6Result, err)
	}
	ipv4OnlyResult, err := NewService(&config.Config{SDKConfig: config.SDKConfig{PreferIPv4: true}, GeminiKey: []config.GeminiKey{{BaseURL: baseURL}}}).Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil || ipv4OnlyResult.OK || ipv4OnlyResult.Message != "request failed" {
		t.Fatalf("PreferIPv4 Check() = %+v, %v; want IPv6-only transport failure", ipv4OnlyResult, err)
	}
}

func TestCheckReturnsSanitizedTimeoutFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result, err := NewService(&config.Config{GeminiKey: []config.GeminiKey{{BaseURL: server.URL}}}).Check(ctx, synthesizer.ConfigProviderKindGemini, 0)
	if err != nil {
		t.Fatalf("Check() error = %v, want sanitized result", err)
	}
	if result.OK || result.StatusCode != nil || result.Message != "request failed" {
		t.Fatalf("Check() = %+v, want timeout failure without upstream detail", result)
	}
}
