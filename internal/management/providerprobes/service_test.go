package providerprobes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/synthesizer"
)

func TestCheckUsesSavedBaseWithoutCredentialsOrHeaders(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/saved-base" {
			t.Errorf("path = %s, want /saved-base", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}
		if got := r.Header.Get("X-Saved-Only"); got != "" {
			t.Errorf("custom header = %q, want empty", got)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	service := NewService(&config.Config{GeminiKey: []config.GeminiKey{{
		APIKey:  "stored-secret",
		BaseURL: server.URL + "/saved-base",
		Headers: map[string]string{"X-Saved-Only": "must-not-send"},
	}}})

	result, err := service.Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.OK || result.StatusCode == nil || *result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Check() = %+v, want reachable 401", result)
	}
	if result.Message != "" {
		t.Fatalf("message = %q, want empty", result.Message)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestCheckReportsTransportFailureWithoutServiceError(t *testing.T) {
	t.Parallel()

	service := NewService(&config.Config{GeminiKey: []config.GeminiKey{{
		BaseURL: "http://127.0.0.1:1",
	}}})

	result, err := service.Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if result.OK || result.StatusCode != nil || result.Message != "request failed" {
		t.Fatalf("Check() = %+v, want unreachable result", result)
	}
}

func TestCheckValidatesSavedIndexAndBaseURL(t *testing.T) {
	t.Parallel()

	service := NewService(&config.Config{GeminiKey: []config.GeminiKey{{}}})
	if _, err := service.Check(context.Background(), synthesizer.ConfigProviderKindGemini, -1); !errors.Is(err, ErrInvalidIndex) {
		t.Fatalf("negative Check() error = %v, want ErrInvalidIndex", err)
	}
	if _, err := service.Check(context.Background(), synthesizer.ConfigProviderKindGemini, 1); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("out-of-range Check() error = %v, want ErrProviderNotFound", err)
	}
	if _, err := service.Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0); !errors.Is(err, ErrProviderBaseURLRequired) {
		t.Fatalf("blank-base Check() error = %v, want ErrProviderBaseURLRequired", err)
	}
}

func TestDiscoverModelsNormalizesAndDoesNotUsePriorSuccess(t *testing.T) {
	t.Parallel()

	var healthy atomic.Bool
	healthy.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			t.Errorf("request = %s %s, want GET /v1/models", r.Method, r.URL.Path)
		}
		if !healthy.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"Claude-One"},{"id":"claude-one"},{"id":" "},{"id":"Claude-Two"}]}`))
	}))
	defer server.Close()

	service := NewService(&config.Config{ClaudeKey: []config.ClaudeKey{{
		APIKey:  "stored-secret",
		BaseURL: server.URL,
	}}})

	result, err := service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindClaude, 0)
	if err != nil {
		t.Fatalf("DiscoverModels() error = %v", err)
	}
	if len(result.Models) != 2 || result.Models[0].ID != "Claude-One" || result.Models[1].ID != "Claude-Two" {
		t.Fatalf("models = %+v, want blank-filtered case-insensitive de-duplication", result.Models)
	}

	healthy.Store(false)
	if _, err = service.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindClaude, 0); !errors.Is(err, ErrModelDiscoveryFailed) {
		t.Fatalf("failed DiscoverModels() error = %v, want strict cache-free failure", err)
	}
}

func TestDiscoverModelsValidatesCredentialAndOpenAIBaseURL(t *testing.T) {
	t.Parallel()

	claude := NewService(&config.Config{ClaudeKey: []config.ClaudeKey{{}}})
	if _, err := claude.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindClaude, 0); !errors.Is(err, ErrProviderCredentialRequired) {
		t.Fatalf("blank credential error = %v, want ErrProviderCredentialRequired", err)
	}

	openAI := NewService(&config.Config{OpenAICompatibility: []config.OpenAICompatibility{{APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "stored-secret"}}}}})
	if _, err := openAI.DiscoverModels(context.Background(), synthesizer.ConfigProviderKindOpenAICompatibility, 0); !errors.Is(err, ErrProviderBaseURLRequired) {
		t.Fatalf("blank OpenAI base error = %v, want ErrProviderBaseURLRequired", err)
	}
}

func TestCheckDoesNotFollowRedirectsOrSendURLUserinfo(t *testing.T) {
	t.Parallel()

	var redirected atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer redirectTarget.Close()

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirectSource.Close()

	redirectService := NewService(&config.Config{GeminiKey: []config.GeminiKey{{BaseURL: redirectSource.URL}}})
	redirectResult, err := redirectService.Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil {
		t.Fatalf("redirect Check() error = %v", err)
	}
	if !redirectResult.OK || redirectResult.StatusCode == nil || *redirectResult.StatusCode != http.StatusFound {
		t.Fatalf("redirect Check() = %+v, want reachable 302", redirectResult)
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("redirect target requests = %d, want 0", got)
	}

	var userinfoRequests atomic.Int32
	userinfoTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		userinfoRequests.Add(1)
	}))
	defer userinfoTarget.Close()
	userinfoURL := strings.Replace(userinfoTarget.URL, "http://", "http://user:password@", 1)
	userinfoService := NewService(&config.Config{GeminiKey: []config.GeminiKey{{BaseURL: userinfoURL}}})
	userinfoResult, err := userinfoService.Check(context.Background(), synthesizer.ConfigProviderKindGemini, 0)
	if err != nil {
		t.Fatalf("userinfo Check() error = %v", err)
	}
	if userinfoResult.OK || userinfoResult.Message != "request failed" {
		t.Fatalf("userinfo Check() = %+v, want sanitized failure", userinfoResult)
	}
	if got := userinfoRequests.Load(); got != 0 {
		t.Fatalf("userinfo target requests = %d, want 0", got)
	}
}
