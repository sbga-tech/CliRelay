package executor

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestStrictModelHelpersUseSavedNormalizationDefaultsAndHostQuery(t *testing.T) {
	var calls atomic.Int32
	ctx := sdkexecutor.WithRoundTripper(context.Background(), roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		switch req.URL.Host {
		case "api.anthropic.com":
			if got := req.URL.String(); got != "https://api.anthropic.com/v1/models" {
				t.Errorf("Claude default URL = %q", got)
			}
			if got := req.Header.Get("x-api-key"); got != "claude-key" {
				t.Errorf("Claude x-api-key = %q", got)
			}
			return strictModelResponse(req, `{"data":[{"id":"claude-default"}]}`), nil
		case "api.openai.com":
			if got := req.URL.String(); got != "https://api.openai.com/v1/models" {
				t.Errorf("Codex API-key default URL = %q", got)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer codex-key" {
				t.Errorf("Codex Authorization = %q", got)
			}
			return strictModelResponse(req, `{"data":[{"id":"codex-default"}]}`), nil
		case "compat.example.test":
			if got := req.URL.String(); got != "https://compat.example.test/bridge/v1/models?keep=query" {
				t.Errorf("OpenAI-compatible URL = %q", got)
			}
			if got := req.Host; got != "catalog.saved-host.test" {
				t.Errorf("OpenAI-compatible Host = %q", got)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer compat-key" {
				t.Errorf("OpenAI-compatible Authorization = %q", got)
			}
			return strictModelResponse(req, `{"data":[{"id":"Model-A","owned_by":"first"},{"id":"model-a","owned_by":"duplicate"},{"id":"  "}]}`), nil
		default:
			t.Errorf("unexpected strict discovery host %q", req.URL.Host)
			return strictModelResponse(req, `{}`), nil
		}
	}))

	claudeModels, err := FetchClaudeModelsStrict(ctx, &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "claude-key"}}, nil)
	if err != nil || len(claudeModels) != 1 || claudeModels[0].ID != "claude-default" {
		t.Fatalf("FetchClaudeModelsStrict() = %+v, %v", claudeModels, err)
	}
	codexModels, err := FetchCodexModelsStrict(ctx, &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "codex-key"}}, nil)
	if err != nil || len(codexModels) != 1 || codexModels[0].ID != "codex-default" {
		t.Fatalf("FetchCodexModelsStrict() = %+v, %v", codexModels, err)
	}
	compatModels, err := FetchOpenAICompatModelsStrict(ctx, &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":     "compat-key",
		"base_url":    "https://compat.example.test/bridge/models?keep=query#fragment",
		"header:Host": "catalog.saved-host.test",
	}}, nil)
	if err != nil || len(compatModels) != 1 || compatModels[0].ID != "Model-A" || compatModels[0].OwnedBy != "first" {
		t.Fatalf("FetchOpenAICompatModelsStrict() = %+v, %v", compatModels, err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("strict discovery calls = %d, want 3", got)
	}
}

func TestFetchCodexModelsStrictRejectsRedirectAndOversizedBodyWithoutCacheFallback(t *testing.T) {
	redirectCalls := atomic.Int32{}
	redirectCtx := sdkexecutor.WithRoundTripper(context.Background(), roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		redirectCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"https://redirected.example.test/v1/models"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}))
	models, err := FetchCodexModelsStrict(redirectCtx, &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "codex-key",
		"base_url": "https://catalog.example.test/v1?keep=query",
	}}, nil)
	if err == nil || len(models) != 0 {
		t.Fatalf("redirect models = %+v, err = %v; want strict failure", models, err)
	}
	if got := redirectCalls.Load(); got != 1 {
		t.Fatalf("redirect request count = %d, want one non-followed request", got)
	}

	oversizedCtx := sdkexecutor.WithRoundTripper(context.Background(), roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(make([]byte, strictModelDiscoveryResponseBodyLimit+1))),
			Request:    req,
		}, nil
	}))
	models, err = FetchCodexModelsStrict(oversizedCtx, &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "codex-key"}}, nil)
	if err == nil || len(models) != 0 {
		t.Fatalf("oversized models = %+v, err = %v; want bounded strict failure", models, err)
	}
}

func strictModelResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
