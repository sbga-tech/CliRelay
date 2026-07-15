package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestFetchOpenAICompatModelsStrictNormalizesSavedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if got := r.Host; got != "compat.saved-host.test" {
			t.Fatalf("Host=%q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("Authorization=%q", got)
		}
		if got := r.Header.Get("X-Test"); got != "saved-header" {
			t.Fatalf("X-Test=%q", got)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"model-a","owned_by":"owner-a"},{"id":"MODEL-A","owned_by":"duplicate"},{"id":"  "}]}`))
	}))
	defer srv.Close()

	models, err := FetchOpenAICompatModelsStrict(context.Background(), &cliproxyauth.Auth{
		Provider: "openai-compatibility",
		Attributes: map[string]string{
			"base_url":      srv.URL + "/v1",
			"api_key":       "test-key",
			"header:X-Test": "saved-header",
			"header:Host":   "compat.saved-host.test",
		},
	}, nil)
	if err != nil {
		t.Fatalf("FetchOpenAICompatModelsStrict() error = %v", err)
	}
	if len(models) != 1 || models[0].ID != "model-a" || models[0].OwnedBy != "owner-a" {
		t.Fatalf("models=%+v", models)
	}
}

func TestFetchOpenAICompatModelsStrictRejectsRedirectWithoutFollowing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("redirect was followed to %q", r.URL.Path)
		}
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer srv.Close()

	models, err := FetchOpenAICompatModelsStrict(context.Background(), &cliproxyauth.Auth{Attributes: map[string]string{
		"base_url":      srv.URL + "/v1",
		"api_key":       "test-key",
		"header:X-Test": "saved-header",
	}}, nil)
	if err == nil {
		t.Fatal("expected redirect status error")
	}
	if len(models) != 0 {
		t.Fatalf("models=%v", models)
	}
}

func TestFetchOpenAICompatModelsStrictRejectsMissingBase(t *testing.T) {
	models, err := FetchOpenAICompatModelsStrict(context.Background(), &cliproxyauth.Auth{
		Attributes: map[string]string{"api_key": "test-key"},
	}, nil)
	if err == nil {
		t.Fatal("expected missing base URL error")
	}
	if len(models) != 0 {
		t.Fatalf("models=%v", models)
	}
}
