package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestCheckGeminiProviderUsesSavedRowAndTreats401AsReachable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want no credential", got)
		}
		if got := r.Header.Get("X-Provider-Header"); got != "" {
			t.Errorf("X-Provider-Header = %q, want no custom header", got)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	h := NewHandler(&config.Config{GeminiKey: []config.GeminiKey{{
		APIKey:  "stored-secret",
		BaseURL: server.URL,
		Headers: map[string]string{"X-Provider-Header": "must-not-send"},
	}}}, "", nil)
	defer h.Close()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/gemini-api-key/check", bytes.NewBufferString(`{"index":0}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.CheckGeminiProvider(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		OK         bool `json:"ok"`
		StatusCode int  `json:"status_code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.OK || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("result = %+v, want reachable 401", result)
	}
}

func TestProviderProbeHandlersValidateOnlySavedIndexes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewHandler(&config.Config{GeminiKey: []config.GeminiKey{{}}}, "", nil)
	defer h.Close()

	invalidRecorder := httptest.NewRecorder()
	invalidCtx, _ := gin.CreateTestContext(invalidRecorder)
	invalidCtx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/gemini-api-key/check", bytes.NewBufferString(`{"index":-1}`))
	invalidCtx.Request.Header.Set("Content-Type", "application/json")
	h.CheckGeminiProvider(invalidCtx)
	if invalidRecorder.Code != http.StatusBadRequest || invalidRecorder.Body.String() != `{"error":"invalid index"}` {
		t.Fatalf("negative index response = %d %s", invalidRecorder.Code, invalidRecorder.Body.String())
	}

	missingRecorder := httptest.NewRecorder()
	missingCtx, _ := gin.CreateTestContext(missingRecorder)
	missingCtx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/gemini-api-key/check", bytes.NewBufferString(`{"index":1}`))
	missingCtx.Request.Header.Set("Content-Type", "application/json")
	h.CheckGeminiProvider(missingCtx)
	if missingRecorder.Code != http.StatusNotFound || missingRecorder.Body.String() != `{"error":"provider not found"}` {
		t.Fatalf("out-of-range response = %d %s", missingRecorder.Code, missingRecorder.Body.String())
	}

	modelsRecorder := httptest.NewRecorder()
	modelsCtx, _ := gin.CreateTestContext(modelsRecorder)
	modelsCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/claude-api-key/models?index=1.5", nil)
	h.DiscoverClaudeProviderModels(modelsCtx)
	if modelsRecorder.Code != http.StatusBadRequest || modelsRecorder.Body.String() != `{"error":"invalid index"}` {
		t.Fatalf("non-integer model index response = %d %s", modelsRecorder.Code, modelsRecorder.Body.String())
	}
}
