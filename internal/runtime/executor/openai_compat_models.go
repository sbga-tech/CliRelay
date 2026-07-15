package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkmodelcatalog "github.com/router-for-me/CLIProxyAPI/v6/sdk/modelcatalog"
)

type openAICompatModelsResponse struct {
	Data   []openAICompatModelPayload `json:"data"`
	Models []openAICompatModelPayload `json:"models"`
	Items  []openAICompatModelPayload `json:"items"`
}

type openAICompatModelPayload struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// FetchOpenAICompatModelsStrict retrieves a saved OpenAI-compatible provider's
// /v1/models catalog without reading or updating a process-global model cache.
func FetchOpenAICompatModelsStrict(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) ([]*sdkmodelcatalog.ModelInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseURL, apiKey := openAICompatModelsCredentials(auth)
	if baseURL == "" {
		return nil, fmt.Errorf("openai-compatible models: base URL is required")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("openai-compatible models: credentials are required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buildOpenAICompatModelsURL(baseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("create openai-compatible models request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
	applyStoredHostHeader(req, auth)

	resp, err := newStrictModelDiscoveryHTTPClient(ctx, cfg, auth).Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai-compatible models request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("openai-compatible models request returned status %d", resp.StatusCode)
	}
	body, err := readStrictModelDiscoveryResponseBody(resp.Body)
	if err != nil {
		return nil, err
	}
	models, ok := parseOpenAICompatModels(body, time.Now().Unix())
	if !ok {
		return nil, fmt.Errorf("invalid or empty openai-compatible models response")
	}
	return models, nil
}

func openAICompatModelsCredentials(auth *cliproxyauth.Auth) (baseURL, apiKey string) {
	if auth == nil || auth.Attributes == nil {
		return "", ""
	}
	return strings.TrimSpace(auth.Attributes["base_url"]), strings.TrimSpace(auth.Attributes["api_key"])
}

func buildOpenAICompatModelsURL(baseURL string) string {
	return buildV1ModelsURL(baseURL)
}

func parseOpenAICompatModels(body []byte, now int64) ([]*sdkmodelcatalog.ModelInfo, bool) {
	var decoded openAICompatModelsResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		var entries []openAICompatModelPayload
		if arrayErr := json.Unmarshal(body, &entries); arrayErr != nil {
			return nil, false
		}
		decoded.Data = entries
	}

	entries := decoded.Data
	if len(entries) == 0 {
		entries = decoded.Models
	}
	if len(entries) == 0 {
		entries = decoded.Items
	}
	out := make([]*sdkmodelcatalog.ModelInfo, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, item := range entries {
		modelID := strings.TrimSpace(item.ID)
		if modelID == "" {
			continue
		}
		key := strings.ToLower(modelID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		object := strings.TrimSpace(item.Object)
		if object == "" {
			object = "model"
		}
		created := item.Created
		if created == 0 {
			created = now
		}
		out = append(out, &sdkmodelcatalog.ModelInfo{
			ID:          modelID,
			Object:      object,
			Created:     created,
			OwnedBy:     strings.TrimSpace(item.OwnedBy),
			Type:        "openai-compatibility",
			DisplayName: modelID,
			Name:        modelID,
			Version:     modelID,
		})
	}
	return out, len(out) > 0
}
