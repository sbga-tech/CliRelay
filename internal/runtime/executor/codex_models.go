package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkmodelcatalog "github.com/router-for-me/CLIProxyAPI/v6/sdk/modelcatalog"
	log "github.com/sirupsen/logrus"
)

const (
	// Official ChatGPT Codex models manifest (OAuth).
	// https://chatgpt.com/backend-api/codex/models?client_version=...
	// client_version gates which models ChatGPT returns (0.118 only had ~4 models;
	// >=0.150 includes gpt-5.5 and gpt-5.6-*). Prefer fingerprint / config version when present.
	defaultCodexModelsManifestBase = "https://chatgpt.com/backend-api/codex"
	defaultCodexModelsClientVer    = "0.180.0"
)

var codexModelsCache struct {
	mu     sync.RWMutex
	models []*sdkmodelcatalog.ModelInfo
}

type codexModelsResponse struct {
	Data   []codexModelPayload `json:"data"`
	Models []codexModelPayload `json:"models"`
	// Some Codex manifest revisions nest models under items/list.
	Items []codexModelPayload `json:"items"`
}

type codexModelPayload struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Title       string `json:"title"`
	Object      string `json:"object"`
	OwnedBy     string `json:"owned_by"`
	Created     int64  `json:"created"`
}

func cloneCodexModels(models []*sdkmodelcatalog.ModelInfo) []*sdkmodelcatalog.ModelInfo {
	if len(models) == 0 {
		return nil
	}
	out := make([]*sdkmodelcatalog.ModelInfo, 0, len(models))
	for _, model := range models {
		if model == nil || strings.TrimSpace(model.ID) == "" {
			continue
		}
		clone := *model
		if len(model.SupportedGenerationMethods) > 0 {
			clone.SupportedGenerationMethods = append([]string(nil), model.SupportedGenerationMethods...)
		}
		if len(model.SupportedParameters) > 0 {
			clone.SupportedParameters = append([]string(nil), model.SupportedParameters...)
		}
		if model.Thinking != nil {
			thinkingClone := *model.Thinking
			if len(model.Thinking.Levels) > 0 {
				thinkingClone.Levels = append([]string(nil), model.Thinking.Levels...)
			}
			clone.Thinking = &thinkingClone
		}
		out = append(out, &clone)
	}
	return out
}

func storeCodexModels(models []*sdkmodelcatalog.ModelInfo) bool {
	cloned := cloneCodexModels(models)
	if len(cloned) == 0 {
		return false
	}
	codexModelsCache.mu.Lock()
	codexModelsCache.models = cloned
	codexModelsCache.mu.Unlock()
	return true
}

func loadCodexModels() []*sdkmodelcatalog.ModelInfo {
	codexModelsCache.mu.RLock()
	cloned := cloneCodexModels(codexModelsCache.models)
	codexModelsCache.mu.RUnlock()
	return cloned
}

func fallbackCodexModels() []*sdkmodelcatalog.ModelInfo {
	if models := loadCodexModels(); len(models) > 0 {
		log.Debugf("codex executor: using cached model list (%d models)", len(models))
		return models
	}
	return nil
}

// resolveCodexModelsClientVersion picks the client_version for the Codex models manifest.
// Priority: cfg identity fingerprint Version / UA embedded version, then a modern fallback.
// A stale fallback (e.g. 0.118) truncates the upstream list and must not be used.
func resolveCodexModelsClientVersion(cfg *config.Config, auth *cliproxyauth.Auth) string {
	candidate := ""
	if cfg != nil {
		fp := cfg.IdentityFingerprint.Codex
		if v := strings.TrimSpace(fp.Version); v != "" {
			candidate = v
		} else if v := codexVersionFromUserAgent(fp.UserAgent); v != "" {
			// Ignore the historical default UA (0.118) which truncates the manifest.
			if !strings.HasPrefix(v, "0.118") {
				candidate = v
			}
		}
	}
	_ = auth
	if candidate == "" {
		return defaultCodexModelsClientVer
	}
	// Prefer the newer of candidate vs modern floor so discovery never regresses
	// to a pre-5.5/5.6 client_version gate.
	if compareCodexClientVersion(candidate, defaultCodexModelsClientVer) < 0 {
		return defaultCodexModelsClientVer
	}
	return candidate
}

// compareCodexClientVersion returns -1 if a<b, 0 if equal, 1 if a>b (numeric dotted).
func compareCodexClientVersion(a, b string) int {
	ap := strings.Split(strings.TrimSpace(a), ".")
	bp := strings.Split(strings.TrimSpace(b), ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		ai := parseCodexVersionPart(ap, i)
		bi := parseCodexVersionPart(bp, i)
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func parseCodexVersionPart(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	// Take leading digits only (e.g. "180" from "180", ignore "0rc1" suffix as 0).
	s := strings.TrimSpace(parts[i])
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}

func codexVersionFromUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ""
	}
	// codex_cli_rs/0.150.0 ... or codex-tui/0.118.0 ...
	for _, prefix := range []string{"codex_cli_rs/", "codex-tui/", "codex-cli/", "Codex Desktop/"} {
		idx := strings.Index(strings.ToLower(ua), strings.ToLower(prefix))
		if idx < 0 {
			continue
		}
		rest := ua[idx+len(prefix):]
		end := 0
		for end < len(rest) {
			c := rest[end]
			if (c >= '0' && c <= '9') || c == '.' {
				end++
				continue
			}
			break
		}
		if end > 0 {
			return rest[:end]
		}
	}
	return ""
}

// FetchCodexModels retrieves the live model list for a Codex auth.
// It retains the historical cached fallback for runtime callers.
func FetchCodexModels(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) []*sdkmodelcatalog.ModelInfo {
	models, err := FetchCodexModelsStrict(ctx, auth, cfg)
	if err != nil {
		log.Debugf("codex executor: models discovery failed: %v", err)
		return fallbackCodexModels()
	}
	storeCodexModels(models)
	return models
}

// FetchCodexModelsStrict retrieves a Codex catalog without using the process-global
// runtime model cache. API-key auth defaults to OpenAI's /v1/models endpoint; OAuth
// with no saved base retains the ChatGPT Codex manifest default.
func FetchCodexModelsStrict(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) ([]*sdkmodelcatalog.ModelInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	token, baseURL := codexCreds(auth)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("codex models: credentials are required")
	}

	useAPIKey := auth != nil && auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != ""
	baseURL = strings.TrimSpace(baseURL)
	clientVer := resolveCodexModelsClientVersion(cfg, auth)
	modelsURL, isManifest := buildCodexModelsURL(baseURL, useAPIKey, clientVer)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create codex models request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if isManifest {
		// Align with Codex CLI manifest probe headers. Version gates the model list.
		req.Header.Set("Originator", codexOriginator)
		req.Header.Set("Version", clientVer)
		req.Header.Set("User-Agent", "codex_cli_rs/"+clientVer)
		if accountID := codexAccountID(auth); accountID != "" {
			req.Header.Set("Chatgpt-Account-Id", accountID)
		}
	}
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
	applyStoredHostHeader(req, auth)

	resp, err := newStrictModelDiscoveryHTTPClient(ctx, cfg, auth).Do(req)
	if err != nil {
		return nil, fmt.Errorf("codex models request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("codex models request returned status %d", resp.StatusCode)
	}
	body, err := readStrictModelDiscoveryResponseBody(resp.Body)
	if err != nil {
		return nil, err
	}
	models, ok := parseCodexModelsStrict(body, time.Now().Unix())
	if !ok {
		return nil, fmt.Errorf("invalid or empty codex models response")
	}
	return models, nil
}

func codexAccountID(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok {
			if v := strings.TrimSpace(accountID); v != "" {
				return v
			}
		}
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["account_id"]); v != "" {
			return v
		}
	}
	return ""
}

func buildCodexModelsURL(baseURL string, useAPIKey bool, clientVersion string) (string, bool) {
	clientVersion = strings.TrimSpace(clientVersion)
	if clientVersion == "" {
		clientVersion = defaultCodexModelsClientVer
	}
	normalized := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if normalized == "" {
		if useAPIKey {
			return buildV1ModelsURL("https://api.openai.com"), false
		}
		// OAuth default: ChatGPT Codex models manifest.
		u := defaultCodexModelsManifestBase + "/models?client_version=" + url.QueryEscape(clientVersion)
		return u, true
	}

	lower := strings.ToLower(normalized)
	isChatGPTBase := modelsURLHasExactHostname(normalized, "chatgpt.com")
	isOpenAIBase := modelsURLHasExactHostname(normalized, "api.openai.com")
	if useAPIKey {
		return buildV1ModelsURL(normalized), false
	}
	// Already a models endpoint.
	if strings.HasSuffix(lower, "/models") || strings.Contains(lower, "/models?") {
		return normalized, isChatGPTBase
	}

	// ChatGPT backend bases expose the versioned Codex manifest.
	if isChatGPTBase {
		if !strings.HasSuffix(lower, "/codex") && !strings.Contains(lower, "/codex/") {
			// e.g. https://chatgpt.com/backend-api
			if strings.HasSuffix(lower, "/backend-api") {
				normalized = normalized + "/codex"
			}
		}
		return normalized + "/models?client_version=" + url.QueryEscape(clientVersion), true
	}

	// An OAuth record explicitly targeting OpenAI still uses the compatible endpoint.
	if isOpenAIBase {
		return buildV1ModelsURL(normalized), false
	}

	// Generic bases use a non-manifest models endpoint.
	return normalized + "/models", false
}

func parseCodexModelsStrict(body []byte, now int64) ([]*sdkmodelcatalog.ModelInfo, bool) {
	var arrayResponse []codexModelPayload
	if err := json.Unmarshal(body, &arrayResponse); err == nil {
		return codexModelInfosFromPayloads(arrayResponse, now)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false
	}
	if _, hasError := raw["error"]; hasError {
		return nil, false
	}

	entries := make([]codexModelPayload, 0)
	recognized := false
	for _, field := range []string{"data", "models", "items"} {
		value, exists := raw[field]
		if !exists {
			continue
		}
		recognized = true
		var group []codexModelPayload
		if err := json.Unmarshal(value, &group); err != nil {
			return nil, false
		}
		entries = append(entries, group...)
	}
	if !recognized || len(entries) == 0 {
		return nil, false
	}
	return codexModelInfosFromPayloads(entries, now)
}

func parseCodexModels(body []byte, now int64) ([]*sdkmodelcatalog.ModelInfo, bool) {
	var decoded codexModelsResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		var arrayResponse []codexModelPayload
		if arrayErr := json.Unmarshal(body, &arrayResponse); arrayErr != nil {
			// Last resort: walk arbitrary JSON for objects with id/slug fields.
			return parseCodexModelsLoose(body, now)
		}
		decoded.Data = arrayResponse
	}

	entries := decoded.Data
	if len(entries) == 0 {
		entries = decoded.Models
	}
	if len(entries) == 0 {
		entries = decoded.Items
	}
	if len(entries) == 0 {
		return parseCodexModelsLoose(body, now)
	}

	return codexModelInfosFromPayloads(entries, now)
}

func codexModelInfosFromPayloads(entries []codexModelPayload, now int64) ([]*sdkmodelcatalog.ModelInfo, bool) {
	out := make([]*sdkmodelcatalog.ModelInfo, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, item := range entries {
		// ChatGPT Codex manifest uses slug as the callable model ID; prefer slug over opaque ID.
		modelID := firstNonEmptyString(item.Slug, item.ID, item.Name)
		if modelID == "" {
			continue
		}
		key := strings.ToLower(modelID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		displayName := firstNonEmptyString(item.DisplayName, item.Title, item.Name, modelID)
		object := strings.TrimSpace(item.Object)
		if object == "" {
			object = "model"
		}
		ownedBy := strings.TrimSpace(item.OwnedBy)
		if ownedBy == "" {
			ownedBy = "openai"
		}
		created := item.Created
		if created == 0 {
			created = now
		}
		model := &sdkmodelcatalog.ModelInfo{
			ID:          modelID,
			Object:      object,
			Created:     created,
			OwnedBy:     ownedBy,
			Type:        "codex",
			DisplayName: displayName,
			Name:        modelID,
			Version:     modelID,
		}
		if static := sdkmodelcatalog.LookupStaticModelInfo(modelID); static != nil {
			if strings.TrimSpace(static.Description) != "" {
				model.Description = static.Description
			}
			if strings.TrimSpace(static.DisplayName) != "" {
				model.DisplayName = static.DisplayName
			}
			if static.Thinking != nil {
				thinkingClone := *static.Thinking
				if len(static.Thinking.Levels) > 0 {
					thinkingClone.Levels = append([]string(nil), static.Thinking.Levels...)
				}
				model.Thinking = &thinkingClone
			}
		}
		out = append(out, model)
	}
	return out, len(out) > 0
}

// parseCodexModelsLoose walks nested JSON maps/arrays looking for model-like objects.
// Codex manifests sometimes wrap the list under evolving keys.
func parseCodexModelsLoose(body []byte, now int64) ([]*sdkmodelcatalog.ModelInfo, bool) {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, false
	}
	seen := make(map[string]struct{})
	out := make([]*sdkmodelcatalog.ModelInfo, 0, 16)
	var walk func(v any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			id := firstNonEmptyString(
				stringFromAny(typed["slug"]),
				stringFromAny(typed["id"]),
				stringFromAny(typed["model"]),
				stringFromAny(typed["name"]),
			)
			// Heuristic: model-like object when id looks like a model slug and not a nested container-only map.
			if id != "" && (strings.Contains(id, "-") || strings.HasPrefix(strings.ToLower(id), "gpt") || strings.HasPrefix(strings.ToLower(id), "o")) {
				key := strings.ToLower(id)
				if _, exists := seen[key]; !exists {
					// Skip obvious non-model containers.
					if _, hasModels := typed["models"]; !hasModels {
						if _, hasData := typed["data"]; !hasData {
							seen[key] = struct{}{}
							display := firstNonEmptyString(
								stringFromAny(typed["display_name"]),
								stringFromAny(typed["title"]),
								stringFromAny(typed["name"]),
								id,
							)
							ownedBy := firstNonEmptyString(stringFromAny(typed["owned_by"]), "openai")
							out = append(out, &sdkmodelcatalog.ModelInfo{
								ID:          id,
								Object:      "model",
								Created:     now,
								OwnedBy:     ownedBy,
								Type:        "codex",
								DisplayName: display,
								Name:        id,
								Version:     id,
							})
						}
					}
				}
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(root)
	return out, len(out) > 0
}

func stringFromAny(v any) string {
	switch typed := v.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}
