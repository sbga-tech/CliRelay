package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/access"
	configaccess "github.com/router-for-me/CLIProxyAPI/v6/internal/access/config_access"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	apikeysettings "github.com/router-for-me/CLIProxyAPI/v6/internal/management/settings/apikey"
	providersettings "github.com/router-for-me/CLIProxyAPI/v6/internal/management/settings/providers"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// refreshAPIKeyCache rebuilds the in-memory access provider cache from SQLite.
// Must be called after every API key write operation.
func (h *Handler) refreshAPIKeyCache() {
	if h == nil || h.cfg == nil {
		return
	}
	// Always update the global provider registry (used during config reload and service bootstrap).
	configaccess.Register(&h.cfg.SDKConfig)
	// Also update the live access manager provider snapshot so changes take effect immediately
	// without waiting for a full config reload.
	if h.accessManager != nil {
		_, _ = access.ApplyAccessProviders(h.accessManager, nil, h.cfg)
	}
}

func (h *Handler) apiKeySettings() *apikeysettings.Service {
	if h == nil {
		return apikeysettings.NewService(nil, nil, nil)
	}
	validateEntry := func(entry config.APIKeyEntry) error {
		var auths []*coreauth.Auth
		if h.authManager != nil {
			auths = h.authManager.List()
		}
		routingCfg := config.RoutingConfig{}
		if h.cfg != nil {
			routingCfg = h.cfg.Routing
		}
		return validateRoutingAndAPIKeyRestrictions(&config.Config{
			SDKConfig: config.SDKConfig{
				APIKeyEntries: []config.APIKeyEntry{entry},
			},
			Routing: routingCfg,
		}, auths)
	}
	return apikeysettings.NewService(h.sanitizeAllowedChannelsForSave, h.validateAllowedChannelGroups, validateEntry)
}

func providerSettingsService(h *Handler) *providersettings.Service {
	if h == nil {
		return providersettings.NewService(nil, nil)
	}
	return providersettings.NewService(h.cfg, h.validateChannelNames)
}

// Generic helpers for list[string]
func (h *Handler) putStringList(c *gin.Context, set func([]string), after func()) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []string
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []string `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	set(arr)
	if after != nil {
		after()
	}
	h.persist(c)
}

func (h *Handler) patchStringList(c *gin.Context, target *[]string, after func()) {
	var body struct {
		Old   *string `json:"old"`
		New   *string `json:"new"`
		Index *int    `json:"index"`
		Value *string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if body.Index != nil && body.Value != nil && *body.Index >= 0 && *body.Index < len(*target) {
		(*target)[*body.Index] = *body.Value
		if after != nil {
			after()
		}
		h.persist(c)
		return
	}
	if body.Old != nil && body.New != nil {
		for i := range *target {
			if (*target)[i] == *body.Old {
				(*target)[i] = *body.New
				if after != nil {
					after()
				}
				h.persist(c)
				return
			}
		}
		*target = append(*target, *body.New)
		if after != nil {
			after()
		}
		h.persist(c)
		return
	}
	c.JSON(400, gin.H{"error": "missing fields"})
}

func (h *Handler) deleteFromStringList(c *gin.Context, target *[]string, after func()) {
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		_, err := fmt.Sscanf(idxStr, "%d", &idx)
		if err == nil && idx >= 0 && idx < len(*target) {
			*target = append((*target)[:idx], (*target)[idx+1:]...)
			if after != nil {
				after()
			}
			h.persist(c)
			return
		}
	}
	if val := strings.TrimSpace(c.Query("value")); val != "" {
		out := make([]string, 0, len(*target))
		for _, v := range *target {
			if strings.TrimSpace(v) != val {
				out = append(out, v)
			}
		}
		*target = out
		if after != nil {
			after()
		}
		h.persist(c)
		return
	}
	c.JSON(400, gin.H{"error": "missing index or value"})
}

// api-keys (legacy simple list — now backed by SQLite)
func (h *Handler) GetAPIKeys(c *gin.Context) {
	c.JSON(200, gin.H{"api-keys": h.apiKeySettings().EnabledKeys()})
}
func (h *Handler) PutAPIKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []string
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []string `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := h.apiKeySettings().ReplaceKeys(arr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok"})
}
func (h *Handler) PatchAPIKeys(c *gin.Context) {
	var body struct {
		Old *string `json:"old"`
		New *string `json:"new"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Old == nil || body.New == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := h.apiKeySettings().PatchKey(*body.Old, *body.New); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok"})
}
func (h *Handler) DeleteAPIKeys(c *gin.Context) {
	if err := h.apiKeySettings().DeleteKey(c.Query("value")); err != nil {
		if errors.Is(err, apikeysettings.ErrMissingValue) {
			c.JSON(400, gin.H{"error": "missing value"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok"})
}

func (h *Handler) GetAPIKeyPermissionProfiles(c *gin.Context) {
	profiles := h.apiKeySettings().PermissionProfiles()
	c.JSON(200, gin.H{
		"api-key-permission-profiles": profiles,
		"items":                       profiles,
	})
}

func (h *Handler) PutAPIKeyPermissionProfiles(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}

	var profiles []usage.APIKeyPermissionProfileRow
	if err = json.Unmarshal(data, &profiles); err != nil {
		var obj struct {
			Items []usage.APIKeyPermissionProfileRow `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		profiles = obj.Items
	}

	if err := h.apiKeySettings().ReplacePermissionProfiles(profiles); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok"})
}

// api-key-entries: backed by SQLite api_keys table
func (h *Handler) GetAPIKeyEntries(c *gin.Context) {
	c.JSON(200, gin.H{"api-key-entries": h.apiKeySettings().APIKeyEntries()})
}

func (h *Handler) PutAPIKeyEntries(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.APIKeyEntry
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.APIKeyEntry `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := h.apiKeySettings().ReplaceEntries(arr); err != nil {
		if errors.Is(err, apikeysettings.ErrInvalidEntry) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok"})
}

func (h *Handler) PatchAPIKeyEntry(c *gin.Context) {
	var body struct {
		Index *int                             `json:"index"`
		Match *string                          `json:"match"`
		Value *apikeysettings.APIKeyEntryPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := h.apiKeySettings().PatchEntry(body.Index, body.Match, *body.Value); err != nil {
		switch {
		case errors.Is(err, apikeysettings.ErrItemNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "item not found"})
			return
		case errors.Is(err, apikeysettings.ErrKeyRequired):
			c.JSON(http.StatusBadRequest, gin.H{"error": "key is required"})
			return
		case errors.Is(err, apikeysettings.ErrAPIKeyExists):
			c.JSON(http.StatusConflict, gin.H{"error": "api key already exists"})
			return
		case errors.Is(err, apikeysettings.ErrInvalidEntry):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok"})
}

func (h *Handler) DeleteAPIKeyEntry(c *gin.Context) {
	deleteLogs := shouldDeleteAPIKeyLogs(c)
	var index *int
	if idxStr := c.Query("index"); idxStr != "" {
		parsed, err := strconv.Atoi(idxStr)
		if err == nil {
			index = &parsed
		}
	}
	deletedKey, err := h.apiKeySettings().DeleteEntry(c.Query("key"), index)
	if err != nil {
		if errors.Is(err, apikeysettings.ErrMissingValue) {
			c.JSON(400, gin.H{"error": "missing key or index"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var logsDeleted int64
	if deleteLogs && deletedKey != "" {
		logsDeleted, _ = usage.DeleteLogsByAPIKey(deletedKey)
	}
	h.refreshAPIKeyCache()
	c.JSON(200, gin.H{"status": "ok", "logs_deleted": logsDeleted})
}

func shouldDeleteAPIKeyLogs(c *gin.Context) bool {
	raw := strings.TrimSpace(c.Query("delete_logs"))
	if raw == "" {
		return true
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return true
	}
	return value
}

// gemini-api-key: []GeminiKey
func (h *Handler) GetGeminiKeys(c *gin.Context) {
	c.JSON(200, gin.H{"gemini-api-key": providerSettingsService(h).GeminiKeys()})
}
func (h *Handler) PutGeminiKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.GeminiKey
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.GeminiKey `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := providerSettingsService(h).ReplaceGeminiKeys(arr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}
func (h *Handler) PatchGeminiKey(c *gin.Context) {
	var body struct {
		Index *int                             `json:"index"`
		Match *string                          `json:"match"`
		Value *providersettings.GeminiKeyPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchGeminiKey(body.Index, body.Match, *body.Value); err != nil {
		if errors.Is(err, providersettings.ErrItemNotFound) {
			c.JSON(404, gin.H{"error": "item not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteGeminiKey(c *gin.Context) {
	if val := strings.TrimSpace(c.Query("api-key")); val != "" {
		if providerSettingsService(h).DeleteGeminiKeyByAPIKey(val) {
			h.persist(c)
		} else {
			c.JSON(404, gin.H{"error": "item not found"})
		}
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		if _, err := fmt.Sscanf(idxStr, "%d", &idx); err == nil && providerSettingsService(h).DeleteGeminiKeyByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing api-key or index"})
}

// claude-api-key: []ClaudeKey
func (h *Handler) GetClaudeKeys(c *gin.Context) {
	c.JSON(200, gin.H{"claude-api-key": providerSettingsService(h).ClaudeKeys()})
}
func (h *Handler) PutClaudeKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.ClaudeKey
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.ClaudeKey `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := providerSettingsService(h).ReplaceClaudeKeys(arr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}
func (h *Handler) PatchClaudeKey(c *gin.Context) {
	var body struct {
		Index *int                             `json:"index"`
		Match *string                          `json:"match"`
		Value *providersettings.ClaudeKeyPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchClaudeKey(body.Index, body.Match, *body.Value); err != nil {
		if errors.Is(err, providersettings.ErrItemNotFound) {
			c.JSON(404, gin.H{"error": "item not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteClaudeKey(c *gin.Context) {
	if val := c.Query("api-key"); val != "" {
		providerSettingsService(h).DeleteClaudeKeyByAPIKey(val)
		h.persist(c)
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		_, err := fmt.Sscanf(idxStr, "%d", &idx)
		if err == nil && providerSettingsService(h).DeleteClaudeKeyByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing api-key or index"})
}

// bedrock-api-key: []BedrockKey
func (h *Handler) GetBedrockKeys(c *gin.Context) {
	c.JSON(200, gin.H{"bedrock-api-key": providerSettingsService(h).BedrockKeys()})
}

func (h *Handler) PutBedrockKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.BedrockKey
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.BedrockKey `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := providerSettingsService(h).ReplaceBedrockKeys(arr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) PatchBedrockKey(c *gin.Context) {
	var body struct {
		Index *int                              `json:"index"`
		Match *string                           `json:"match"`
		Value *providersettings.BedrockKeyPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchBedrockKey(body.Index, body.Match, *body.Value); err != nil {
		if errors.Is(err, providersettings.ErrItemNotFound) {
			c.JSON(404, gin.H{"error": "item not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteBedrockKey(c *gin.Context) {
	if val := strings.TrimSpace(c.Query("api-key")); val != "" {
		if providerSettingsService(h).DeleteBedrockKeyByAPIKey(val) {
			h.persist(c)
			return
		}
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}
	if val := strings.TrimSpace(c.Query("access-key-id")); val != "" {
		if providerSettingsService(h).DeleteBedrockKeyByAccessKeyID(val) {
			h.persist(c)
			return
		}
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}
	if val := strings.TrimSpace(c.Query("name")); val != "" {
		if providerSettingsService(h).DeleteBedrockKeyByName(val) {
			h.persist(c)
			return
		}
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		if _, err := fmt.Sscanf(idxStr, "%d", &idx); err == nil && providerSettingsService(h).DeleteBedrockKeyByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing api-key, access-key-id, name, or index"})
}

// opencode-go-api-key: []OpenCodeGoKey
func (h *Handler) GetOpenCodeGoKeys(c *gin.Context) {
	c.JSON(200, gin.H{"opencode-go-api-key": providerSettingsService(h).OpenCodeGoKeys()})
}

func (h *Handler) PutOpenCodeGoKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.OpenCodeGoKey
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.OpenCodeGoKey `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := providerSettingsService(h).ReplaceOpenCodeGoKeys(arr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) PatchOpenCodeGoKey(c *gin.Context) {
	var body struct {
		APIKey *string                           `json:"api-key"`
		Name   *string                           `json:"name"`
		Index  *int                              `json:"index"`
		Value  *providersettings.OpenCodeGoPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchOpenCodeGoKey(body.Index, body.APIKey, body.Name, *body.Value); err != nil {
		if errors.Is(err, providersettings.ErrItemNotFound) {
			c.JSON(404, gin.H{"error": "item not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteOpenCodeGoKey(c *gin.Context) {
	if apiKey := strings.TrimSpace(c.Query("api-key")); apiKey != "" {
		if providerSettingsService(h).DeleteOpenCodeGoKeyByAPIKey(apiKey) {
			h.persist(c)
			return
		}
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}
	if name := strings.TrimSpace(c.Query("name")); name != "" {
		if providerSettingsService(h).DeleteOpenCodeGoKeyByName(name) {
			h.persist(c)
			return
		}
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		if _, err := fmt.Sscanf(idxStr, "%d", &idx); err == nil && providerSettingsService(h).DeleteOpenCodeGoKeyByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing api-key, name, or index"})
}

// openai-compatibility: []OpenAICompatibility
func (h *Handler) GetOpenAICompat(c *gin.Context) {
	c.JSON(200, gin.H{"openai-compatibility": providerSettingsService(h).OpenAICompatibility()})
}
func (h *Handler) PutOpenAICompat(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.OpenAICompatibility
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.OpenAICompatibility `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := providerSettingsService(h).ReplaceOpenAICompatibility(arr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}
func (h *Handler) PatchOpenAICompat(c *gin.Context) {
	var body struct {
		Name  *string                                    `json:"name"`
		Index *int                                       `json:"index"`
		Value *providersettings.OpenAICompatibilityPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchOpenAICompatibility(body.Index, body.Name, *body.Value); err != nil {
		if errors.Is(err, providersettings.ErrItemNotFound) {
			c.JSON(404, gin.H{"error": "item not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteOpenAICompat(c *gin.Context) {
	if name := c.Query("name"); name != "" {
		providerSettingsService(h).DeleteOpenAICompatibilityByName(name)
		h.persist(c)
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		_, err := fmt.Sscanf(idxStr, "%d", &idx)
		if err == nil && providerSettingsService(h).DeleteOpenAICompatibilityByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing name or index"})
}

// vertex-api-key: []VertexCompatKey
func (h *Handler) GetVertexCompatKeys(c *gin.Context) {
	c.JSON(200, gin.H{"vertex-api-key": providerSettingsService(h).VertexCompatKeys()})
}
func (h *Handler) PutVertexCompatKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.VertexCompatKey
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.VertexCompatKey `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	providerSettingsService(h).ReplaceVertexCompatKeys(arr)
	h.persist(c)
}
func (h *Handler) PatchVertexCompatKey(c *gin.Context) {
	var body struct {
		Index *int                                `json:"index"`
		Match *string                             `json:"match"`
		Value *providersettings.VertexCompatPatch `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchVertexCompatKey(body.Index, body.Match, *body.Value); err != nil {
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteVertexCompatKey(c *gin.Context) {
	if val := strings.TrimSpace(c.Query("api-key")); val != "" {
		providerSettingsService(h).DeleteVertexCompatKeyByAPIKey(val)
		h.persist(c)
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		_, errScan := fmt.Sscanf(idxStr, "%d", &idx)
		if errScan == nil && providerSettingsService(h).DeleteVertexCompatKeyByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing api-key or index"})
}

// codex-api-key: []CodexKey
func (h *Handler) GetCodexKeys(c *gin.Context) {
	c.JSON(200, gin.H{"codex-api-key": providerSettingsService(h).CodexKeys()})
}
func (h *Handler) PutCodexKeys(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.CodexKey
	if err = json.Unmarshal(data, &arr); err != nil {
		var obj struct {
			Items []config.CodexKey `json:"items"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil || len(obj.Items) == 0 {
			c.JSON(400, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}
	if err := providerSettingsService(h).ReplaceCodexKeys(arr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}
func (h *Handler) PatchCodexKey(c *gin.Context) {
	var body struct {
		Index *int                            `json:"index"`
		Match *string                         `json:"match"`
		Value *providersettings.CodexKeyPatch `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := providerSettingsService(h).PatchCodexKey(body.Index, body.Match, *body.Value); err != nil {
		if errors.Is(err, providersettings.ErrItemNotFound) {
			c.JSON(404, gin.H{"error": "item not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.persist(c)
}

func (h *Handler) DeleteCodexKey(c *gin.Context) {
	if val := c.Query("api-key"); val != "" {
		providerSettingsService(h).DeleteCodexKeyByAPIKey(val)
		h.persist(c)
		return
	}
	if idxStr := c.Query("index"); idxStr != "" {
		var idx int
		_, err := fmt.Sscanf(idxStr, "%d", &idx)
		if err == nil && providerSettingsService(h).DeleteCodexKeyByIndex(idx) {
			h.persist(c)
			return
		}
	}
	c.JSON(400, gin.H{"error": "missing api-key or index"})
}
