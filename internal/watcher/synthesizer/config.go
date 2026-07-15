package synthesizer

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/diff"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// ConfigSynthesizer generates Auth entries from configuration API keys.
// It handles Gemini, Claude, Bedrock, Codex, OpenCode Go, Cline, Ollama Cloud, OpenAI-compat, and Vertex-compat providers.
type ConfigSynthesizer struct{}

// ConfigProviderKind identifies a saved provider configuration that can be
// materialized without registering an auth record.
type ConfigProviderKind string

const (
	ConfigProviderKindGemini              ConfigProviderKind = "gemini"
	ConfigProviderKindClaude              ConfigProviderKind = "claude"
	ConfigProviderKindCodex               ConfigProviderKind = "codex"
	ConfigProviderKindVertex              ConfigProviderKind = "vertex"
	ConfigProviderKindBedrock             ConfigProviderKind = "bedrock"
	ConfigProviderKindOpenAICompatibility ConfigProviderKind = "openai-compatibility"
)

// StableIdentity describes the existing deterministic ID and source-label
// inputs for a config-derived auth. It does not allocate an ID itself.
type StableIdentity struct {
	Kind        string
	Parts       []string
	SourceLabel string
}

// BuildConfigProviderAuthSkeleton materializes immutable saved-provider data
// without assigning a runtime identity or state. The selected OpenAI-compatible
// provider uses its first non-empty API key entry even when that row is disabled.
func BuildConfigProviderAuthSkeleton(cfg *config.Config, tenantID string, kind ConfigProviderKind, index int) (*coreauth.Auth, StableIdentity, error) {
	if cfg == nil {
		return nil, StableIdentity{}, fmt.Errorf("config is required")
	}
	if index < 0 {
		return nil, StableIdentity{}, fmt.Errorf("provider index must be non-negative")
	}

	switch kind {
	case ConfigProviderKindGemini:
		if index >= len(cfg.GeminiKey) {
			return nil, StableIdentity{}, fmt.Errorf("provider not found")
		}
		entry := cfg.GeminiKey[index]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		attrs := map[string]string{}
		if key != "" {
			attrs["api_key"] = key
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if base != "" {
			attrs["base_url"] = base
		}
		if hash := diff.ComputeGeminiModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "gemini-apikey"
		}
		return &coreauth.Auth{
				TenantID:   tenantID,
				Provider:   "gemini",
				Label:      label,
				Prefix:     strings.TrimSpace(entry.Prefix),
				ProxyURL:   strings.TrimSpace(entry.ProxyURL),
				ProxyID:    strings.TrimSpace(entry.ProxyID),
				Attributes: attrs,
			}, StableIdentity{
				Kind:        "gemini:apikey",
				Parts:       []string{key, base},
				SourceLabel: "config:gemini",
			}, nil

	case ConfigProviderKindClaude:
		if index >= len(cfg.ClaudeKey) {
			return nil, StableIdentity{}, fmt.Errorf("provider not found")
		}
		entry := cfg.ClaudeKey[index]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		attrs := map[string]string{}
		if key != "" {
			attrs["api_key"] = key
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if base != "" {
			attrs["base_url"] = base
		}
		if hash := diff.ComputeClaudeModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		if entry.SkipAnthropicProcessing {
			attrs["skip_anthropic_processing"] = "true"
		}
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "claude-apikey"
		}
		return &coreauth.Auth{
				TenantID:   tenantID,
				Provider:   "claude",
				Label:      label,
				Prefix:     strings.TrimSpace(entry.Prefix),
				ProxyURL:   strings.TrimSpace(entry.ProxyURL),
				ProxyID:    strings.TrimSpace(entry.ProxyID),
				Attributes: attrs,
			}, StableIdentity{
				Kind:        "claude:apikey",
				Parts:       []string{key, base},
				SourceLabel: "config:claude",
			}, nil

	case ConfigProviderKindCodex:
		if index >= len(cfg.CodexKey) {
			return nil, StableIdentity{}, fmt.Errorf("provider not found")
		}
		entry := cfg.CodexKey[index]
		key := strings.TrimSpace(entry.APIKey)
		base := entry.BaseURL
		attrs := map[string]string{}
		if key != "" {
			attrs["api_key"] = key
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if base != "" {
			attrs["base_url"] = base
		}
		if entry.Websockets {
			attrs["websockets"] = "true"
		}
		if hash := diff.ComputeCodexModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "codex-apikey"
		}
		return &coreauth.Auth{
				TenantID:   tenantID,
				Provider:   "codex",
				Label:      label,
				Prefix:     strings.TrimSpace(entry.Prefix),
				ProxyURL:   strings.TrimSpace(entry.ProxyURL),
				ProxyID:    strings.TrimSpace(entry.ProxyID),
				Attributes: attrs,
			}, StableIdentity{
				Kind:        "codex:apikey",
				Parts:       []string{key, base},
				SourceLabel: "config:codex",
			}, nil

	case ConfigProviderKindVertex:
		if index >= len(cfg.VertexCompatAPIKey) {
			return nil, StableIdentity{}, fmt.Errorf("provider not found")
		}
		entry := cfg.VertexCompatAPIKey[index]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		attrs := map[string]string{
			"base_url":     base,
			"provider_key": "vertex",
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if key != "" {
			attrs["api_key"] = key
		}
		if hash := diff.ComputeVertexCompatModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		return &coreauth.Auth{
				TenantID:   tenantID,
				Provider:   "vertex",
				Label:      "vertex-apikey",
				Prefix:     strings.TrimSpace(entry.Prefix),
				ProxyURL:   proxyURL,
				ProxyID:    strings.TrimSpace(entry.ProxyID),
				Attributes: attrs,
			}, StableIdentity{
				Kind:        "vertex:apikey",
				Parts:       []string{key, base, proxyURL},
				SourceLabel: "config:vertex-apikey",
			}, nil

	case ConfigProviderKindBedrock:
		if index >= len(cfg.BedrockKey) {
			return nil, StableIdentity{}, fmt.Errorf("provider not found")
		}
		entry := cfg.BedrockKey[index]
		authMode := strings.ToLower(strings.TrimSpace(entry.AuthMode))
		switch authMode {
		case "apikey", "api_key", "api-key":
			authMode = "api-key"
		default:
			authMode = "sigv4"
		}
		region := strings.TrimSpace(entry.Region)
		if region == "" {
			region = "us-east-1"
		}
		base := strings.TrimSpace(entry.BaseURL)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		attrs := map[string]string{
			"auth_mode": authMode,
			"region":    region,
		}
		identity := StableIdentity{
			Kind:        "bedrock:apikey",
			Parts:       []string{authMode, region, base, proxyURL},
			SourceLabel: "config:bedrock",
		}
		switch authMode {
		case "api-key":
			if key := strings.TrimSpace(entry.APIKey); key != "" {
				attrs["api_key"] = key
				identity.Parts = append(identity.Parts, key)
			}
		default:
			accessKeyID := strings.TrimSpace(entry.AccessKeyID)
			secretAccessKey := strings.TrimSpace(entry.SecretAccessKey)
			sessionToken := strings.TrimSpace(entry.SessionToken)
			if accessKeyID != "" {
				attrs["api_key"] = accessKeyID
				attrs["access_key_id"] = accessKeyID
			}
			if secretAccessKey != "" {
				attrs["secret_access_key"] = secretAccessKey
			}
			if sessionToken != "" {
				attrs["session_token"] = sessionToken
			}
			identity.Parts = append(identity.Parts, accessKeyID, secretAccessKey, sessionToken)
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if base != "" {
			attrs["base_url"] = base
		}
		if entry.ForceGlobal {
			attrs["force_global"] = "true"
		}
		if hash := diff.ComputeBedrockModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "bedrock-apikey"
		}
		return &coreauth.Auth{
			TenantID:   tenantID,
			Provider:   "bedrock",
			Label:      label,
			Prefix:     strings.TrimSpace(entry.Prefix),
			ProxyURL:   proxyURL,
			ProxyID:    strings.TrimSpace(entry.ProxyID),
			Attributes: attrs,
		}, identity, nil

	case ConfigProviderKindOpenAICompatibility:
		if index >= len(cfg.OpenAICompatibility) {
			return nil, StableIdentity{}, fmt.Errorf("provider not found")
		}
		return buildOpenAICompatibilityAuthSkeleton(cfg, tenantID, index, firstNonEmptyOpenAICompatibilityKey(cfg.OpenAICompatibility[index]))
	default:
		return nil, StableIdentity{}, fmt.Errorf("unsupported config provider kind %q", kind)
	}
}

func firstNonEmptyOpenAICompatibilityKey(compat config.OpenAICompatibility) *int {
	for index := range compat.APIKeyEntries {
		if strings.TrimSpace(compat.APIKeyEntries[index].APIKey) != "" {
			return &index
		}
	}
	return nil
}

func buildOpenAICompatibilityAuthSkeleton(cfg *config.Config, tenantID string, providerIndex int, keyIndex *int) (*coreauth.Auth, StableIdentity, error) {
	if cfg == nil || providerIndex < 0 || providerIndex >= len(cfg.OpenAICompatibility) {
		return nil, StableIdentity{}, fmt.Errorf("provider not found")
	}
	compat := cfg.OpenAICompatibility[providerIndex]
	if keyIndex != nil && (*keyIndex < 0 || *keyIndex >= len(compat.APIKeyEntries)) {
		return nil, StableIdentity{}, fmt.Errorf("provider key not found")
	}
	providerName := strings.ToLower(strings.TrimSpace(compat.Name))
	if providerName == "" {
		providerName = "openai-compatibility"
	}
	base := strings.TrimSpace(compat.BaseURL)
	attrs := map[string]string{
		"base_url":     base,
		"compat_name":  compat.Name,
		"provider_key": providerName,
	}
	if compat.Priority != 0 {
		attrs["priority"] = strconv.Itoa(compat.Priority)
	}
	if hash := diff.ComputeOpenAICompatModelsHash(compat.Models); hash != "" {
		attrs["models_hash"] = hash
	}
	addConfigHeadersToAttrs(compat.Headers, attrs)
	identity := StableIdentity{
		Kind:        fmt.Sprintf("openai-compatibility:%s", providerName),
		Parts:       []string{base},
		SourceLabel: fmt.Sprintf("config:%s", providerName),
	}
	auth := &coreauth.Auth{
		TenantID:   tenantID,
		Provider:   providerName,
		Label:      compat.Name,
		Prefix:     strings.TrimSpace(compat.Prefix),
		Attributes: attrs,
	}
	if keyIndex == nil {
		return auth, identity, nil
	}
	entry := compat.APIKeyEntries[*keyIndex]
	key := strings.TrimSpace(entry.APIKey)
	proxyURL := strings.TrimSpace(entry.ProxyURL)
	if key != "" {
		attrs["api_key"] = key
	}
	auth.ProxyURL = proxyURL
	auth.ProxyID = strings.TrimSpace(entry.ProxyID)
	identity.Parts = []string{key, base, proxyURL}
	return auth, identity, nil
}

func applyConfigProviderAuthSynthesis(auth *coreauth.Auth, identity StableIdentity, now time.Time, idGen *StableIDGenerator) {
	if auth == nil {
		return
	}
	id, token := idGen.Next(identity.Kind, identity.Parts...)
	auth.ID = id
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["source"] = fmt.Sprintf("%s[%s]", identity.SourceLabel, token)
	auth.Status = coreauth.StatusActive
	auth.CreatedAt = now
	auth.UpdatedAt = now
}

// NewConfigSynthesizer creates a new ConfigSynthesizer instance.
func NewConfigSynthesizer() *ConfigSynthesizer {
	return &ConfigSynthesizer{}
}

// Synthesize generates Auth entries from config API keys.
func (s *ConfigSynthesizer) Synthesize(ctx *SynthesisContext) ([]*coreauth.Auth, error) {
	out := make([]*coreauth.Auth, 0, 32)
	if ctx == nil || ctx.Config == nil {
		return out, nil
	}

	// Gemini API Keys
	out = append(out, s.synthesizeGeminiKeys(ctx)...)
	// Claude API Keys
	out = append(out, s.synthesizeClaudeKeys(ctx)...)
	// AWS Bedrock Runtime credentials
	out = append(out, s.synthesizeBedrockKeys(ctx)...)
	// Codex API Keys
	out = append(out, s.synthesizeCodexKeys(ctx)...)
	// OpenCode Go API Keys
	out = append(out, s.synthesizeOpenCodeGoKeys(ctx)...)
	// Cline API Keys
	out = append(out, s.synthesizeClineKeys(ctx)...)
	// Ollama Cloud API Keys
	out = append(out, s.synthesizeOllamaCloudKeys(ctx)...)
	// OpenAI-compat
	out = append(out, s.synthesizeOpenAICompat(ctx)...)
	// Vertex-compat
	out = append(out, s.synthesizeVertexCompat(ctx)...)

	return out, nil
}

// synthesizeGeminiKeys creates Auth entries for Gemini API keys.
func (s *ConfigSynthesizer) synthesizeGeminiKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	out := make([]*coreauth.Auth, 0, len(cfg.GeminiKey))
	for index := range cfg.GeminiKey {
		entry := cfg.GeminiKey[index]
		if strings.TrimSpace(entry.APIKey) == "" {
			continue
		}
		auth, identity, err := BuildConfigProviderAuthSkeleton(cfg, "", ConfigProviderKindGemini, index)
		if err != nil {
			continue
		}
		applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
		ApplyAuthExcludedModelsMeta(auth, cfg, entry.ExcludedModels, "apikey")
		ApplyDisableAllModelsState(auth, entry.ExcludedModels)
		out = append(out, auth)
	}
	return out
}

// synthesizeClaudeKeys creates Auth entries for Claude API keys.
func (s *ConfigSynthesizer) synthesizeClaudeKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	out := make([]*coreauth.Auth, 0, len(cfg.ClaudeKey))
	for index := range cfg.ClaudeKey {
		entry := cfg.ClaudeKey[index]
		if strings.TrimSpace(entry.APIKey) == "" {
			continue
		}
		auth, identity, err := BuildConfigProviderAuthSkeleton(cfg, "", ConfigProviderKindClaude, index)
		if err != nil {
			continue
		}
		applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
		ApplyAuthExcludedModelsMeta(auth, cfg, entry.ExcludedModels, "apikey")
		ApplyDisableAllModelsState(auth, entry.ExcludedModels)
		out = append(out, auth)
	}
	return out
}

// synthesizeBedrockKeys creates Auth entries for AWS Bedrock Runtime credentials.
func (s *ConfigSynthesizer) synthesizeBedrockKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	out := make([]*coreauth.Auth, 0, len(cfg.BedrockKey))
	for index := range cfg.BedrockKey {
		entry := cfg.BedrockKey[index]
		authMode := strings.ToLower(strings.TrimSpace(entry.AuthMode))
		switch authMode {
		case "apikey", "api_key", "api-key":
			if strings.TrimSpace(entry.APIKey) == "" {
				continue
			}
		default:
			if strings.TrimSpace(entry.AccessKeyID) == "" || strings.TrimSpace(entry.SecretAccessKey) == "" {
				continue
			}
		}
		auth, identity, err := BuildConfigProviderAuthSkeleton(cfg, "", ConfigProviderKindBedrock, index)
		if err != nil {
			continue
		}
		applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
		ApplyAuthExcludedModelsMeta(auth, cfg, entry.ExcludedModels, "apikey")
		ApplyDisableAllModelsState(auth, entry.ExcludedModels)
		out = append(out, auth)
	}
	return out
}

// synthesizeCodexKeys creates Auth entries for Codex API keys.
func (s *ConfigSynthesizer) synthesizeCodexKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	out := make([]*coreauth.Auth, 0, len(cfg.CodexKey))
	for index := range cfg.CodexKey {
		entry := cfg.CodexKey[index]
		if strings.TrimSpace(entry.APIKey) == "" {
			continue
		}
		auth, identity, err := BuildConfigProviderAuthSkeleton(cfg, "", ConfigProviderKindCodex, index)
		if err != nil {
			continue
		}
		applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
		ApplyAuthExcludedModelsMeta(auth, cfg, entry.ExcludedModels, "apikey")
		ApplyDisableAllModelsState(auth, entry.ExcludedModels)
		out = append(out, auth)
	}
	return out
}

// synthesizeOpenCodeGoKeys creates Auth entries for OpenCode Go API keys.
func (s *ConfigSynthesizer) synthesizeOpenCodeGoKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.OpenCodeGoKey))
	for i := range cfg.OpenCodeGoKey {
		entry := cfg.OpenCodeGoKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		prefix := strings.TrimSpace(entry.Prefix)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		proxyID := strings.TrimSpace(entry.ProxyID)
		id, token := idGen.Next("opencode-go:apikey", key, proxyURL)
		attrs := map[string]string{
			"source":  fmt.Sprintf("config:opencode-go[%s]", token),
			"api_key": key,
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if hash := diff.ComputeOpenCodeGoModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		if visionFallbackModel := strings.TrimSpace(entry.VisionFallbackModel); visionFallbackModel != "" {
			attrs["vision_fallback_model"] = visionFallbackModel
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "opencode-go-apikey"
		}
		a := &coreauth.Auth{
			ID:         id,
			Provider:   "opencode-go",
			Label:      label,
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   proxyURL,
			ProxyID:    proxyID,
			Attributes: attrs,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		ApplyConfigDisabledState(a, entry.Disabled)
		out = append(out, a)
	}
	return out
}

// synthesizeClineKeys creates Auth entries for ClinePass API keys.
func (s *ConfigSynthesizer) synthesizeClineKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.ClineKey))
	for i := range cfg.ClineKey {
		entry := cfg.ClineKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		prefix := strings.TrimSpace(entry.Prefix)
		base := strings.TrimSpace(entry.BaseURL)
		if base == "" {
			base = config.DefaultClineBaseURL
		}
		base = strings.TrimSuffix(base, "/")
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		proxyID := strings.TrimSpace(entry.ProxyID)
		id, token := idGen.Next("cline:apikey", key, base, proxyURL)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:cline[%s]", token),
			"api_key":      key,
			"base_url":     base,
			"compat_name":  "ClinePass",
			"provider_key": "cline",
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if hash := diff.ComputeClineModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		if visionFallbackModel := strings.TrimSpace(entry.VisionFallbackModel); visionFallbackModel != "" {
			attrs["vision_fallback_model"] = visionFallbackModel
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "cline-apikey"
		}
		a := &coreauth.Auth{
			ID:         id,
			Provider:   "cline",
			Label:      label,
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   proxyURL,
			ProxyID:    proxyID,
			Attributes: attrs,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		ApplyConfigDisabledState(a, entry.Disabled)
		out = append(out, a)
	}
	return out
}

// synthesizeOllamaCloudKeys creates Auth entries for Ollama Cloud API keys.
func (s *ConfigSynthesizer) synthesizeOllamaCloudKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.OllamaCloudKey))
	for i := range cfg.OllamaCloudKey {
		entry := cfg.OllamaCloudKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		prefix := strings.TrimSpace(entry.Prefix)
		base := strings.TrimSpace(entry.BaseURL)
		if base == "" {
			base = config.DefaultOllamaCloudBaseURL
		}
		base = strings.TrimSuffix(base, "/")
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		proxyID := strings.TrimSpace(entry.ProxyID)
		id, token := idGen.Next("ollama-cloud:apikey", key, base, proxyURL)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:ollama-cloud[%s]", token),
			"api_key":      key,
			"base_url":     base,
			"compat_name":  "Ollama Cloud",
			"provider_key": "ollama-cloud",
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		if hash := diff.ComputeOllamaCloudModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		if visionFallbackModel := strings.TrimSpace(entry.VisionFallbackModel); visionFallbackModel != "" {
			attrs["vision_fallback_model"] = visionFallbackModel
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = "ollama-cloud-apikey"
		}
		a := &coreauth.Auth{
			ID:         id,
			Provider:   "ollama-cloud",
			Label:      label,
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   proxyURL,
			ProxyID:    proxyID,
			Attributes: attrs,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		ApplyConfigDisabledState(a, entry.Disabled)
		out = append(out, a)
	}
	return out
}

// synthesizeOpenAICompat creates Auth entries for OpenAI-compatible providers.
func (s *ConfigSynthesizer) synthesizeOpenAICompat(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	out := make([]*coreauth.Auth, 0)
	for providerIndex := range cfg.OpenAICompatibility {
		compat := cfg.OpenAICompatibility[providerIndex]
		if compat.Disabled {
			continue
		}
		if len(compat.APIKeyEntries) == 0 {
			auth, identity, err := buildOpenAICompatibilityAuthSkeleton(cfg, "", providerIndex, nil)
			if err != nil {
				continue
			}
			applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
			out = append(out, auth)
			continue
		}
		for keyIndex := range compat.APIKeyEntries {
			if compat.APIKeyEntries[keyIndex].Disabled {
				continue
			}
			selectedKeyIndex := keyIndex
			auth, identity, err := buildOpenAICompatibilityAuthSkeleton(cfg, "", providerIndex, &selectedKeyIndex)
			if err != nil {
				continue
			}
			applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
			out = append(out, auth)
		}
	}
	return out
}

// synthesizeVertexCompat creates Auth entries for Vertex-compatible providers.
func (s *ConfigSynthesizer) synthesizeVertexCompat(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	out := make([]*coreauth.Auth, 0, len(cfg.VertexCompatAPIKey))
	for index := range cfg.VertexCompatAPIKey {
		auth, identity, err := BuildConfigProviderAuthSkeleton(cfg, "", ConfigProviderKindVertex, index)
		if err != nil {
			continue
		}
		applyConfigProviderAuthSynthesis(auth, identity, ctx.Now, ctx.IDGenerator)
		ApplyAuthExcludedModelsMeta(auth, cfg, nil, "apikey")
		out = append(out, auth)
	}
	return out
}
