package management

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/management/providerprobes"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/synthesizer"
)

type providerProbeRequest struct {
	Index *int `json:"index"`
}

// CheckGeminiProvider checks the saved Gemini provider selected by its
// zero-based configuration index.
func (h *Handler) CheckGeminiProvider(c *gin.Context) {
	h.checkProviderConnection(c, synthesizer.ConfigProviderKindGemini)
}

// CheckClaudeProvider checks the saved Claude provider selected by its
// zero-based configuration index.
func (h *Handler) CheckClaudeProvider(c *gin.Context) {
	h.checkProviderConnection(c, synthesizer.ConfigProviderKindClaude)
}

// CheckCodexProvider checks the saved Codex provider selected by its
// zero-based configuration index.
func (h *Handler) CheckCodexProvider(c *gin.Context) {
	h.checkProviderConnection(c, synthesizer.ConfigProviderKindCodex)
}

// CheckVertexProvider checks the saved Vertex-compatible provider selected by
// its zero-based configuration index.
func (h *Handler) CheckVertexProvider(c *gin.Context) {
	h.checkProviderConnection(c, synthesizer.ConfigProviderKindVertex)
}

// CheckBedrockProvider checks the saved Bedrock provider selected by its
// zero-based configuration index.
func (h *Handler) CheckBedrockProvider(c *gin.Context) {
	h.checkProviderConnection(c, synthesizer.ConfigProviderKindBedrock)
}

// DiscoverClaudeProviderModels discovers models from a saved Claude provider.
func (h *Handler) DiscoverClaudeProviderModels(c *gin.Context) {
	h.discoverProviderModels(c, synthesizer.ConfigProviderKindClaude)
}

// DiscoverCodexProviderModels discovers models from a saved Codex provider.
func (h *Handler) DiscoverCodexProviderModels(c *gin.Context) {
	h.discoverProviderModels(c, synthesizer.ConfigProviderKindCodex)
}

// DiscoverOpenAICompatibilityModels discovers models from a saved
// OpenAI-compatible provider.
func (h *Handler) DiscoverOpenAICompatibilityModels(c *gin.Context) {
	h.discoverProviderModels(c, synthesizer.ConfigProviderKindOpenAICompatibility)
}

func (h *Handler) checkProviderConnection(c *gin.Context, kind synthesizer.ConfigProviderKind) {
	index, ok := providerProbeRequestIndex(c)
	if !ok {
		return
	}

	service := providerprobes.NewForTenant(h.providerConfigForTenant(c), effectiveTenantID(c))
	result, err := service.Check(c.Request.Context(), kind, index)
	if err != nil {
		h.writeProviderProbeError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *Handler) discoverProviderModels(c *gin.Context, kind synthesizer.ConfigProviderKind) {
	index, ok := providerModelsQueryIndex(c)
	if !ok {
		return
	}

	service := providerprobes.NewForTenant(h.providerConfigForTenant(c), effectiveTenantID(c))
	result, err := service.DiscoverModels(c.Request.Context(), kind, index)
	if err != nil {
		h.writeProviderProbeError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func providerProbeRequestIndex(c *gin.Context) (int, bool) {
	var body providerProbeRequest
	if err := c.ShouldBindJSON(&body); err != nil || body.Index == nil || *body.Index < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
		return 0, false
	}
	return *body.Index, true
}

func providerModelsQueryIndex(c *gin.Context) (int, bool) {
	index, err := strconv.Atoi(strings.TrimSpace(c.Query("index")))
	if err != nil || index < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
		return 0, false
	}
	return index, true
}

func (h *Handler) writeProviderProbeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, providerprobes.ErrInvalidIndex):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
	case errors.Is(err, providerprobes.ErrProviderNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
	case errors.Is(err, providerprobes.ErrProviderBaseURLRequired):
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider base_url is required"})
	case errors.Is(err, providerprobes.ErrProviderCredentialRequired):
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider credential is required"})
	default:
		// Strict discovery and provider skeleton failures deliberately do not expose
		// upstream details, headers, or response bodies.
		c.JSON(http.StatusBadGateway, gin.H{"error": "model discovery failed"})
	}
}
