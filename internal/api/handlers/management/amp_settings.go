package management

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	ampsettings "github.com/router-for-me/CLIProxyAPI/v6/internal/management/settings/amp"
)

func ampSettingsService(h *Handler) *ampsettings.Service {
	if h == nil {
		return ampsettings.NewService(nil)
	}
	return ampsettings.NewService(h.cfg)
}

// GetAmpCode returns the complete ampcode configuration.
func (h *Handler) GetAmpCode(c *gin.Context) {
	c.JSON(200, gin.H{"ampcode": ampSettingsService(h).Snapshot()})
}

// GetAmpUpstreamURL returns the ampcode upstream URL.
func (h *Handler) GetAmpUpstreamURL(c *gin.Context) {
	c.JSON(200, gin.H{"upstream-url": ampSettingsService(h).UpstreamURL()})
}

// PutAmpUpstreamURL updates the ampcode upstream URL.
func (h *Handler) PutAmpUpstreamURL(c *gin.Context) {
	h.updateStringField(c, func(v string) { ampSettingsService(h).SetUpstreamURL(v) })
}

// DeleteAmpUpstreamURL clears the ampcode upstream URL.
func (h *Handler) DeleteAmpUpstreamURL(c *gin.Context) {
	ampSettingsService(h).ClearUpstreamURL()
	h.persist(c)
}

// GetAmpUpstreamAPIKey returns the ampcode upstream API key.
func (h *Handler) GetAmpUpstreamAPIKey(c *gin.Context) {
	c.JSON(200, gin.H{"upstream-api-key": ampSettingsService(h).UpstreamAPIKey()})
}

// PutAmpUpstreamAPIKey updates the ampcode upstream API key.
func (h *Handler) PutAmpUpstreamAPIKey(c *gin.Context) {
	h.updateStringField(c, func(v string) { ampSettingsService(h).SetUpstreamAPIKey(v) })
}

// DeleteAmpUpstreamAPIKey clears the ampcode upstream API key.
func (h *Handler) DeleteAmpUpstreamAPIKey(c *gin.Context) {
	ampSettingsService(h).ClearUpstreamAPIKey()
	h.persist(c)
}

// GetAmpRestrictManagementToLocalhost returns the localhost restriction setting.
func (h *Handler) GetAmpRestrictManagementToLocalhost(c *gin.Context) {
	c.JSON(200, gin.H{"restrict-management-to-localhost": ampSettingsService(h).RestrictManagementToLocalhost()})
}

// PutAmpRestrictManagementToLocalhost updates the localhost restriction setting.
func (h *Handler) PutAmpRestrictManagementToLocalhost(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { ampSettingsService(h).SetRestrictManagementToLocalhost(v) })
}

// GetAmpModelMappings returns the ampcode model mappings.
func (h *Handler) GetAmpModelMappings(c *gin.Context) {
	c.JSON(200, gin.H{"model-mappings": ampSettingsService(h).ModelMappings()})
}

// PutAmpModelMappings replaces all ampcode model mappings.
func (h *Handler) PutAmpModelMappings(c *gin.Context) {
	var body struct {
		Value []config.AmpModelMapping `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	ampSettingsService(h).SetModelMappings(body.Value)
	h.persist(c)
}

// PatchAmpModelMappings adds or updates model mappings.
func (h *Handler) PatchAmpModelMappings(c *gin.Context) {
	var body struct {
		Value []config.AmpModelMapping `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}

	ampSettingsService(h).PatchModelMappings(body.Value)
	h.persist(c)
}

// DeleteAmpModelMappings removes specified model mappings by "from" field.
func (h *Handler) DeleteAmpModelMappings(c *gin.Context) {
	var body struct {
		Value []string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Value) == 0 {
		ampSettingsService(h).DeleteModelMappings(nil)
		h.persist(c)
		return
	}

	ampSettingsService(h).DeleteModelMappings(body.Value)
	h.persist(c)
}

// GetAmpForceModelMappings returns whether model mappings are forced.
func (h *Handler) GetAmpForceModelMappings(c *gin.Context) {
	c.JSON(200, gin.H{"force-model-mappings": ampSettingsService(h).ForceModelMappings()})
}

// PutAmpForceModelMappings updates the force model mappings setting.
func (h *Handler) PutAmpForceModelMappings(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { ampSettingsService(h).SetForceModelMappings(v) })
}

// GetAmpUpstreamAPIKeys returns the ampcode upstream API keys mapping.
func (h *Handler) GetAmpUpstreamAPIKeys(c *gin.Context) {
	c.JSON(200, gin.H{"upstream-api-keys": ampSettingsService(h).UpstreamAPIKeys()})
}

// PutAmpUpstreamAPIKeys replaces all ampcode upstream API keys mappings.
func (h *Handler) PutAmpUpstreamAPIKeys(c *gin.Context) {
	var body struct {
		Value []config.AmpUpstreamAPIKeyEntry `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	ampSettingsService(h).SetUpstreamAPIKeys(body.Value)
	h.persist(c)
}

// PatchAmpUpstreamAPIKeys adds or updates upstream API keys entries.
// Matching is done by upstream-api-key value.
func (h *Handler) PatchAmpUpstreamAPIKeys(c *gin.Context) {
	var body struct {
		Value []config.AmpUpstreamAPIKeyEntry `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}

	ampSettingsService(h).PatchUpstreamAPIKeys(body.Value)
	h.persist(c)
}

// DeleteAmpUpstreamAPIKeys removes specified upstream API keys entries.
// Body must be JSON: {"value": ["<upstream-api-key>", ...]}.
// If "value" is an empty array, clears all entries.
// If JSON is invalid or "value" is missing/null, returns 400 and does not persist any change.
func (h *Handler) DeleteAmpUpstreamAPIKeys(c *gin.Context) {
	var body struct {
		Value []string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}

	if body.Value == nil {
		c.JSON(400, gin.H{"error": "missing value"})
		return
	}

	if len(body.Value) == 0 {
		_ = ampSettingsService(h).DeleteUpstreamAPIKeys(body.Value)
		h.persist(c)
		return
	}

	if err := ampSettingsService(h).DeleteUpstreamAPIKeys(body.Value); err != nil {
		c.JSON(400, gin.H{"error": "empty value"})
		return
	}
	h.persist(c)
}
