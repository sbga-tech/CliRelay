package management

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/management/authfilequota"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
)

type codexResetCreditConsumeRequest struct {
	AuthIndex string `json:"auth_index"`
}

// GetAuthFileQuota returns normalized quota presentation data for one auth file
// belonging to the effective tenant.
func (h *Handler) GetAuthFileQuota(c *gin.Context) {
	authIndex := strings.TrimSpace(c.Query("auth_index"))
	if authIndex == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_index is required"})
		return
	}
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}

	result, err := h.authFileQuotaServiceForTenant(effectiveTenantID(c)).Fetch(c.Request.Context(), authIndex)
	if err != nil {
		h.writeAuthFileQuotaError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// ConsumeCodexResetCredit consumes one Codex reset credit for the effective
// tenant's selected auth file. The server owns the target, credential and
// redeem request identifier.
func (h *Handler) ConsumeCodexResetCredit(c *gin.Context) {
	var body codexResetCreditConsumeRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	body.AuthIndex = strings.TrimSpace(body.AuthIndex)
	if body.AuthIndex == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_index is required"})
		return
	}
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}

	if err := h.authFileQuotaServiceForTenant(effectiveTenantID(c)).ConsumeCodexResetCredit(c.Request.Context(), body.AuthIndex); err != nil {
		h.writeAuthFileQuotaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) authFileQuotaServiceForTenant(tenantID string) *authfilequota.Service {
	if h == nil {
		return authfilequota.NewForTenant(tenantID, nil, nil, authfilequota.Dependencies{})
	}
	cfg := usage.BuildTenantRuntimeConfig(h.cfg, tenantID)
	return authfilequota.NewForTenant(tenantID, &cfg, h.authManager, h.authFileQuotaDependencies)
}

func (h *Handler) writeAuthFileQuotaError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, authfilequota.ErrAuthManagerUnavailable):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
	case errors.Is(err, authfilequota.ErrAuthNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
	case errors.Is(err, authfilequota.ErrUnsupportedProvider):
		c.JSON(http.StatusBadRequest, gin.H{"error": "quota unsupported for auth provider"})
	case errors.Is(err, authfilequota.ErrAuthTokenNotFound):
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth token not found"})
	case errors.Is(err, authfilequota.ErrTokenRefresh):
		c.JSON(http.StatusBadGateway, gin.H{"error": "auth token refresh failed"})
	case errors.Is(err, authfilequota.ErrInvalidQuotaResponse):
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid quota response"})
	default:
		// The quota service intentionally never exposes upstream error details.
		c.JSON(http.StatusBadGateway, gin.H{"error": "quota request failed"})
	}
}
