// Package authfilequota fetches quota summaries for stored tenant auth files.
package authfilequota

import (
	"context"
	"errors"
	"net/http"
	"time"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const (
	defaultQuotaTimeout       = 60 * time.Second
	defaultQuotaResponseLimit = int64(4 << 20)
	defaultOAuthResponseLimit = int64(64 << 10)
)

var (
	ErrAuthManagerUnavailable = errors.New("auth manager unavailable")
	ErrAuthNotFound           = errors.New("auth not found")
	ErrUnsupportedProvider    = errors.New("quota unsupported for auth provider")
	ErrAuthTokenNotFound      = errors.New("auth token not found")
	ErrTokenRefresh           = errors.New("auth token refresh failed")
	ErrQuotaRequest           = errors.New("quota request failed")
	ErrInvalidQuotaResponse   = errors.New("invalid quota response")
)

// QuotaFormat carries locale-sensitive presentation primitives. Kind is closed
// by this package; callers must never receive provider response payloads.
type QuotaFormat struct {
	Kind           string   `json:"kind"`
	TokenType      string   `json:"token_type,omitempty"`
	Amount         *float64 `json:"amount,omitempty"`
	Used           *float64 `json:"used,omitempty"`
	Limit          *float64 `json:"limit,omitempty"`
	Status         string   `json:"status,omitempty"`
	StartAtMs      *int64   `json:"start_at_ms,omitempty"`
	EndAtMs        *int64   `json:"end_at_ms,omitempty"`
	RemainingCents *int64   `json:"remaining_cents,omitempty"`
	TotalCents     *int64   `json:"total_cents,omitempty"`
}

// QuotaItem is a provider-neutral quota presentation primitive.
type QuotaItem struct {
	Key           string       `json:"key,omitempty"`
	Label         string       `json:"label"`
	Percent       *float64     `json:"percent"`
	Value         string       `json:"value,omitempty"`
	ResetAtMs     *int64       `json:"reset_at_ms,omitempty"`
	WindowSeconds int64        `json:"window_seconds,omitempty"`
	Meta          string       `json:"meta,omitempty"`
	Format        *QuotaFormat `json:"format,omitempty"`
}

// QuotaResult is the fixed response from an auth-file quota operation.
type QuotaResult struct {
	Provider               string      `json:"provider"`
	Items                  []QuotaItem `json:"items"`
	PlanType               *string     `json:"plan_type,omitempty"`
	ResetCreditCount       *int        `json:"reset_credit_count,omitempty"`
	ResetCreditExpirations []string    `json:"reset_credit_expirations,omitempty"`
}

// ClaudeOAuthRefresher makes token-refresh behavior injectable in focused tests.
type ClaudeOAuthRefresher interface {
	RefreshTokens(ctx context.Context, refreshToken string) (*claudeauth.ClaudeTokenData, error)
}

// Endpoints contains every external target used by auth-file quota operations.
// Empty fields receive the production endpoint in Dependencies.normalized.
type Endpoints struct {
	Antigravity             []string
	ClaudeUsage             string
	ClaudeOAuthToken        string
	CodexUsage              string
	CodexResetCredits       string
	CodexConsumeResetCredit string
	GeminiCLIQuota          string
	KimiUsage               string
	KiroQuota               string
	XAIWeeklyBilling        string
	XAIOAuthDiscovery       string
	XAIMonthlyBilling       string
}

// Dependencies configures fixed quota networking and OAuth refresh behavior.
// Its zero value uses production endpoints and bounded clients.
type Dependencies struct {
	DefaultQuotaTimeout      time.Duration
	QuotaResponseLimit       int64
	OAuthTokenResponseLimit  int64
	GeminiOAuthScopes        []string
	AntigravityOAuthTokenURL string
	NewClaudeOAuthRefresher  func(*config.Config) ClaudeOAuthRefresher
	KimiOAuthClientID        string
	KimiOAuthTokenURL        string
	Endpoints                Endpoints
}

// Service is scoped to a single effective tenant and its runtime configuration.
type Service struct {
	tenantID    string
	cfg         *config.Config
	authManager *coreauth.Manager
	deps        Dependencies
}

func New(cfg *config.Config, authManager *coreauth.Manager, deps Dependencies) *Service {
	return NewForTenant("", cfg, authManager, deps)
}

func NewForTenant(tenantID string, cfg *config.Config, authManager *coreauth.Manager, deps Dependencies) *Service {
	return &Service{
		tenantID:    coreauth.NormalizedTenantID(tenantID),
		cfg:         cfg,
		authManager: authManager,
		deps:        deps.normalized(),
	}
}

func (d Dependencies) normalized() Dependencies {
	if d.DefaultQuotaTimeout <= 0 {
		d.DefaultQuotaTimeout = defaultQuotaTimeout
	}
	if d.QuotaResponseLimit <= 0 {
		d.QuotaResponseLimit = defaultQuotaResponseLimit
	}
	if d.OAuthTokenResponseLimit <= 0 {
		d.OAuthTokenResponseLimit = defaultOAuthResponseLimit
	}
	d.Endpoints = d.Endpoints.withProductionDefaults()
	return d
}

func (e Endpoints) withProductionDefaults() Endpoints {
	if len(e.Antigravity) == 0 {
		e.Antigravity = []string{
			"https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
			"https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:fetchAvailableModels",
			"https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
		}
	}
	if e.ClaudeUsage == "" {
		e.ClaudeUsage = "https://api.anthropic.com/api/oauth/usage"
	}
	if e.ClaudeOAuthToken == "" {
		e.ClaudeOAuthToken = "https://api.anthropic.com/v1/oauth/token"
	}
	if e.CodexUsage == "" {
		e.CodexUsage = "https://chatgpt.com/backend-api/wham/usage"
	}
	if e.CodexResetCredits == "" {
		e.CodexResetCredits = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits"
	}
	if e.CodexConsumeResetCredit == "" {
		e.CodexConsumeResetCredit = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"
	}
	if e.GeminiCLIQuota == "" {
		e.GeminiCLIQuota = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"
	}
	if e.KimiUsage == "" {
		e.KimiUsage = "https://api.kimi.com/coding/v1/usages"
	}
	if e.KiroQuota == "" {
		e.KiroQuota = "https://codewhisperer.us-east-1.amazonaws.com"
	}
	if e.XAIWeeklyBilling == "" {
		e.XAIWeeklyBilling = "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
	}
	if e.XAIOAuthDiscovery == "" {
		e.XAIOAuthDiscovery = "https://auth.x.ai/.well-known/openid-configuration"
	}
	if e.XAIMonthlyBilling == "" {
		e.XAIMonthlyBilling = "https://cli-chat-proxy.grok.com/v1/billing"
	}
	return e
}

func (s *Service) quotaTimeout() time.Duration { return s.deps.DefaultQuotaTimeout }
func (s *Service) quotaResponseLimit() int64   { return s.deps.QuotaResponseLimit }
func (s *Service) oauthResponseLimit() int64   { return s.deps.OAuthTokenResponseLimit }

// QuotaTransport resolves proxy precedence as ProxyID, then per-auth ProxyURL,
// then the tenant runtime configuration fallback.
func (s *Service) QuotaTransport(auth *coreauth.Auth) http.RoundTripper {
	return s.quotaTransport(auth)
}
