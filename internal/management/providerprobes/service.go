package providerprobes

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkmodelcatalog "github.com/router-for-me/CLIProxyAPI/v6/sdk/modelcatalog"
)

const providerProbeTimeout = 30 * time.Second

// Service operates only on a tenant's effective runtime configuration. It does
// not require an auth manager or a registered runtime executor, so disabled
// saved provider rows remain probeable.
type Service struct {
	cfg      *config.Config
	tenantID string
}

// NewService builds a service for a configuration without a tenant identity.
// It is useful to callers whose config is already scoped and which do not need
// the transient skeleton's TenantID field.
func NewService(cfg *config.Config) *Service {
	return NewForTenant(cfg, "")
}

// NewForTenant builds a service for one effective tenant configuration.
func NewForTenant(cfg *config.Config, tenantID string) *Service {
	return &Service{cfg: cfg, tenantID: strings.TrimSpace(tenantID)}
}

// Check sends an unauthenticated GET to the selected saved provider base URL.
// HTTP responses of every status are reachable. Transport failures are
// represented in CheckResult rather than returned as service errors.
func (s *Service) Check(ctx context.Context, kind synthesizer.ConfigProviderKind, index int) (CheckResult, error) {
	if !checkKindSupported(kind) {
		return CheckResult{}, ErrUnsupportedProviderKind
	}

	auth, err := s.savedAuth(kind, index)
	if err != nil {
		return CheckResult{}, err
	}
	baseURL := authAttribute(auth, "base_url")
	if baseURL == "" {
		return CheckResult{}, ErrProviderBaseURLRequired
	}

	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, providerProbeTimeout)
	defer cancel()

	started := time.Now()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, baseURL, nil)
	if err != nil {
		return failedCheck(started), nil
	}
	// URL userinfo would make net/http synthesize an Authorization header.
	// Connectivity probes are deliberately unauthenticated, even for a stored URL.
	if req.URL.User != nil {
		return failedCheck(started), nil
	}

	transport, transportOK := s.probeTransport(auth)
	if !transportOK {
		return failedCheck(started), nil
	}
	client := &http.Client{
		Timeout:   providerProbeTimeout,
		Transport: transport,
		// A redirect is an upstream status from the saved destination, not
		// permission to issue a second request to a different destination.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return failedCheck(started), nil
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	return CheckResult{
		OK:         true,
		StatusCode: &statusCode,
		LatencyMs:  time.Since(started).Milliseconds(),
	}, nil
}

// DiscoverModels obtains models from the selected saved provider without
// consulting process-global model caches or registered executors.
func (s *Service) DiscoverModels(ctx context.Context, kind synthesizer.ConfigProviderKind, index int) (ModelResult, error) {
	if !discoveryKindSupported(kind) {
		return ModelResult{}, ErrUnsupportedProviderKind
	}

	auth, err := s.savedAuth(kind, index)
	if err != nil {
		return ModelResult{}, err
	}
	if authAttribute(auth, "api_key") == "" {
		return ModelResult{}, ErrProviderCredentialRequired
	}
	if kind == synthesizer.ConfigProviderKindOpenAICompatibility && authAttribute(auth, "base_url") == "" {
		return ModelResult{}, ErrProviderBaseURLRequired
	}

	if ctx == nil {
		ctx = context.Background()
	}
	modelsCtx, cancel := context.WithTimeout(ctx, providerProbeTimeout)
	defer cancel()

	var models []*sdkmodelcatalog.ModelInfo
	switch kind {
	case synthesizer.ConfigProviderKindClaude:
		models, err = executor.FetchClaudeModelsStrict(modelsCtx, auth, s.cfg)
	case synthesizer.ConfigProviderKindCodex:
		models, err = executor.FetchCodexModelsStrict(modelsCtx, auth, s.cfg)
	case synthesizer.ConfigProviderKindOpenAICompatibility:
		models, err = executor.FetchOpenAICompatModelsStrict(modelsCtx, auth, s.cfg)
	}
	if err != nil {
		return ModelResult{}, ErrModelDiscoveryFailed
	}

	result := normalizeModels(models)
	if len(result.Models) == 0 {
		return ModelResult{}, ErrModelDiscoveryFailed
	}
	return result, nil
}

func (s *Service) savedAuth(kind synthesizer.ConfigProviderKind, index int) (*coreauth.Auth, error) {
	if index < 0 {
		return nil, ErrInvalidIndex
	}
	if !providerIndexExists(s.cfg, kind, index) {
		return nil, ErrProviderNotFound
	}
	auth, _, err := synthesizer.BuildConfigProviderAuthSkeleton(s.cfg, s.tenantID, kind, index)
	if err != nil || auth == nil {
		return nil, ErrProviderNotFound
	}
	return auth, nil
}

func (s *Service) probeTransport(auth *coreauth.Auth) (*http.Transport, bool) {
	preferIPv4 := s.cfg != nil && s.cfg.PreferIPv4
	transport := util.NewDefaultTransport(preferIPv4)
	if s.cfg == nil {
		return transport, true
	}
	proxyURL := strings.TrimSpace(s.cfg.ResolveProxyURL(auth.ProxyID, auth.ProxyURL))
	if proxyURL != "" {
		proxied := util.BuildProxyTransport(proxyURL, preferIPv4)
		if proxied == nil {
			return nil, false
		}
		transport = proxied
	}
	util.ApplyTLSConfig(transport, &s.cfg.SDKConfig)
	return transport, true
}

func failedCheck(started time.Time) CheckResult {
	return CheckResult{
		LatencyMs: time.Since(started).Milliseconds(),
		Message:   "request failed",
	}
}

func normalizeModels(models []*sdkmodelcatalog.ModelInfo) ModelResult {
	out := make([]Model, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Model{ID: id, OwnedBy: strings.TrimSpace(model.OwnedBy)})
	}
	return ModelResult{Models: out}
}

func authAttribute(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(auth.Attributes[key])
}

func checkKindSupported(kind synthesizer.ConfigProviderKind) bool {
	switch kind {
	case synthesizer.ConfigProviderKindGemini,
		synthesizer.ConfigProviderKindClaude,
		synthesizer.ConfigProviderKindCodex,
		synthesizer.ConfigProviderKindVertex,
		synthesizer.ConfigProviderKindBedrock:
		return true
	default:
		return false
	}
}

func discoveryKindSupported(kind synthesizer.ConfigProviderKind) bool {
	switch kind {
	case synthesizer.ConfigProviderKindClaude,
		synthesizer.ConfigProviderKindCodex,
		synthesizer.ConfigProviderKindOpenAICompatibility:
		return true
	default:
		return false
	}
}

func providerIndexExists(cfg *config.Config, kind synthesizer.ConfigProviderKind, index int) bool {
	if cfg == nil || index < 0 {
		return false
	}
	switch kind {
	case synthesizer.ConfigProviderKindGemini:
		return index < len(cfg.GeminiKey)
	case synthesizer.ConfigProviderKindClaude:
		return index < len(cfg.ClaudeKey)
	case synthesizer.ConfigProviderKindCodex:
		return index < len(cfg.CodexKey)
	case synthesizer.ConfigProviderKindVertex:
		return index < len(cfg.VertexCompatAPIKey)
	case synthesizer.ConfigProviderKindBedrock:
		return index < len(cfg.BedrockKey)
	case synthesizer.ConfigProviderKindOpenAICompatibility:
		return index < len(cfg.OpenAICompatibility)
	default:
		return false
	}
}
