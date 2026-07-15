package authfilequota

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/api/bodyutil"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	codexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	geminiAuth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/gemini"
	xaiauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/xai"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/geminicli"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// TokenValueForAuth obtains a stored credential without refreshing it.
func TokenValueForAuth(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if token := TokenValueFromMetadata(auth.Metadata); token != "" {
		return token
	}
	if auth.Attributes != nil {
		if key := strings.TrimSpace(auth.Attributes["api_key"]); key != "" {
			return key
		}
	}
	switch storage := auth.Storage.(type) {
	case *codexauth.CodexTokenStorage:
		if token := strings.TrimSpace(storage.AccessToken); token != "" {
			return token
		}
		if token := strings.TrimSpace(storage.IDToken); token != "" {
			return token
		}
	case *geminiAuth.GeminiTokenStorage:
		if token := tokenValueFromStoredToken(storage.Token); token != "" {
			return token
		}
	}
	if shared := geminicli.ResolveSharedCredential(auth.Runtime); shared != nil {
		return TokenValueFromMetadata(shared.MetadataSnapshot())
	}
	return ""
}

// hasRefreshCredential detects persisted OAuth refresh-token layouts without
// treating an absent credential as a failed refresh attempt.
func hasRefreshCredential(auth *coreauth.Auth) bool {
	if auth == nil {
		return false
	}
	if refreshTokenFromMap(auth.Metadata) != "" {
		return true
	}
	switch storage := auth.Storage.(type) {
	case *codexauth.CodexTokenStorage:
		return strings.TrimSpace(storage.RefreshToken) != ""
	case *geminiAuth.GeminiTokenStorage:
		return refreshTokenFromMap(oauthTokenMap(storage.Token)) != ""
	}
	if shared := geminicli.ResolveSharedCredential(auth.Runtime); shared != nil {
		return refreshTokenFromMap(shared.MetadataSnapshot()) != ""
	}
	return false
}

func refreshTokenFromMap(values map[string]any) string {
	if value := stringValue(values, "refresh_token"); value != "" {
		return value
	}
	return stringValue(oauthTokenMap(values["token"]), "refresh_token")
}

// ResolveTokenForAuth refreshes OAuth records as necessary and persists successful
// refreshes through the owning tenant's auth manager.
func (s *Service) ResolveTokenForAuth(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	if TokenValueForAuth(auth) == "" && !hasRefreshCredential(auth) {
		return "", nil
	}
	switch normalizedQuotaProvider(auth.Provider) {
	case "gemini-cli":
		return s.refreshGeminiOAuthAccessToken(ctx, auth)
	case "antigravity":
		return s.refreshAntigravityOAuthAccessToken(ctx, auth)
	case "claude":
		return s.refreshClaudeOAuthAccessToken(ctx, auth)
	case "kimi":
		return s.refreshKimiOAuthAccessToken(ctx, auth)
	case "xai":
		return s.refreshXAIOAuthAccessToken(ctx, auth)
	default:
		return TokenValueForAuth(auth), nil
	}
}

func (s *Service) refreshXAIOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}
	if strings.EqualFold(stringValue(auth.Metadata, "auth_kind"), "api_key") {
		return TokenValueForAuth(auth), nil
	}
	if token := TokenValueForAuth(auth); token != "" && stringValue(auth.Metadata, "refresh_token") == "" && stringValue(auth.Metadata, "access_token") == "" {
		return token, nil
	}
	metadata := auth.Metadata
	if len(metadata) == 0 {
		return "", fmt.Errorf("xai oauth metadata missing")
	}
	current := strings.TrimSpace(TokenValueFromMetadata(metadata))
	if current != "" && !xaiTokenNeedsRefresh(metadata) {
		return current, nil
	}
	refreshToken := stringValue(metadata, "refresh_token")
	if refreshToken == "" {
		if current != "" {
			return current, nil
		}
		return "", fmt.Errorf("xai refresh token missing")
	}
	tokenData, err := s.refreshXAIOAuthTokens(ctx, auth, refreshToken, stringValue(metadata, "token_endpoint"))
	if err != nil {
		return "", err
	}
	if tokenData == nil || strings.TrimSpace(tokenData.AccessToken) == "" {
		return "", fmt.Errorf("xai oauth token refresh returned empty access_token")
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	now := time.Now()
	metadata = auth.Metadata
	metadata["type"], metadata["auth_kind"], metadata["access_token"] = "xai", "oauth", strings.TrimSpace(tokenData.AccessToken)
	if value := strings.TrimSpace(tokenData.RefreshToken); value != "" {
		metadata["refresh_token"] = value
	}
	if value := strings.TrimSpace(tokenData.IDToken); value != "" {
		metadata["id_token"] = value
	}
	if value := strings.TrimSpace(tokenData.TokenType); value != "" {
		metadata["token_type"] = value
	}
	if tokenData.ExpiresIn > 0 {
		metadata["expires_in"] = tokenData.ExpiresIn
	}
	if value := strings.TrimSpace(tokenData.Expire); value != "" {
		metadata["expired"] = value
	}
	if value := strings.TrimSpace(tokenData.Email); value != "" {
		metadata["email"] = value
	}
	if value := strings.TrimSpace(tokenData.Subject); value != "" {
		metadata["sub"] = value
	}
	if value := stringValue(metadata, "token_endpoint"); value != "" {
		metadata["token_endpoint"] = value
	}
	if stringValue(metadata, "base_url") == "" {
		metadata["base_url"] = xaiauth.DefaultAPIBaseURL
	}
	metadata["last_refresh"] = now.UTC().Format(time.RFC3339)
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["auth_kind"] = "oauth"
	if strings.TrimSpace(auth.Attributes["base_url"]) == "" {
		auth.Attributes["base_url"] = xaiauth.DefaultAPIBaseURL
	}
	if email := stringValue(metadata, "email"); email != "" {
		auth.Attributes["email"] = email
	}
	s.persistRefresh(ctx, auth, now)
	return strings.TrimSpace(tokenData.AccessToken), nil
}

func (s *Service) refreshXAIOAuthTokens(ctx context.Context, auth *coreauth.Auth, refreshToken, tokenEndpoint string) (*xaiauth.TokenData, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	tokenEndpoint = strings.TrimSpace(tokenEndpoint)
	if tokenEndpoint == "" {
		var err error
		tokenEndpoint, err = s.discoverXAIOAuthTokenEndpoint(ctx, auth)
		if err != nil {
			return nil, err
		}
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {xaiauth.ClientID}, "refresh_token": {strings.TrimSpace(refreshToken)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, status, err := s.doBounded(req, auth, s.oauthResponseLimit())
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("xai token refresh failed: status %d", status)
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if strings.TrimSpace(response.AccessToken) == "" {
		return nil, fmt.Errorf("xai token refresh returned empty access_token")
	}
	claims := idTokenClaims(response.IDToken)
	email, subject := "", ""
	if claims != nil {
		email, subject = stringAt(claims, "email"), stringAt(claims, "sub", "subject", "principal_id", "principalId")
	}
	return &xaiauth.TokenData{AccessToken: strings.TrimSpace(response.AccessToken), RefreshToken: strings.TrimSpace(response.RefreshToken), IDToken: strings.TrimSpace(response.IDToken), TokenType: strings.TrimSpace(response.TokenType), ExpiresIn: response.ExpiresIn, Expire: time.Now().Add(time.Duration(response.ExpiresIn) * time.Second).UTC().Format(time.RFC3339), Email: email, Subject: subject}, nil
}

// discoverXAIOAuthTokenEndpoint preserves xAI's OIDC discovery flow while
// bounding the discovery response and prohibiting redirects.
func (s *Service) discoverXAIOAuthTokenEndpoint(ctx context.Context, auth *coreauth.Auth) (string, error) {
	endpoint := s.deps.Endpoints.XAIOAuthDiscovery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("xai discovery: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	body, status, err := s.doBounded(req, auth, s.oauthResponseLimit())
	if err != nil {
		return "", fmt.Errorf("xai discovery: request failed: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("xai discovery failed with status %d", status)
	}
	var discovery struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil {
		return "", fmt.Errorf("xai discovery: parse response: %w", err)
	}
	if _, err := xaiauth.ValidateOAuthEndpoint(discovery.AuthorizationEndpoint, "authorization_endpoint"); err != nil {
		return "", err
	}
	tokenEndpoint, err := xaiauth.ValidateOAuthEndpoint(discovery.TokenEndpoint, "token_endpoint")
	if err != nil {
		return "", err
	}
	return tokenEndpoint, nil
}

func (s *Service) refreshClaudeOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}
	metadata := auth.Metadata
	if len(metadata) == 0 {
		return "", fmt.Errorf("claude oauth metadata missing")
	}
	current := strings.TrimSpace(TokenValueFromMetadata(metadata))
	if current != "" && !claudeTokenNeedsRefresh(metadata) {
		return current, nil
	}
	refreshToken := stringValue(metadata, "refresh_token")
	if refreshToken == "" {
		return "", fmt.Errorf("claude refresh token missing")
	}
	var refresher ClaudeOAuthRefresher
	if factory := s.deps.NewClaudeOAuthRefresher; factory != nil {
		refresher = factory(s.claudeOAuthRefreshConfig(auth))
	} else {
		refresher = claudeauth.NewClaudeAuth(s.claudeOAuthRefreshConfig(auth))
	}
	if refresher == nil {
		return "", fmt.Errorf("claude oauth refresher unavailable")
	}
	var tokenData *claudeauth.ClaudeTokenData
	var err error
	if bounded, ok := refresher.(interface {
		RefreshTokensBounded(context.Context, string, claudeauth.ClaudeRefreshOptions) (*claudeauth.ClaudeTokenData, error)
	}); ok {
		tokenData, err = bounded.RefreshTokensBounded(ctx, refreshToken, claudeauth.ClaudeRefreshOptions{Endpoint: s.deps.Endpoints.ClaudeOAuthToken, Timeout: s.quotaTimeout(), ResponseLimit: s.oauthResponseLimit()})
	} else {
		// Injectable legacy refreshers are retained for compatibility tests.
		tokenData, err = refresher.RefreshTokens(ctx, refreshToken)
	}
	if err != nil {
		return "", err
	}
	if tokenData == nil || strings.TrimSpace(tokenData.AccessToken) == "" {
		return "", fmt.Errorf("claude oauth token refresh returned empty access_token")
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	now := time.Now()
	auth.Metadata["access_token"] = strings.TrimSpace(tokenData.AccessToken)
	if value := strings.TrimSpace(tokenData.RefreshToken); value != "" {
		auth.Metadata["refresh_token"] = value
	}
	if value := strings.TrimSpace(tokenData.Email); value != "" {
		auth.Metadata["email"] = value
	}
	if value := strings.TrimSpace(tokenData.Expire); value != "" {
		auth.Metadata["expired"] = value
	}
	auth.Metadata["type"], auth.Metadata["last_refresh"] = "claude", now.Format(time.RFC3339)
	s.persistRefresh(ctx, auth, now)
	return strings.TrimSpace(tokenData.AccessToken), nil
}

func (s *Service) claudeOAuthRefreshConfig(auth *coreauth.Auth) *config.Config {
	var copy config.Config
	if s != nil && s.cfg != nil {
		copy = *s.cfg
	}
	if auth == nil {
		return &copy
	}
	proxyURL := auth.ProxyURL
	if s != nil && s.cfg != nil {
		proxyURL = s.cfg.ResolveProxyURL(auth.ProxyID, auth.ProxyURL)
	}
	if proxyURL = strings.TrimSpace(proxyURL); proxyURL != "" {
		copy.ProxyURL = proxyURL
	}
	return &copy
}

func (s *Service) refreshGeminiOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}
	metadata, update := geminiOAuthMetadata(auth)
	if len(metadata) == 0 {
		return "", fmt.Errorf("gemini oauth metadata missing")
	}
	base := oauthTokenMap(metadata["token"])
	var token oauth2.Token
	if len(base) > 0 {
		if encoded, err := json.Marshal(base); err == nil {
			_ = json.Unmarshal(encoded, &token)
		}
	}
	if token.AccessToken == "" {
		token.AccessToken = stringValue(metadata, "access_token")
	}
	if token.RefreshToken == "" {
		token.RefreshToken = stringValue(metadata, "refresh_token")
	}
	if token.TokenType == "" {
		token.TokenType = stringValue(metadata, "token_type")
	}
	if token.Expiry.IsZero() {
		if raw := stringValue(metadata, "expiry"); raw != "" {
			if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
				token.Expiry = parsed
			}
		}
	}
	cfg := s.cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	clientID, clientSecret := geminiAuth.ResolveOAuthClientCredentials(cfg, base, metadata)
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("gemini oauth client-id missing (set config oauth-clients.gemini.client-id or env %s)", config.EnvGeminiOAuthClientID)
	}
	scopes := append([]string(nil), s.deps.GeminiOAuthScopes...)
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: s.quotaTimeout(), Transport: &oauthResponseLimitTransport{base: s.QuotaTransport(auth), limit: s.oauthResponseLimit()}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	current, err := (&oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Scopes: scopes, Endpoint: google.Endpoint}).TokenSource(ctx, &token).Token()
	if err != nil {
		return "", err
	}
	update(buildOAuthTokenFields(current, buildOAuthTokenMap(base, current)))
	return strings.TrimSpace(current.AccessToken), nil
}

func (s *Service) refreshAntigravityOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}
	metadata := auth.Metadata
	if len(metadata) == 0 {
		return "", fmt.Errorf("antigravity oauth metadata missing")
	}
	if current := strings.TrimSpace(TokenValueFromMetadata(metadata)); current != "" && !antigravityTokenNeedsRefresh(metadata) {
		return current, nil
	}
	refreshToken := stringValue(metadata, "refresh_token")
	if refreshToken == "" {
		return "", fmt.Errorf("antigravity refresh token missing")
	}
	cfg := s.cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	clientID, clientSecret := cfg.OAuthClientCredentials(config.OAuthClientAntigravity)
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("antigravity oauth client-id missing (set config oauth-clients.antigravity.client-id or env %s)", config.EnvAntigravityOAuthClientID)
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {clientSecret}, "grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	tokenURL := strings.TrimSpace(s.deps.AntigravityOAuthTokenURL)
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, status, err := s.doBounded(req, auth, s.oauthResponseLimit())
	if err != nil {
		return "", err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return "", fmt.Errorf("antigravity oauth token refresh failed: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.AccessToken) == "" {
		return "", fmt.Errorf("antigravity oauth token refresh returned empty access_token")
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	now := time.Now()
	auth.Metadata["access_token"], auth.Metadata["type"] = strings.TrimSpace(response.AccessToken), "antigravity"
	if value := strings.TrimSpace(response.RefreshToken); value != "" {
		auth.Metadata["refresh_token"] = value
	}
	if response.ExpiresIn > 0 {
		auth.Metadata["expires_in"], auth.Metadata["timestamp"], auth.Metadata["expired"] = response.ExpiresIn, now.UnixMilli(), now.Add(time.Duration(response.ExpiresIn)*time.Second).Format(time.RFC3339)
	}
	s.persistRefresh(ctx, auth, now)
	return strings.TrimSpace(response.AccessToken), nil
}

func (s *Service) refreshKimiOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}
	metadata := auth.Metadata
	if len(metadata) == 0 {
		return "", fmt.Errorf("kimi oauth metadata missing")
	}
	current, expiry := strings.TrimSpace(TokenValueFromMetadata(metadata)), stringValue(metadata, "expired")
	if current != "" && expiry != "" {
		if parsed, err := time.Parse(time.RFC3339, expiry); err == nil && time.Now().Add(30*time.Second).Before(parsed) {
			return current, nil
		}
	}
	refreshToken := stringValue(metadata, "refresh_token")
	if refreshToken == "" {
		return "", fmt.Errorf("kimi refresh token missing")
	}
	clientID := strings.TrimSpace(s.deps.KimiOAuthClientID)
	if clientID == "" {
		clientID = "17e5f671-d194-4dfb-9706-5516cb48c098"
	}
	tokenURL := strings.TrimSpace(s.deps.KimiOAuthTokenURL)
	if tokenURL == "" {
		tokenURL = "https://auth.kimi.com/api/oauth/token"
	}
	form := url.Values{"client_id": {clientID}, "grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Msh-Platform", "cli-proxy-api")
	if deviceID := stringValue(metadata, "device_id"); deviceID != "" {
		req.Header.Set("X-Msh-Device-Id", deviceID)
	}
	body, status, err := s.doBoundedWithTimeout(req, auth, s.oauthResponseLimit(), 30*time.Second)
	if err != nil {
		return "", err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return "", fmt.Errorf("kimi oauth token refresh failed: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	var response struct {
		AccessToken  string  `json:"access_token"`
		RefreshToken string  `json:"refresh_token"`
		ExpiresIn    float64 `json:"expires_in"`
		TokenType    string  `json:"token_type"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.AccessToken) == "" {
		return "", fmt.Errorf("kimi oauth token refresh returned empty access_token")
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	now := time.Now()
	auth.Metadata["access_token"], auth.Metadata["type"] = strings.TrimSpace(response.AccessToken), "kimi"
	if value := strings.TrimSpace(response.RefreshToken); value != "" {
		auth.Metadata["refresh_token"] = value
	}
	if deviceID := stringValue(metadata, "device_id"); deviceID != "" {
		auth.Metadata["device_id"] = deviceID
	}
	if response.ExpiresIn > 0 {
		auth.Metadata["expires_in"], auth.Metadata["timestamp"], auth.Metadata["expired"] = int64(response.ExpiresIn), now.UnixMilli(), now.Add(time.Duration(response.ExpiresIn)*time.Second).Format(time.RFC3339)
	}
	s.persistRefresh(ctx, auth, now)
	return strings.TrimSpace(response.AccessToken), nil
}

func (s *Service) persistRefresh(ctx context.Context, auth *coreauth.Auth, now time.Time) {
	if s == nil || s.authManager == nil || auth == nil {
		return
	}
	auth.LastRefreshedAt, auth.UpdatedAt = now, now
	_, _ = s.authManager.Update(ctx, auth)
}

func (s *Service) doBounded(req *http.Request, auth *coreauth.Auth, limit int64) ([]byte, int, error) {
	return s.doBoundedWithTimeout(req, auth, limit, s.quotaTimeout())
}

func (s *Service) doBoundedWithTimeout(req *http.Request, auth *coreauth.Auth, limit int64, timeout time.Duration) ([]byte, int, error) {
	client := util.NewHTTPClient(timeout)
	client.Transport = s.QuotaTransport(auth)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			log.WithError(closeErr).Debug("close quota response")
		}
	}()
	body, err := bodyutil.ReadAll(response.Body, limit)
	if err != nil {
		return nil, response.StatusCode, err
	}
	return body, response.StatusCode, nil
}

// oauthResponseLimitTransport bounds oauth2's internal response reader without
// granting it redirects or an unbounded response body.
type oauthResponseLimitTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t *oauthResponseLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(req)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	if t.limit > 0 && response.ContentLength > t.limit {
		_ = response.Body.Close()
		return nil, bodyutil.ErrBodyTooLarge
	}
	if t.limit > 0 {
		response.Body = http.MaxBytesReader(nil, response.Body, t.limit)
	}
	return response, nil
}

func xaiTokenNeedsRefresh(metadata map[string]any) bool {
	const skew = 30 * time.Second
	if metadata == nil {
		return true
	}
	for _, key := range []string{"expired", "expiry", "expires_at", "expiresAt"} {
		if parsed, err := time.Parse(time.RFC3339, stringValue(metadata, key)); err == nil && stringValue(metadata, key) != "" {
			return !parsed.After(time.Now().Add(skew))
		}
	}
	expiresIn, timestamp := int64Value(metadata["expires_in"]), int64Value(metadata["timestamp"])
	if expiresIn > 0 && timestamp > 0 {
		return !time.UnixMilli(timestamp).Add(time.Duration(expiresIn) * time.Second).After(time.Now().Add(skew))
	}
	return false
}

func antigravityTokenNeedsRefresh(metadata map[string]any) bool {
	const skew = 30 * time.Second
	if metadata == nil {
		return true
	}
	if value := stringValue(metadata, "expired"); value != "" {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			return !parsed.After(time.Now().Add(skew))
		}
	}
	expiresIn, timestamp := int64Value(metadata["expires_in"]), int64Value(metadata["timestamp"])
	return !(expiresIn > 0 && timestamp > 0) || !time.UnixMilli(timestamp).Add(time.Duration(expiresIn)*time.Second).After(time.Now().Add(skew))
}

func claudeTokenNeedsRefresh(metadata map[string]any) bool {
	const skew = 30 * time.Second
	if metadata == nil {
		return true
	}
	for _, key := range []string{"expired", "expiry", "expires_at", "expiresAt"} {
		if value := stringValue(metadata, key); value != "" {
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				return !parsed.After(time.Now().Add(skew))
			}
		}
	}
	return false
}

func int64Value(raw any) int64 {
	switch value := raw.(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case uint:
		return int64(value)
	case uint32:
		return int64(value)
	case uint64:
		if value <= uint64(^uint64(0)>>1) {
			return int64(value)
		}
	case float32:
		return int64(value)
	case float64:
		return int64(value)
	case json.Number:
		if out, err := value.Int64(); err == nil {
			return out
		}
	case string:
		if out, err := json.Number(strings.TrimSpace(value)).Int64(); err == nil {
			return out
		}
	}
	return 0
}

func geminiOAuthMetadata(auth *coreauth.Auth) (map[string]any, func(map[string]any)) {
	if auth == nil {
		return nil, func(map[string]any) {}
	}
	if shared := geminicli.ResolveSharedCredential(auth.Runtime); shared != nil {
		return shared.MetadataSnapshot(), func(fields map[string]any) { _ = shared.MergeMetadata(fields) }
	}
	metadata := cloneMap(auth.Metadata)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	if storage, ok := auth.Storage.(*geminiAuth.GeminiTokenStorage); ok {
		if metadata["token"] == nil {
			metadata["token"] = storage.Token
		}
		return metadata, func(fields map[string]any) {
			if auth.Metadata == nil {
				auth.Metadata = make(map[string]any)
			}
			for key, value := range fields {
				auth.Metadata[key] = value
			}
			if token, ok := fields["token"]; ok {
				storage.Token = token
			}
		}
	}
	return metadata, func(fields map[string]any) {
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		for key, value := range fields {
			auth.Metadata[key] = value
		}
	}
}

func stringValue(metadata map[string]any, key string) string {
	if value, ok := metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}
func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
func buildOAuthTokenMap(base map[string]any, token *oauth2.Token) map[string]any {
	out := cloneMap(base)
	if out == nil {
		out = make(map[string]any)
	}
	if token == nil {
		return out
	}
	if raw, err := json.Marshal(token); err == nil {
		var fields map[string]any
		if json.Unmarshal(raw, &fields) == nil {
			for key, value := range fields {
				out[key] = value
			}
		}
	}
	return out
}
func buildOAuthTokenFields(token *oauth2.Token, merged map[string]any) map[string]any {
	fields := make(map[string]any, 5)
	if token == nil {
		return fields
	}
	if token.AccessToken != "" {
		fields["access_token"] = token.AccessToken
	}
	if token.TokenType != "" {
		fields["token_type"] = token.TokenType
	}
	if token.RefreshToken != "" {
		fields["refresh_token"] = token.RefreshToken
	}
	if !token.Expiry.IsZero() {
		fields["expiry"] = token.Expiry.Format(time.RFC3339)
	}
	if len(merged) > 0 {
		fields["token"] = cloneMap(merged)
	}
	return fields
}

func oauthTokenMap(raw any) map[string]any {
	if values, ok := raw.(map[string]any); ok {
		return cloneMap(values)
	}
	if raw == nil {
		return make(map[string]any)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return make(map[string]any)
	}
	var values map[string]any
	if json.Unmarshal(encoded, &values) != nil {
		return make(map[string]any)
	}
	return values
}

func tokenValueFromStoredToken(raw any) string {
	switch token := raw.(type) {
	case *oauth2.Token:
		if token != nil {
			return strings.TrimSpace(token.AccessToken)
		}
	case oauth2.Token:
		return strings.TrimSpace(token.AccessToken)
	}
	return TokenValueFromMetadata(map[string]any{"token": raw})
}

// TokenValueFromMetadata accepts the persisted token layouts used by auth files.
func TokenValueFromMetadata(metadata map[string]any) string {
	for _, key := range []string{"accessToken", "access_token"} {
		if value := stringValue(metadata, key); value != "" {
			return value
		}
	}
	if token := metadata["token"]; token != nil {
		switch value := token.(type) {
		case string:
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		case map[string]any:
			for _, key := range []string{"access_token", "accessToken"} {
				if token := stringValue(value, key); token != "" {
					return token
				}
			}
		case map[string]string:
			for _, key := range []string{"access_token", "accessToken"} {
				if token := strings.TrimSpace(value[key]); token != "" {
					return token
				}
			}
		}
	}
	for _, key := range []string{"id_token", "cookie"} {
		if value := stringValue(metadata, key); value != "" {
			return value
		}
	}
	return ""
}
