package authfilequota

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	geminiAuth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/gemini"
	managementauthfiles "github.com/router-for-me/CLIProxyAPI/v6/internal/management/authfiles"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const (
	defaultAntigravityProjectID = "bamboo-precept-lgxtn"
	fiveHoursSeconds            = int64(18_000)
	weekSeconds                 = int64(604_800)
)

// Fetch looks up an auth file only within the service tenant and dispatches by
// its stored provider. No caller-supplied provider, URL, headers, or payload is used.
func (s *Service) Fetch(ctx context.Context, authIndex string) (QuotaResult, error) {
	if s == nil || s.authManager == nil {
		return QuotaResult{}, ErrAuthManagerUnavailable
	}
	auth := s.AuthByIndex(authIndex)
	if auth == nil {
		return QuotaResult{}, ErrAuthNotFound
	}
	provider, ok := quotaProvider(auth)
	if !ok {
		return QuotaResult{}, ErrUnsupportedProvider
	}
	token, err := s.ResolveTokenForAuth(ctx, auth)
	if err != nil {
		return QuotaResult{}, fmt.Errorf("%w: %v", ErrTokenRefresh, err)
	}
	if strings.TrimSpace(token) == "" {
		return QuotaResult{}, ErrAuthTokenNotFound
	}

	switch provider {
	case "antigravity":
		items, err := s.fetchAntigravity(ctx, auth, token)
		return QuotaResult{Provider: provider, Items: items}, err
	case "claude":
		items, err := s.fetchClaude(ctx, auth, token)
		return QuotaResult{Provider: provider, Items: items}, err
	case "codex":
		result, err := s.fetchCodex(ctx, auth, token)
		return result, err
	case "gemini-cli":
		items, err := s.fetchGeminiCLI(ctx, auth, token)
		return QuotaResult{Provider: provider, Items: items}, err
	case "kimi":
		items, err := s.fetchKimi(ctx, auth, token)
		return QuotaResult{Provider: provider, Items: items}, err
	case "kiro":
		items, err := s.fetchKiro(ctx, auth, token)
		return QuotaResult{Provider: provider, Items: items}, err
	case "xai":
		result, err := s.fetchXAI(ctx, auth, token)
		return result, err
	default:
		return QuotaResult{}, ErrUnsupportedProvider
	}
}

// ConsumeCodexResetCredit sends the only allowed reset-credit request. Its
// redeem ID is generated server-side so clients cannot replay or choose it.
func (s *Service) ConsumeCodexResetCredit(ctx context.Context, authIndex string) error {
	if s == nil || s.authManager == nil {
		return ErrAuthManagerUnavailable
	}
	auth := s.AuthByIndex(authIndex)
	if auth == nil {
		return ErrAuthNotFound
	}
	if provider, ok := quotaProvider(auth); !ok || provider != "codex" {
		return ErrUnsupportedProvider
	}
	token, err := s.ResolveTokenForAuth(ctx, auth)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenRefresh, err)
	}
	if strings.TrimSpace(token) == "" {
		return ErrAuthTokenNotFound
	}
	body, err := json.Marshal(struct {
		RedeemRequestID string `json:"redeem_request_id"`
	}{RedeemRequestID: uuid.NewString()})
	if err != nil {
		return fmt.Errorf("%w: encode consume request", ErrQuotaRequest)
	}
	headers := codexHeaders(token, auth)
	_, err = s.quotaRequest(ctx, auth, http.MethodPost, s.deps.Endpoints.CodexConsumeResetCredit, headers, body)
	return err
}

func normalizedQuotaProvider(provider string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(provider), "_", "-")) {
	case "gemini", "gemini-cli":
		return "gemini-cli"
	case "claude", "anthropic":
		return "claude"
	case "xai", "x-ai", "grok":
		return "xai"
	case "antigravity", "codex", "kimi", "kiro":
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(provider), "_", "-"))
	default:
		return ""
	}
}

func quotaProvider(auth *coreauth.Auth) (string, bool) {
	if auth == nil {
		return "", false
	}
	provider := normalizedQuotaProvider(auth.Provider)
	switch provider {
	case "claude":
		kind := strings.ToLower(strings.ReplaceAll(authValue(auth, "account_type", "accountType", "auth_kind", "authKind"), "-", "_"))
		if kind == "api_key" || kind == "apikey" || authValue(auth, "api_key") != "" {
			return "", false
		}
	}
	return provider, provider != ""
}

func (s *Service) fetchAntigravity(ctx context.Context, auth *coreauth.Auth, token string) ([]QuotaItem, error) {
	body, _ := json.Marshal(map[string]string{"project": antigravityProjectID(auth)})
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
		"User-Agent":    "antigravity/1.11.5 windows/amd64",
	}
	var last error
	for _, endpoint := range s.deps.Endpoints.Antigravity {
		response, err := s.quotaRequest(ctx, auth, http.MethodPost, endpoint, headers, body)
		if err != nil {
			last = err
			continue
		}
		payload, ok := decodeObject(response)
		if !ok {
			return nil, ErrInvalidQuotaResponse
		}
		models, ok := objectAt(payload, "models")
		if !ok {
			return nil, ErrInvalidQuotaResponse
		}
		return buildAntigravityItems(payload, models), nil
	}
	if last != nil {
		return nil, last
	}
	return nil, ErrQuotaRequest
}

func (s *Service) fetchClaude(ctx context.Context, auth *coreauth.Auth, token string) ([]QuotaItem, error) {
	response, err := s.quotaRequest(ctx, auth, http.MethodGet, s.deps.Endpoints.ClaudeUsage, map[string]string{
		"Accept": "application/json, text/plain, */*", "Authorization": "Bearer " + token,
		"Content-Type": "application/json", "User-Agent": "claude-code/2.1.7", "anthropic-beta": "oauth-2025-04-20",
	}, nil)
	if err != nil {
		return nil, err
	}
	payload, ok := decodeObject(response)
	if !ok {
		return nil, ErrInvalidQuotaResponse
	}
	return buildClaudeItems(payload), nil
}

func (s *Service) fetchCodex(ctx context.Context, auth *coreauth.Auth, token string) (QuotaResult, error) {
	headers := codexHeaders(token, auth)
	response, err := s.quotaRequest(ctx, auth, http.MethodGet, s.deps.Endpoints.CodexUsage, headers, nil)
	if err != nil {
		return QuotaResult{}, err
	}
	payload, ok := decodeObject(response)
	if !ok {
		return QuotaResult{}, ErrInvalidQuotaResponse
	}
	// Usage stays visible when local plan metadata persistence fails, matching the legacy relay.
	_ = s.reconcileCodexUsage(ctx, auth, payload)
	count := codexResetCreditCount(payload)
	result := QuotaResult{Provider: "codex", Items: buildCodexItems(payload), ResetCreditCount: new(count)}
	if plan := normalizeTag(stringAt(payload, "plan_type", "planType")); plan != "" {
		result.PlanType = new(plan)
	}
	if count > 0 {
		if details, detailsErr := s.quotaRequest(ctx, auth, http.MethodGet, s.deps.Endpoints.CodexResetCredits, headers, nil); detailsErr == nil {
			if expirations := codexResetCreditExpirations(details); len(expirations) > 0 {
				result.ResetCreditExpirations = expirations
			}
		}
	}
	return result, nil
}

func (s *Service) fetchGeminiCLI(ctx context.Context, auth *coreauth.Auth, token string) ([]QuotaItem, error) {
	projectID := geminiCLIProjectID(auth)
	if projectID == "" {
		return nil, ErrInvalidQuotaResponse
	}
	body, _ := json.Marshal(map[string]string{"project": projectID})
	response, err := s.quotaRequest(ctx, auth, http.MethodPost, s.deps.Endpoints.GeminiCLIQuota, map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}, body)
	if err != nil {
		return nil, err
	}
	payload, ok := decodeObject(response)
	if !ok {
		return nil, ErrInvalidQuotaResponse
	}
	return buildGeminiCLIItems(payload), nil
}

func (s *Service) fetchKimi(ctx context.Context, auth *coreauth.Auth, token string) ([]QuotaItem, error) {
	response, err := s.quotaRequest(ctx, auth, http.MethodGet, s.deps.Endpoints.KimiUsage, map[string]string{"Authorization": "Bearer " + token}, nil)
	if err != nil {
		return nil, err
	}
	payload, ok := decodeObject(response)
	if !ok {
		return nil, ErrInvalidQuotaResponse
	}
	return buildKimiItems(payload), nil
}

func (s *Service) fetchKiro(ctx context.Context, auth *coreauth.Auth, token string) ([]QuotaItem, error) {
	body := []byte(`{"origin":"AI_EDITOR","resourceType":"AGENTIC_REQUEST"}`)
	response, err := s.quotaRequest(ctx, auth, http.MethodPost, s.deps.Endpoints.KiroQuota, map[string]string{
		"Content-Type": "application/x-amz-json-1.0", "x-amz-target": "AmazonCodeWhispererService.GetUsageLimits", "Authorization": "Bearer " + token,
	}, body)
	if err != nil {
		return nil, err
	}
	payload, ok := decodeObject(response)
	if !ok {
		return nil, ErrInvalidQuotaResponse
	}
	return buildKiroItems(payload), nil
}

type xaiResponse struct {
	payload map[string]any
	err     error
}

func (s *Service) fetchXAI(ctx context.Context, auth *coreauth.Auth, token string) (QuotaResult, error) {
	headers := map[string]string{"Authorization": "Bearer " + token, "x-xai-token-auth": "xai-grok-cli", "x-grok-client-version": "0.2.91", "accept": "*/*", "user-agent": "grok-pager/0.2.91 grok-shell/0.2.91 (macos; aarch64)"}
	if userID := xaiUserID(auth); userID != "" {
		headers["x-userid"] = userID
	}
	endpoints := []string{s.deps.Endpoints.XAIWeeklyBilling, s.deps.Endpoints.XAIMonthlyBilling}
	responses := make([]xaiResponse, len(endpoints))
	var wait sync.WaitGroup
	for i, endpoint := range endpoints {
		wait.Add(1)
		go func(index int, target string) {
			defer wait.Done()
			body, err := s.quotaRequest(ctx, auth, http.MethodGet, target, headers, nil)
			if err != nil {
				responses[index].err = err
				return
			}
			payload, ok := decodeObject(body)
			if !ok {
				responses[index].err = ErrInvalidQuotaResponse
				return
			}
			config, ok := objectAt(payload, "config")
			if !ok {
				responses[index].err = ErrInvalidQuotaResponse
				return
			}
			responses[index].payload = config
		}(i, endpoint)
	}
	wait.Wait()
	weekly, monthly := xaiSummary(responses[0].payload), xaiSummary(responses[1].payload)
	summary := mergeXAISummaries(weekly, monthly)
	if summary == nil {
		if responses[0].err != nil && responses[1].err != nil {
			if errors.Is(responses[0].err, ErrInvalidQuotaResponse) && errors.Is(responses[1].err, ErrInvalidQuotaResponse) {
				return QuotaResult{}, ErrInvalidQuotaResponse
			}
			return QuotaResult{}, ErrQuotaRequest
		}
		return QuotaResult{}, ErrInvalidQuotaResponse
	}
	result := QuotaResult{Provider: "xai", Items: buildXAIItems(summary)}
	if plan := xaiPlanType(summary.monthlyLimitCents); plan != "" {
		result.PlanType = new(plan)
	}
	return result, nil
}

func (s *Service) quotaRequest(ctx context.Context, auth *coreauth.Auth, method, endpoint string, headers map[string]string, body []byte) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: invalid fixed endpoint", ErrQuotaRequest)
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrQuotaRequest)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, status, err := s.doBounded(request, auth, s.quotaResponseLimit())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuotaRequest, err)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: upstream status %d", ErrQuotaRequest, status)
	}
	return response, nil
}

func codexHeaders(token string, auth *coreauth.Auth) map[string]string {
	headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"}
	if accountID := codexAccountID(auth); accountID != "" {
		headers["Chatgpt-Account-Id"] = accountID
	}
	return headers
}

func antigravityProjectID(auth *coreauth.Auth) string {
	if value := authValue(auth, "project_id", "projectId", "project"); value != "" {
		return value
	}
	if auth == nil {
		return defaultAntigravityProjectID
	}
	for _, values := range []map[string]any{auth.Metadata} {
		for _, key := range []string{"installed", "web"} {
			if object, ok := objectAt(values, key); ok {
				if value := stringAt(object, "project_id", "projectId", "project"); value != "" {
					return value
				}
			}
		}
	}
	return defaultAntigravityProjectID
}

func geminiCLIProjectID(auth *coreauth.Auth) string {
	if projectID := authValue(auth, "project_id", "projectId"); projectID != "" {
		return projectID
	}
	if auth != nil {
		if storage, ok := auth.Storage.(*geminiAuth.GeminiTokenStorage); ok {
			if projectID := strings.TrimSpace(storage.ProjectID); projectID != "" {
				return projectID
			}
		}
	}
	return projectIDPattern(authValue(auth, "account"))
}

func projectIDPattern(value string) string {
	start, end := strings.LastIndex(value, "("), strings.LastIndex(value, ")")
	if start >= 0 && end > start {
		return strings.TrimSpace(value[start+1 : end])
	}
	return ""
}

func codexAccountID(auth *coreauth.Auth) string {
	for _, key := range []string{"chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"} {
		if value := authValue(auth, key); value != "" {
			return value
		}
	}
	for _, raw := range []string{authValue(auth, "id_token")} {
		claims := idTokenClaims(raw)
		if claims == nil {
			continue
		}
		if value := stringAt(claims, "chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"); value != "" {
			return value
		}
		if nested, ok := objectAt(claims, "https://api.openai.com/auth"); ok {
			if value := stringAt(nested, "chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"); value != "" {
				return value
			}
		}
	}
	return ""
}

func xaiUserID(auth *coreauth.Auth) string {
	for _, key := range []string{"sub", "subject", "principal_id", "principalId", "user_id", "userId"} {
		if value := authValue(auth, key); value != "" {
			return value
		}
	}
	for _, metadata := range []map[string]any{auth.Metadata} {
		for _, key := range []string{"oauth", "user"} {
			if nested, ok := objectAt(metadata, key); ok {
				if value := stringAt(nested, "sub", "subject", "principal_id", "principalId", "user_id", "userId", "id"); value != "" {
					return value
				}
			}
		}
	}
	if claims := idTokenClaims(authValue(auth, "id_token")); claims != nil {
		return stringAt(claims, "principal_id", "principalId", "sub", "subject", "user_id", "userId", "id")
	}
	return ""
}

func authValue(auth *coreauth.Auth, keys ...string) string {
	if auth == nil {
		return ""
	}
	if value := stringAt(auth.Metadata, keys...); value != "" {
		return value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
			return value
		}
	}
	return ""
}

func idTokenClaims(value string) map[string]any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(value), &parsed) == nil {
		return parsed
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil
	}
	payload := strings.NewReplacer("-", "+", "_", "/").Replace(parts[1])
	payload += strings.Repeat("=", (4-len(payload)%4)%4)
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(decoded, &parsed) != nil {
		return nil
	}
	return parsed
}

func buildAntigravityItems(payload, models map[string]any) []QuotaItem {
	type group struct {
		key, label string
		ids        map[string]struct{}
	}
	groups := []group{
		{"provider:gemini3-pro", "antigravity_quota.gemini3_pro", stringSet("gemini-3-pro-low", "gemini-3-pro-high", "gemini-3-pro-preview", "gemini-3.1-pro-low", "gemini-3.1-pro-high", "gemini-3.1-pro-preview")},
		{"provider:gemini3-flash", "antigravity_quota.gemini3_flash", stringSet("gemini-3-flash", "gemini-3-flash-agent")},
		{"provider:gemini-image", "antigravity_quota.gemini_image", stringSet("gemini-2.5-flash-image", "gemini-3.1-flash-image", "gemini-3-pro-image", "gemini-3-pro-image-preview")},
		{"provider:claude", "antigravity_quota.claude", stringSet("claude-fable-5", "claude-sonnet-4-5", "claude-sonnet-4-5-thinking", "claude-opus-4-5-thinking", "claude-sonnet-4-6", "claude-opus-4-6", "claude-opus-4-6-thinking", "claude-opus-4-7", "claude-opus-4-8")},
	}
	skipped := stringSet("chat_20706", "chat_23310", "tab_flash_lite_preview", "tab_jump_flash_lite_preview", "gemini-2.5-flash-thinking", "gemini-2.5-pro")
	type summary struct {
		percent *float64
		reset   *int64
		count   int
	}
	summaries := make([]summary, len(groups))
	for modelID, raw := range models {
		if _, skip := skipped[modelID]; skip {
			continue
		}
		model, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		quota, ok := objectAt(model, "quotaInfo", "quota_info")
		if !ok {
			continue
		}
		fraction, hasFraction := quotaFraction(valueAt(quota, "remainingFraction", "remaining_fraction", "remaining"))
		reset := resetTimeMs(valueAt(quota, "resetTime", "reset_time"))
		if !hasFraction && reset == nil {
			continue
		}
		for index, group := range groups {
			if _, matched := group.ids[strings.TrimPrefix(strings.ToLower(modelID), "models/")]; !matched {
				continue
			}
			current := &summaries[index]
			current.count++
			if hasFraction {
				percent := math.Round(clampPercent(fraction * 100))
				if current.percent == nil || percent < *current.percent {
					current.percent = new(percent)
				}
			}
			if reset != nil && (current.reset == nil || *reset < *current.reset) {
				current.reset = reset
			}
		}
	}
	items := make([]QuotaItem, 0, len(groups))
	for index, group := range groups {
		if summary := summaries[index]; summary.count > 0 {
			items = append(items, QuotaItem{Key: group.key, Label: group.label, Percent: summary.percent, ResetAtMs: summary.reset})
		}
	}
	_ = payload
	return items
}

func buildClaudeItems(payload map[string]any) []QuotaItem {
	definitions := []struct{ key, label string }{
		{"five_hour", "claude_quota.five_hour"}, {"seven_day", "claude_quota.seven_day"},
		{"seven_day_oauth_apps", "claude_quota.seven_day_oauth_apps"}, {"seven_day_opus", "claude_quota.seven_day_opus"},
		{"seven_day_sonnet", "claude_quota.seven_day_sonnet"}, {"seven_day_cowork", "claude_quota.seven_day_cowork"},
		{"iguana_necktie", "claude_quota.iguana_necktie"},
	}
	items := make([]QuotaItem, 0, len(definitions)+1)
	for _, definition := range definitions {
		window, ok := objectAt(payload, definition.key)
		if !ok {
			continue
		}
		percent := remainingPercentNullable(numberAt(window, "utilization"))
		reset := resetTimeMs(valueAt(window, "resets_at", "resetsAt"))
		if percent == nil && reset == nil {
			continue
		}
		items = append(items, QuotaItem{Key: definition.key, Label: definition.label, Percent: percent, ResetAtMs: reset})
	}
	if extra, ok := objectAt(payload, "extra_usage"); ok && boolAt(extra, "is_enabled") {
		if utilization := numberAt(extra, "utilization"); utilization != nil {
			meta := ""
			if used, limit := stringAt(extra, "used_credits"), stringAt(extra, "monthly_limit"); used != "" && limit != "" {
				meta = used + " / " + limit + " credits"
			}
			items = append(items, QuotaItem{Key: "extra_usage", Label: "claude_quota.extra_usage_label", Percent: remainingPercentNullable(utilization), Meta: meta})
		}
	}
	return items
}

func buildCodexItems(payload map[string]any) []QuotaItem {
	items := make([]QuotaItem, 0, 8)
	addInfo := func(prefix string, info map[string]any, includeNonStandard bool) {
		windows := rateLimitWindows(info)
		var five, weekly map[string]any
		for _, window := range windows {
			switch int64Number(numberAt(window, "limit_window_seconds", "limitWindowSeconds")) {
			case fiveHoursSeconds:
				if five == nil {
					five = window
				}
			case weekSeconds:
				if weekly == nil {
					weekly = window
				}
			}
		}
		addWindow := func(key, label string, seconds int64, window map[string]any) {
			if window == nil {
				return
			}
			used := numberAt(window, "used_percent", "usedPercent")
			if used == nil && (!boolAtDefault(info, true, "allowed") || boolAt(info, "limit_reached", "limitReached")) {
				used = new(float64(100))
			}
			items = append(items, QuotaItem{Key: key, Label: label, Percent: remainingPercentNullable(used), ResetAtMs: codexResetAt(window), WindowSeconds: seconds})
		}
		base, subscriptionLabel := "code", "m_quota.code_subscription"
		if prefix == "review" {
			base, subscriptionLabel = "review", "m_quota.review_subscription"
		}
		labels := map[string]string{"code": "m_quota.code_5h", "review": "m_quota.review_5h"}
		weeklyLabels := map[string]string{"code": "m_quota.code_weekly", "review": "m_quota.review_weekly"}
		addWindow(base+"_5h", labels[base], fiveHoursSeconds, five)
		addWindow(base+"_week", weeklyLabels[base], weekSeconds, weekly)
		if includeNonStandard {
			for _, window := range windows {
				seconds := int64Number(numberAt(window, "limit_window_seconds", "limitWindowSeconds"))
				if seconds > 0 && seconds != fiveHoursSeconds && seconds != weekSeconds {
					addWindow(fmt.Sprintf("%s_subscription_%d", base, seconds), subscriptionLabel, seconds, window)
				}
			}
		}
	}
	if rate, ok := objectAt(payload, "rate_limit", "rateLimit"); ok {
		addInfo("code", rate, true)
	}
	if review, ok := objectAt(payload, "code_review_rate_limit", "codeReviewRateLimit"); ok {
		addInfo("review", review, true)
	}
	for _, entry := range arrayAt(payload, "additional_rate_limits", "additionalRateLimits") {
		additional, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		info, ok := objectAt(additional, "rate_limit", "rateLimit")
		if !ok {
			continue
		}
		name := stringAt(additional, "limit_name", "limitName")
		if name == "" {
			name = "Additional Codex quota"
		}
		keyPart := normalizedKeyPart(stringAt(additional, "metered_feature", "meteredFeature"))
		if keyPart == "" && strings.EqualFold(name, "gpt-5.3-codex-spark") {
			keyPart = "codex_bengalfox"
		}
		if keyPart == "" {
			keyPart = normalizedKeyPart(name)
		}
		if keyPart == "" {
			keyPart = "additional"
		}
		var five, weekly map[string]any
		for _, window := range rateLimitWindows(info) {
			switch int64Number(numberAt(window, "limit_window_seconds", "limitWindowSeconds")) {
			case fiveHoursSeconds:
				if five == nil {
					five = window
				}
			case weekSeconds:
				if weekly == nil {
					weekly = window
				}
			}
		}
		addAdditional := func(suffix, label string, seconds int64, window map[string]any) {
			if window == nil {
				return
			}
			used := numberAt(window, "used_percent", "usedPercent")
			if used == nil && (!boolAtDefault(info, true, "allowed") || boolAt(info, "limit_reached", "limitReached")) {
				used = new(float64(100))
			}
			items = append(items, QuotaItem{Key: "additional:" + keyPart + ":" + suffix, Label: label, Percent: remainingPercentNullable(used), ResetAtMs: codexResetAt(window), WindowSeconds: seconds})
		}
		addAdditional("5h", name+": 5h", fiveHoursSeconds, five)
		addAdditional("week", name+": Weekly", weekSeconds, weekly)
	}
	return items
}

// rateLimitWindows applies the frontend's nullish snake/camel alias semantics:
// one primary and one secondary window, never duplicate alias variants.
func rateLimitWindows(info map[string]any) []map[string]any {
	windows := make([]map[string]any, 0, 2)
	if primary, ok := objectAt(info, "primary_window", "primaryWindow"); ok {
		windows = append(windows, primary)
	}
	if secondary, ok := objectAt(info, "secondary_window", "secondaryWindow"); ok {
		windows = append(windows, secondary)
	}
	return windows
}

func buildGeminiCLIItems(payload map[string]any) []QuotaItem {
	type bucket struct {
		id, tokenType, reset string
		fraction, amount     *float64
	}
	groups := map[string][]bucket{}
	firstSeen := map[string]int{}
	for _, raw := range arrayAt(payload, "buckets") {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		rawModelID := stringAt(entry, "modelId", "model_id")
		modelID := strings.TrimPrefix(rawModelID, "projects/")
		if marker := strings.LastIndex(modelID, "/models/"); marker >= 0 {
			modelID = modelID[marker+len("/models/"):]
		}
		modelID = strings.TrimPrefix(modelID, "models/")
		if modelID == "" || strings.HasPrefix(modelID, "gemini-2.0-flash") {
			continue
		}
		groupID, label, preferred := geminiGroup(modelID)
		tokenType := stringAt(entry, "tokenType", "token_type")
		key := groupID + ":" + tokenType
		if _, exists := firstSeen[key]; !exists {
			firstSeen[key] = len(firstSeen)
		}
		fraction, hasFraction := quotaFraction(valueAt(entry, "remainingFraction", "remaining_fraction"))
		var fractionPtr *float64
		if hasFraction {
			fractionPtr = new(fraction)
		}
		groups[key] = append(groups[key], bucket{id: modelID, tokenType: tokenType, reset: stringAt(entry, "resetTime", "reset_time"), fraction: fractionPtr, amount: numberAt(entry, "remainingAmount", "remaining_amount")})
		_ = label
		_ = preferred
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		leftRank := geminiGroupOrder(strings.SplitN(keys[i], ":", 2)[0])
		rightRank := geminiGroupOrder(strings.SplitN(keys[j], ":", 2)[0])
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if leftRank == 1<<30 {
			return firstSeen[keys[i]] < firstSeen[keys[j]]
		}
		return keys[i] < keys[j]
	})
	items := make([]QuotaItem, 0, len(keys))
	for _, key := range keys {
		buckets := groups[key]
		groupID, label, preferred := geminiGroup(buckets[0].id)
		selected := buckets[0]
		for _, candidate := range buckets {
			if candidate.id == preferred {
				selected = candidate
				break
			}
			if selected.fraction == nil && candidate.fraction != nil {
				selected.fraction = candidate.fraction
			}
			if selected.amount == nil && candidate.amount != nil {
				selected.amount = candidate.amount
			}
			if selected.reset == "" && candidate.reset != "" {
				selected.reset = candidate.reset
			}
		}
		var percent *float64
		if selected.fraction != nil {
			percent = new(math.Round(clampPercent(*selected.fraction * 100)))
		} else if selected.amount != nil && *selected.amount <= 0 {
			percent = new(float64(0))
		} else if selected.reset != "" {
			percent = new(float64(0))
		}
		items = append(items, QuotaItem{Key: groupID, Label: label, Percent: percent, ResetAtMs: resetTimeMs(selected.reset), Format: &QuotaFormat{Kind: "tokens_remaining", TokenType: selected.tokenType, Amount: selected.amount}})
	}
	return items
}

func geminiGroup(modelID string) (string, string, string) {
	for _, definition := range []struct {
		id, label, preferred string
		ids                  []string
	}{{"gemini-2.5-pro", "Gemini 2.5 Pro", "gemini-2.5-pro", []string{"gemini-2.5-pro", "gemini-2.5-pro-preview"}}, {"gemini-2.5-flash", "Gemini 2.5 Flash", "gemini-2.5-flash", []string{"gemini-2.5-flash", "gemini-2.5-flash-preview"}}, {"gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", "gemini-2.5-flash-lite", []string{"gemini-2.5-flash-lite"}}, {"gemini-2.0-flash", "Gemini 2.0 Flash", "gemini-2.0-flash", []string{"gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-2.0-flash-exp"}}, {"gemini-1.5-pro", "Gemini 1.5 Pro", "gemini-1.5-pro", []string{"gemini-1.5-pro", "gemini-1.5-pro-latest"}}, {"gemini-1.5-flash", "Gemini 1.5 Flash", "gemini-1.5-flash", []string{"gemini-1.5-flash", "gemini-1.5-flash-latest"}}} {
		for _, id := range definition.ids {
			if id == modelID {
				return definition.id, definition.label, definition.preferred
			}
		}
	}
	return modelID, modelID, ""
}
func geminiGroupOrder(id string) int {
	for index, key := range []string{"gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"} {
		if key == id {
			return index
		}
	}
	return 1 << 30
}

func buildKimiItems(payload map[string]any) []QuotaItem {
	usage := payload
	_, hasTopUsage := objectAt(payload, "usage")
	_, hasTopLimits := payload["limits"]
	if !hasTopUsage && hasTopLimits && payload["limits"] == nil {
		hasTopLimits = false
	}
	if !hasTopUsage && !hasTopLimits {
		selected := false
		for _, raw := range arrayAt(payload, "usages") {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if !selected || strings.EqualFold(stringAt(item, "scope"), "FEATURE_CODING") {
				usage, selected = item, true
			}
			if strings.EqualFold(stringAt(item, "scope"), "FEATURE_CODING") {
				break
			}
		}
	}
	limits := arrayAt(usage, "limits")
	var fiveDetail, weeklyDetail map[string]any
	for _, raw := range limits {
		limit, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		window, _ := objectAt(limit, "window")
		minutes := kimiWindowMinutes(window)
		detail, _ := objectAt(limit, "detail")
		if minutes == 300 {
			fiveDetail = detail
		}
		if minutes == 7*24*60 {
			weeklyDetail = detail
		}
	}
	if topUsage, ok := objectAt(payload, "usage"); ok {
		weeklyDetail = topUsage
	}
	if detail, ok := objectAt(usage, "detail"); ok {
		weeklyDetail = detail
	}
	items := make([]QuotaItem, 0, 2)
	if item := kimiItem("code_5h", "m_quota.code_5h", fiveHoursSeconds, fiveDetail); item != nil {
		items = append(items, *item)
	}
	if item := kimiItem("code_week", "m_quota.code_weekly", weekSeconds, weeklyDetail); item != nil {
		items = append(items, *item)
	}
	return items
}

func kimiItem(key, label string, window int64, detail map[string]any) *QuotaItem {
	if detail == nil {
		return nil
	}
	limit, used, remaining := numberAt(detail, "limit"), numberAt(detail, "used"), numberAt(detail, "remaining")
	if remaining == nil && limit != nil && used != nil {
		remaining = new(math.Max(0, *limit-*used))
	}
	var percent *float64
	if limit != nil {
		if *limit <= 0 {
			percent = new(float64(0))
		} else if remaining != nil {
			percent = new(math.Round(clampPercent(*remaining / *limit * 100)))
		}
	}
	reset := resetTimeMs(valueAt(detail, "resetTime", "reset_time"))
	if percent == nil && reset == nil {
		return nil
	}
	return &QuotaItem{Key: key, Label: label, Percent: percent, ResetAtMs: reset, WindowSeconds: window, Format: &QuotaFormat{Kind: "tokens_remaining", Amount: remaining, Used: used, Limit: limit}}
}

func kimiWindowMinutes(window map[string]any) int64 {
	if window == nil {
		return 0
	}
	duration := numberAt(window, "duration")
	if duration == nil || *duration <= 0 {
		return 0
	}
	switch strings.ToUpper(stringAt(window, "timeUnit", "time_unit")) {
	case "", "TIME_UNIT_MINUTE":
		return int64(*duration)
	case "TIME_UNIT_HOUR":
		return int64(*duration * 60)
	case "TIME_UNIT_DAY":
		return int64(*duration * 24 * 60)
	case "TIME_UNIT_WEEK":
		return int64(*duration * 7 * 24 * 60)
	}
	return 0
}

func buildKiroItems(payload map[string]any) []QuotaItem {
	items := make([]QuotaItem, 0, 3)
	if subscription := stringAtObject(payload, "subscriptionInfo", "subscriptionTitle"); subscription != "" {
		items = append(items, QuotaItem{Label: "m_quota.subscription", Percent: nil, Meta: subscription})
	}
	breakdown := arrayAt(payload, "usageBreakdownList")
	if len(breakdown) == 0 {
		return items
	}
	usage, ok := breakdown[0].(map[string]any)
	if !ok {
		return items
	}
	limit, used := numberAt(usage, "usageLimitWithPrecision"), numberAt(usage, "currentUsageWithPrecision")
	if limit != nil && used != nil {
		remaining := math.Max(0, *limit-*used)
		percent := new(float64(0))
		if *limit > 0 {
			percent = new(math.Round(remaining / *limit * 100))
		}
		items = append(items, QuotaItem{Label: "m_quota.base_quota", Percent: percent, ResetAtMs: unixSecondsMs(numberAt(usage, "nextDateReset"), numberAt(payload, "nextDateReset")), Format: &QuotaFormat{Kind: "usage_ratio", Used: used, Limit: limit}})
	}
	if trial, ok := objectAt(usage, "freeTrialInfo"); ok {
		limit, used := numberAt(trial, "usageLimitWithPrecision"), numberAt(trial, "currentUsageWithPrecision")
		if limit != nil && used != nil {
			remaining := math.Max(0, *limit-*used)
			percent := new(float64(0))
			if *limit > 0 {
				percent = new(math.Round(remaining / *limit * 100))
			}
			items = append(items, QuotaItem{Label: "m_quota.trial_quota", Percent: percent, ResetAtMs: unixSecondsMs(numberAt(trial, "freeTrialExpiry")), Format: &QuotaFormat{Kind: "trial_usage_ratio", Used: used, Limit: limit, Status: stringAt(trial, "freeTrialStatus")}})
		}
	}
	return items
}

type xaiSummaryModel struct {
	periodType                                                                           string
	usagePercent                                                                         *float64
	periodStart, periodEnd                                                               *int64
	products                                                                             []xaiProduct
	monthlyLimitCents, usedCents, includedUsedCents, onDemandCapCents, onDemandUsedCents *int64
	usedPercent, onDemandUsedPercent                                                     *float64
	billingStart, billingEnd                                                             *int64
}
type xaiProduct struct {
	name  string
	usage *float64
}

func xaiSummary(config map[string]any) *xaiSummaryModel {
	if config == nil {
		return nil
	}
	period, _ := objectAt(config, "currentPeriod", "current_period")
	periodType := strings.ToLower(stringAt(period, "type"))
	if strings.Contains(periodType, "weekly") {
		periodType = "weekly"
	} else if strings.Contains(periodType, "monthly") {
		periodType = "monthly"
	} else {
		periodType = "unknown"
	}
	credit := numberAt(config, "creditUsagePercent", "credit_usage_percent")
	monthlyLimit, used, cap, explicitOnDemand := centsAt(config, "monthlyLimit", "monthly_limit"), centsAt(config, "used"), centsAt(config, "onDemandCap", "on_demand_cap"), centsAt(config, "onDemandUsed", "on_demand_used")
	included := used
	if used != nil && monthlyLimit != nil && *monthlyLimit > 0 && *used > *monthlyLimit {
		included = new(*monthlyLimit)
	}
	derived := (*int64)(nil)
	if used != nil && monthlyLimit != nil {
		derived = new(maxInt64(0, *used-*monthlyLimit))
	}
	onDemand := explicitOnDemand
	if onDemand == nil {
		onDemand = derived
	}
	usedPercent := ratioPercent(included, monthlyLimit)
	onDemandPercent := ratioPercent(onDemand, cap)
	start := resetTimeMs(valueAt(period, "start"))
	end := resetTimeMs(valueAt(period, "end"))
	billingStart := resetTimeMs(valueAt(config, "billingPeriodStart", "billing_period_start"))
	billingEnd := resetTimeMs(valueAt(config, "billingPeriodEnd", "billing_period_end"))
	if start == nil {
		start = billingStart
	}
	if end == nil {
		end = billingEnd
	}
	products := []xaiProduct{}
	for _, raw := range arrayAt(config, "productUsage", "product_usage") {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := stringAt(item, "product")
		if name == "" {
			name = fmt.Sprintf("Product %d", len(products)+1)
		}
		products = append(products, xaiProduct{name, numberAt(item, "usagePercent", "usage_percent")})
	}
	hasWeekly := credit != nil || periodType == "weekly" || len(products) > 0
	hasMonthly := monthlyLimit != nil || used != nil || (!hasWeekly && (cap != nil || billingEnd != nil))
	if !hasWeekly && !hasMonthly {
		return nil
	}
	if hasWeekly && periodType == "unknown" {
		periodType = "weekly"
	}
	if !hasWeekly {
		periodType = "monthly"
	}
	if !hasMonthly {
		billingStart = nil
		billingEnd = nil
	}
	return &xaiSummaryModel{periodType: periodType, usagePercent: credit, periodStart: start, periodEnd: end, products: products, monthlyLimitCents: monthlyLimit, usedCents: used, includedUsedCents: included, onDemandCapCents: cap, onDemandUsedCents: onDemand, usedPercent: usedPercent, onDemandUsedPercent: onDemandPercent, billingStart: billingStart, billingEnd: billingEnd}
}
func mergeXAISummaries(primary, fallback *xaiSummaryModel) *xaiSummaryModel {
	if primary == nil {
		return fallback
	}
	if fallback == nil {
		return primary
	}
	out := *primary
	if out.usagePercent == nil {
		out.usagePercent = fallback.usagePercent
	}
	if out.periodStart == nil {
		out.periodStart = fallback.periodStart
	}
	if out.periodEnd == nil {
		out.periodEnd = fallback.periodEnd
	}
	if len(out.products) == 0 {
		out.products = fallback.products
	}
	if out.monthlyLimitCents == nil {
		out.monthlyLimitCents = fallback.monthlyLimitCents
	}
	if out.usedCents == nil {
		out.usedCents = fallback.usedCents
	}
	if out.includedUsedCents == nil {
		out.includedUsedCents = fallback.includedUsedCents
	}
	if out.onDemandCapCents == nil {
		out.onDemandCapCents = fallback.onDemandCapCents
	}
	if out.onDemandUsedCents == nil {
		out.onDemandUsedCents = fallback.onDemandUsedCents
	}
	if out.usedPercent == nil {
		out.usedPercent = fallback.usedPercent
	}
	if out.onDemandUsedPercent == nil {
		out.onDemandUsedPercent = fallback.onDemandUsedPercent
	}
	if out.billingStart == nil {
		out.billingStart = fallback.billingStart
	}
	if out.billingEnd == nil {
		out.billingEnd = fallback.billingEnd
	}
	if out.periodType == "unknown" {
		out.periodType = fallback.periodType
	}
	return &out
}
func buildXAIItems(summary *xaiSummaryModel) []QuotaItem {
	items := []QuotaItem{}
	if summary.periodType == "weekly" && (summary.usagePercent != nil || summary.periodEnd != nil || len(summary.products) > 0) {
		items = append(items, QuotaItem{Key: "weekly_limit", Label: "xai_quota.weekly_limit", Percent: remainingPercent(summary.usagePercent), Value: percentValue(summary.usagePercent), ResetAtMs: summary.periodEnd, WindowSeconds: weekSeconds, Format: &QuotaFormat{Kind: "date_range", StartAtMs: summary.periodStart, EndAtMs: summary.periodEnd}})
	}
	for _, product := range summary.products {
		items = append(items, QuotaItem{Key: "product:" + product.name, Label: "xai_quota.product_usage_named::" + product.name, Percent: remainingPercent(product.usage), Value: percentValue(product.usage)})
	}
	if summary.onDemandCapCents != nil && *summary.onDemandCapCents > 0 {
		var remaining *int64
		if summary.onDemandUsedCents != nil {
			remaining = new(maxInt64(0, *summary.onDemandCapCents-*summary.onDemandUsedCents))
		}
		items = append(items, QuotaItem{Key: "pay_as_you_go", Label: "xai_quota.pay_as_you_go_label", Percent: remainingPercent(summary.onDemandUsedPercent), Value: percentValue(summary.onDemandUsedPercent), Format: &QuotaFormat{Kind: "usd_ratio", RemainingCents: remaining, TotalCents: summary.onDemandCapCents}})
	} else {
		items = append(items, QuotaItem{Key: "pay_as_you_go", Label: "xai_quota.pay_as_you_go_label", Percent: new(float64(100)), Value: "100%"})
	}
	if summary.monthlyLimitCents != nil || summary.usedCents != nil || summary.billingEnd != nil {
		var remaining *int64
		if summary.monthlyLimitCents != nil && summary.includedUsedCents != nil {
			remaining = new(maxInt64(0, *summary.monthlyLimitCents-*summary.includedUsedCents))
		}
		items = append(items, QuotaItem{Key: "monthly_credits", Label: "xai_quota.monthly_credits", Percent: remainingPercent(summary.usedPercent), Value: percentValue(summary.usedPercent), ResetAtMs: summary.billingEnd, Format: &QuotaFormat{Kind: "usd_ratio", RemainingCents: remaining, TotalCents: summary.monthlyLimitCents}})
	}
	return items
}
func xaiPlanType(cents *int64) string {
	if cents == nil {
		return ""
	}
	if *cents == 15000 {
		return "supergrok"
	}
	if *cents == 150000 {
		return "supergrok-heavy"
	}
	return ""
}

func (s *Service) reconcileCodexUsage(ctx context.Context, auth *coreauth.Auth, payload map[string]any) error {
	plan := normalizeTag(stringAt(payload, "plan_type", "planType"))
	if plan == "" || auth == nil || auth.Metadata == nil {
		return nil
	}
	changed := false
	if strings.TrimSpace(stringAt(auth.Metadata, "type")) == "" {
		auth.Metadata["type"] = "codex"
		changed = true
	}
	current := normalizeTag(stringAt(auth.Metadata, "plan_type", "planType"))
	if current != plan {
		auth.Metadata["plan_type"] = plan
		delete(auth.Metadata, "planType")
		changed = true
	}
	if reconcileExplicitDisplayTags(auth) {
		changed = true
	}
	if !changed {
		return nil
	}
	auth.UpdatedAt = time.Now()
	_, err := s.authManager.Update(ctx, auth)
	return err
}

// ReconcileCodexWhamUsagePlan retains plan metadata for the temporary generic
// relay while keeping the logic owned by the Codex quota backend.
func (s *Service) ReconcileCodexWhamUsagePlan(ctx context.Context, auth *coreauth.Auth, parsedURL *url.URL, status int, response []byte) error {
	if status < http.StatusOK || status >= http.StatusMultipleChoices || !isCodexWhamUsageURL(parsedURL) || auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil
	}
	payload, ok := decodeObject(response)
	if !ok {
		return nil
	}
	return s.reconcileCodexUsage(ctx, auth, payload)
}
func isCodexWhamUsageURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	return strings.TrimRight(parsed.EscapedPath(), "/") == "/backend-api/wham/usage"
}
func reconcileExplicitDisplayTags(auth *coreauth.Auth) bool {
	if auth == nil || auth.Metadata == nil {
		return false
	}
	current, present := managementauthfiles.MetadataStringSliceWithPresence(auth.Metadata, "display_tags")
	if !present {
		return false
	}
	next := managementauthfiles.BuildTagPayload(auth).DisplayTags
	if normalizedStringSlicesEqual(current, next) {
		return false
	}
	auth.Metadata["display_tags"] = next
	return true
}
func normalizedStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if managementauthfiles.NormalizeTagValue(left[i]) != managementauthfiles.NormalizeTagValue(right[i]) {
			return false
		}
	}
	return true
}

func codexResetCreditCount(payload map[string]any) int {
	credits, _ := objectAt(payload, "rate_limit_reset_credits", "rateLimitResetCredits")
	if count := numberAt(credits, "available_count", "availableCount"); count != nil {
		return maxInt(0, int(math.Floor(*count)))
	}
	return 0
}
func codexResetCreditExpirations(body []byte) []string {
	var input any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&input) != nil {
		return nil
	}
	list := findCodexCredits(input, 0)
	values := []string{}
	seen := map[string]struct{}{}
	for _, raw := range list {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		value := stringAt(item, "expires_at", "expiresAt")
		if value != "" {
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				values = append(values, value)
			}
		}
	}
	sort.SliceStable(values, func(i, j int) bool {
		left, leftErr := time.Parse(time.RFC3339, values[i])
		right, rightErr := time.Parse(time.RFC3339, values[j])
		if leftErr != nil && rightErr != nil {
			return false
		}
		if leftErr != nil {
			return false
		}
		if rightErr != nil {
			return true
		}
		return left.Before(right)
	})
	return values
}
func findCodexCredits(input any, depth int) []any {
	if list, ok := input.([]any); ok {
		return list
	}
	object, ok := input.(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range []string{"credits", "rate_limit_reset_credits", "rateLimitResetCredits", "items", "data"} {
		if list, ok := object[key].([]any); ok && len(list) > 0 {
			return list
		}
		if depth < 1 {
			if nested := findCodexCredits(object[key], depth+1); len(nested) > 0 {
				return nested
			}
		}
	}
	return nil
}
func codexResetAt(window map[string]any) *int64 {
	if value := numberAt(window, "reset_at", "resetAt"); value != nil && *value > 0 {
		return unixSecondsMs(value)
	}
	if after := numberAt(window, "reset_after_seconds", "resetAfterSeconds"); after != nil && *after > 0 {
		return new(time.Now().Add(time.Duration(*after) * time.Second).UnixMilli())
	}
	return nil
}

func decodeObject(body []byte) (map[string]any, bool) {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || value == nil {
		return nil, false
	}
	return value, true
}
func objectAt(input map[string]any, keys ...string) (map[string]any, bool) {
	for _, key := range keys {
		if value, ok := input[key].(map[string]any); ok && value != nil {
			return value, true
		}
	}
	return nil, false
}
func arrayAt(input map[string]any, keys ...string) []any {
	for _, key := range keys {
		if value, ok := input[key].([]any); ok {
			return value
		}
	}
	return nil
}
func valueAt(input map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := input[key]; ok {
			return value
		}
	}
	return nil
}
func stringAt(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := input[key]; ok {
			switch typed := value.(type) {
			case string:
				if out := strings.TrimSpace(typed); out != "" {
					return out
				}
			case json.Number:
				return typed.String()
			case float64:
				return fmt.Sprintf("%v", typed)
			case float32:
				return fmt.Sprintf("%v", typed)
			case int:
				return fmt.Sprintf("%d", typed)
			case int64:
				return fmt.Sprintf("%d", typed)
			}
		}
	}
	return ""
}
func stringAtObject(input map[string]any, parent, child string) string {
	if object, ok := objectAt(input, parent); ok {
		return stringAt(object, child)
	}
	return ""
}
func numberAt(input map[string]any, keys ...string) *float64 {
	for _, key := range keys {
		if value, ok := input[key]; ok {
			if out, ok := numberValue(value); ok {
				return new(out)
			}
		}
	}
	return nil
}
func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		out, err := typed.Float64()
		return out, err == nil && !math.IsNaN(out) && !math.IsInf(out, 0)
	case float64:
		return typed, !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case float32:
		out := float64(typed)
		return out, !math.IsNaN(out) && !math.IsInf(out, 0)
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case string:
		out, err := json.Number(strings.TrimSpace(typed)).Float64()
		return out, err == nil && !math.IsNaN(out) && !math.IsInf(out, 0)
	}
	return 0, false
}
func quotaFraction(value any) (float64, bool) {
	if text, ok := value.(string); ok && strings.HasSuffix(strings.TrimSpace(text), "%") {
		out, ok := numberValue(strings.TrimSuffix(strings.TrimSpace(text), "%"))
		return out / 100, ok
	}
	return numberValue(value)
}
func boolAt(input map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := input[key].(bool); ok {
			return value
		}
	}
	return false
}
func boolAtDefault(input map[string]any, defaultValue bool, keys ...string) bool {
	for _, key := range keys {
		if value, ok := input[key].(bool); ok {
			return value
		}
	}
	return defaultValue
}
func resetTimeMs(value any) *int64 {
	raw := stringValueAny(value)
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return new(parsed.UnixMilli())
		}
	}
	return nil
}
func stringValueAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return fmt.Sprintf("%v", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case int:
		return fmt.Sprintf("%d", typed)
	}
	return ""
}
func unixSecondsMs(values ...*float64) *int64 {
	for _, value := range values {
		if value != nil && *value > 0 {
			return new(int64(math.Round(*value * 1000)))
		}
	}
	return nil
}
func remainingPercent(used *float64) *float64 {
	if used == nil {
		return new(float64(100))
	}
	return new(math.Round(clampPercent(100 - clampPercent(*used))))
}
func remainingPercentNullable(used *float64) *float64 {
	if used == nil {
		return nil
	}
	return new(math.Round(clampPercent(100 - clampPercent(*used))))
}
func percentValue(used *float64) string {
	if percent := remainingPercent(used); percent != nil {
		return fmt.Sprintf("%.0f%%", *percent)
	}
	return ""
}
func ratioPercent(numerator, denominator *int64) *float64 {
	if numerator == nil || denominator == nil || *denominator <= 0 {
		return nil
	}
	return new(math.Round(float64(*numerator) / float64(*denominator) * 100))
}
func centsAt(input map[string]any, keys ...string) *int64 {
	for _, key := range keys {
		value, ok := input[key]
		if !ok || value == nil {
			continue
		}
		if object, ok := value.(map[string]any); ok {
			value = valueAt(object, "val")
		}
		if number, ok := numberValue(value); ok {
			return new(int64(number))
		}
	}
	return nil
}
func clampPercent(value float64) float64 { return math.Max(0, math.Min(100, value)) }
func normalizeTag(value string) string   { return managementauthfiles.NormalizeTagValue(value) }
func normalizedKeyPart(value string) string {
	var builder strings.Builder
	underscore := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			underscore = false
		} else if !underscore && builder.Len() > 0 {
			builder.WriteByte('_')
			underscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}
func stringSet(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
func int64Number(value *float64) int64 {
	if value == nil {
		return 0
	}
	return int64(*value)
}
