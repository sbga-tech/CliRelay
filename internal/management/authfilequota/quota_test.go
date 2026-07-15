package authfilequota

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type quotaTestStore struct {
	mu    sync.Mutex
	saves []*coreauth.Auth
}

func (s *quotaTestStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (s *quotaTestStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves = append(s.saves, auth.Clone())
	return auth.ID, nil
}
func (s *quotaTestStore) Delete(context.Context, string) error { return nil }

func registerQuotaTestAuth(t *testing.T, manager *coreauth.Manager, auth *coreauth.Auth) *coreauth.Auth {
	t.Helper()
	registered, err := manager.Register(context.Background(), auth)
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}
	return registered
}

func quotaMillis(t *testing.T, value string) *int64 {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse timestamp %q: %v", value, err)
	}
	out := parsed.UnixMilli()
	return &out
}

func assertQuotaResult(t *testing.T, got, want QuotaResult) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Fatalf("quota result = %s, want %s", gotJSON, wantJSON)
	}
}

func assertQuotaJSONBody(t *testing.T, body string, want any) {
	t.Helper()
	var got any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode request body %q: %v", body, err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("encode expected request body: %v", err)
	}
	var expected any
	if err := json.Unmarshal(wantJSON, &expected); err != nil {
		t.Fatalf("decode expected request body: %v", err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("request body = %#v, want %#v", got, expected)
	}
}

func TestFetchProviderFixtures(t *testing.T) {
	reset := "2026-01-02T03:04:05Z"
	weeklyStart := "2026-01-04T00:00:00Z"
	weeklyEnd := "2026-01-11T00:00:00Z"
	monthlyEnd := "2026-02-01T00:00:00Z"
	now := time.Now()
	antigravityTimestamp := now.UnixMilli()
	kimiExpiry := now.Add(time.Hour).UTC().Format(time.RFC3339)

	tests := []struct {
		name      string
		auth      *coreauth.Auth
		deps      func(string) Dependencies
		serve     func(*testing.T, http.ResponseWriter, *http.Request)
		want      QuotaResult
		verifyReq func(*testing.T, []quotaObservedRequest)
	}{
		{
			name: "antigravity",
			auth: &coreauth.Auth{Provider: "antigravity", FileName: "antigravity.json", Metadata: map[string]any{"access_token": "antigravity-token", "project_id": "project-42", "expires_in": int64(3600), "timestamp": antigravityTimestamp}},
			deps: func(base string) Dependencies {
				return Dependencies{Endpoints: Endpoints{Antigravity: []string{base + "/antigravity"}}}
			},
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/antigravity" || r.Method != http.MethodPost {
					t.Fatalf("antigravity request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer antigravity-token" {
					t.Fatalf("antigravity authorization = %q", got)
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Fatalf("antigravity content type = %q", got)
				}
				_, _ = io.WriteString(w, `{"models":{"gemini-3-pro-low":{"quotaInfo":{"remainingFraction":0.75,"resetTime":"2026-01-02T03:04:05Z"}},"gemini-3-flash":{"quotaInfo":{"remainingFraction":0.5,"resetTime":"2026-01-02T03:04:05Z"}}}}`)
			},
			want: QuotaResult{Provider: "antigravity", Items: []QuotaItem{
				{Key: "provider:gemini3-pro", Label: "antigravity_quota.gemini3_pro", Percent: new(float64(75)), ResetAtMs: quotaMillis(t, reset)},
				{Key: "provider:gemini3-flash", Label: "antigravity_quota.gemini3_flash", Percent: new(float64(50)), ResetAtMs: quotaMillis(t, reset)},
			}},
			verifyReq: func(t *testing.T, requests []quotaObservedRequest) {
				if len(requests) != 1 {
					t.Fatalf("antigravity requests = %d, want 1", len(requests))
				}
				assertQuotaJSONBody(t, requests[0].body, map[string]string{"project": "project-42"})
			},
		},
		{
			name: "claude oauth",
			auth: &coreauth.Auth{Provider: "anthropic", FileName: "claude.json", Metadata: map[string]any{"access_token": "claude-token"}},
			deps: func(base string) Dependencies {
				return Dependencies{Endpoints: Endpoints{ClaudeUsage: base + "/claude"}}
			},
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/claude" || r.Method != http.MethodGet {
					t.Fatalf("claude request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer claude-token" {
					t.Fatalf("claude authorization = %q", got)
				}
				if got := r.Header.Get("anthropic-beta"); got != "oauth-2025-04-20" {
					t.Fatalf("claude beta header = %q", got)
				}
				_, _ = io.WriteString(w, `{"five_hour":{"utilization":25,"resets_at":"2026-01-02T03:04:05Z"},"extra_usage":{"is_enabled":true,"utilization":20,"used_credits":"10","monthly_limit":"50"}}`)
			},
			want: QuotaResult{Provider: "claude", Items: []QuotaItem{
				{Key: "five_hour", Label: "claude_quota.five_hour", Percent: new(float64(75)), ResetAtMs: quotaMillis(t, reset)},
				{Key: "extra_usage", Label: "claude_quota.extra_usage_label", Percent: new(float64(80)), Meta: "10 / 50 credits"},
			}},
		},
		{
			name: "codex",
			auth: &coreauth.Auth{Provider: "codex", FileName: "codex.json", Metadata: map[string]any{"access_token": "codex-token", "chatgpt_account_id": "account-123"}},
			deps: func(base string) Dependencies {
				return Dependencies{Endpoints: Endpoints{CodexUsage: base + "/backend-api/wham/usage", CodexResetCredits: base + "/backend-api/wham/rate-limit-reset-credits"}}
			},
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer codex-token" {
					t.Fatalf("codex authorization = %q", got)
				}
				if got := r.Header.Get("Chatgpt-Account-Id"); got != "account-123" {
					t.Fatalf("codex account header = %q", got)
				}
				switch r.URL.Path {
				case "/backend-api/wham/usage":
					if r.Method != http.MethodGet {
						t.Fatalf("codex usage method = %s", r.Method)
					}
					_, _ = io.WriteString(w, `{"plan_type":"Pro","rate_limit":{"primary_window":{"limit_window_seconds":18000,"used_percent":25,"reset_at":1767225600},"secondary_window":{"limit_window_seconds":604800,"used_percent":50,"reset_at":1767830400}},"rate_limit_reset_credits":{"available_count":2}}`)
				case "/backend-api/wham/rate-limit-reset-credits":
					if r.Method != http.MethodGet {
						t.Fatalf("codex reset details method = %s", r.Method)
					}
					_, _ = io.WriteString(w, `{"credits":[{"expires_at":"2026-01-03T00:00:00Z"},{"expires_at":"2026-01-02T00:00:00Z"}]}`)
				default:
					t.Fatalf("unexpected codex target %s", r.URL.Path)
				}
			},
			want: QuotaResult{Provider: "codex", Items: []QuotaItem{
				{Key: "code_5h", Label: "m_quota.code_5h", Percent: new(float64(75)), ResetAtMs: new(int64(1767225600000)), WindowSeconds: 18000},
				{Key: "code_week", Label: "m_quota.code_weekly", Percent: new(float64(50)), ResetAtMs: new(int64(1767830400000)), WindowSeconds: 604800},
			}, PlanType: new("pro"), ResetCreditCount: new(2), ResetCreditExpirations: []string{"2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"}},
		},
		{
			name: "gemini cli",
			auth: &coreauth.Auth{Provider: "gemini-cli", FileName: "gemini.json", Metadata: map[string]any{"access_token": "gemini-token", "project_id": "project-123"}},
			deps: func(base string) Dependencies {
				return Dependencies{Endpoints: Endpoints{GeminiCLIQuota: base + "/gemini"}}
			},
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/gemini" || r.Method != http.MethodPost {
					t.Fatalf("gemini request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer gemini-token" {
					t.Fatalf("gemini authorization = %q", got)
				}
				_, _ = io.WriteString(w, `{"buckets":[{"modelId":"projects/project-123/locations/us/models/gemini-2.5-pro","tokenType":"INPUT_TOKENS","remainingFraction":0.4,"remainingAmount":12345,"resetTime":"2026-01-02T03:04:05Z"}]}`)
			},
			want: QuotaResult{Provider: "gemini-cli", Items: []QuotaItem{{
				Key: "gemini-2.5-pro", Label: "Gemini 2.5 Pro", Percent: new(float64(40)), ResetAtMs: quotaMillis(t, reset),
				Format: &QuotaFormat{Kind: "tokens_remaining", TokenType: "INPUT_TOKENS", Amount: new(float64(12345))},
			}}},
			verifyReq: func(t *testing.T, requests []quotaObservedRequest) {
				if len(requests) != 1 {
					t.Fatalf("gemini requests = %d, want 1", len(requests))
				}
				assertQuotaJSONBody(t, requests[0].body, map[string]string{"project": "project-123"})
			},
		},
		{
			name: "kimi",
			auth: &coreauth.Auth{Provider: "kimi", FileName: "kimi.json", Metadata: map[string]any{"access_token": "kimi-token", "expired": kimiExpiry}},
			deps: func(base string) Dependencies { return Dependencies{Endpoints: Endpoints{KimiUsage: base + "/kimi"}} },
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/kimi" || r.Method != http.MethodGet {
					t.Fatalf("kimi request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer kimi-token" {
					t.Fatalf("kimi authorization = %q", got)
				}
				_, _ = io.WriteString(w, `{"usages":[{"scope":"FEATURE_CODING","limits":[{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":1000,"used":250,"resetTime":"2026-01-02T03:04:05Z"}},{"window":{"duration":7,"timeUnit":"TIME_UNIT_DAY"},"detail":{"limit":2000,"used":500,"resetTime":"2026-01-03T03:04:05Z"}}]}]}`)
			},
			want: QuotaResult{Provider: "kimi", Items: []QuotaItem{
				{Key: "code_5h", Label: "m_quota.code_5h", Percent: new(float64(75)), ResetAtMs: quotaMillis(t, reset), WindowSeconds: 18000, Format: &QuotaFormat{Kind: "tokens_remaining", Amount: new(float64(750)), Used: new(float64(250)), Limit: new(float64(1000))}},
				{Key: "code_week", Label: "m_quota.code_weekly", Percent: new(float64(75)), ResetAtMs: quotaMillis(t, "2026-01-03T03:04:05Z"), WindowSeconds: 604800, Format: &QuotaFormat{Kind: "tokens_remaining", Amount: new(float64(1500)), Used: new(float64(500)), Limit: new(float64(2000))}},
			}},
		},
		{
			name: "kiro",
			auth: &coreauth.Auth{Provider: "kiro", FileName: "kiro.json", Metadata: map[string]any{"access_token": "kiro-token"}},
			deps: func(base string) Dependencies { return Dependencies{Endpoints: Endpoints{KiroQuota: base + "/kiro"}} },
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/kiro" || r.Method != http.MethodPost {
					t.Fatalf("kiro request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("x-amz-target"); got != "AmazonCodeWhispererService.GetUsageLimits" {
					t.Fatalf("kiro target header = %q", got)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer kiro-token" {
					t.Fatalf("kiro authorization = %q", got)
				}
				_, _ = io.WriteString(w, `{"subscriptionInfo":{"subscriptionTitle":"Kiro Pro"},"usageBreakdownList":[{"usageLimitWithPrecision":100,"currentUsageWithPrecision":25,"nextDateReset":1767225600,"freeTrialInfo":{"usageLimitWithPrecision":10,"currentUsageWithPrecision":4,"freeTrialExpiry":1767830400,"freeTrialStatus":"ACTIVE"}}]}`)
			},
			want: QuotaResult{Provider: "kiro", Items: []QuotaItem{
				{Label: "m_quota.subscription", Percent: nil, Meta: "Kiro Pro"},
				{Label: "m_quota.base_quota", Percent: new(float64(75)), ResetAtMs: new(int64(1767225600000)), Format: &QuotaFormat{Kind: "usage_ratio", Used: new(float64(25)), Limit: new(float64(100))}},
				{Label: "m_quota.trial_quota", Percent: new(float64(60)), ResetAtMs: new(int64(1767830400000)), Format: &QuotaFormat{Kind: "trial_usage_ratio", Used: new(float64(4)), Limit: new(float64(10)), Status: "ACTIVE"}},
			}},
			verifyReq: func(t *testing.T, requests []quotaObservedRequest) {
				if len(requests) != 1 {
					t.Fatalf("kiro requests = %d, want 1", len(requests))
				}
				assertQuotaJSONBody(t, requests[0].body, map[string]string{"origin": "AI_EDITOR", "resourceType": "AGENTIC_REQUEST"})
			},
		},
		{
			name: "xai",
			auth: &coreauth.Auth{Provider: "grok", FileName: "xai.json", Metadata: map[string]any{"access_token": "xai-token", "sub": "user-123"}},
			deps: func(base string) Dependencies {
				return Dependencies{Endpoints: Endpoints{XAIWeeklyBilling: base + "/xai/weekly", XAIMonthlyBilling: base + "/xai/monthly"}}
			},
			serve: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Fatalf("xai method = %s", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer xai-token" {
					t.Fatalf("xai authorization = %q", got)
				}
				if got := r.Header.Get("x-userid"); got != "user-123" {
					t.Fatalf("xai user header = %q", got)
				}
				switch r.URL.Path {
				case "/xai/weekly":
					_, _ = io.WriteString(w, `{"config":{"currentPeriod":{"type":"WEEKLY","start":"2026-01-04T00:00:00Z","end":"2026-01-11T00:00:00Z"},"creditUsagePercent":25,"productUsage":[{"product":"Grok 4","usagePercent":40}]}}`)
				case "/xai/monthly":
					_, _ = io.WriteString(w, `{"config":{"monthlyLimit":15000,"used":5000,"onDemandCap":5000,"onDemandUsed":1000,"billingPeriodStart":"2026-01-01T00:00:00Z","billingPeriodEnd":"2026-02-01T00:00:00Z"}}`)
				default:
					t.Fatalf("unexpected xai target %s", r.URL.Path)
				}
			},
			want: QuotaResult{Provider: "xai", PlanType: new("supergrok"), Items: []QuotaItem{
				{Key: "weekly_limit", Label: "xai_quota.weekly_limit", Percent: new(float64(75)), Value: "75%", ResetAtMs: quotaMillis(t, weeklyEnd), WindowSeconds: 604800, Format: &QuotaFormat{Kind: "date_range", StartAtMs: quotaMillis(t, weeklyStart), EndAtMs: quotaMillis(t, weeklyEnd)}},
				{Key: "product:Grok 4", Label: "xai_quota.product_usage_named::Grok 4", Percent: new(float64(60)), Value: "60%"},
				{Key: "pay_as_you_go", Label: "xai_quota.pay_as_you_go_label", Percent: new(float64(80)), Value: "80%", Format: &QuotaFormat{Kind: "usd_ratio", RemainingCents: new(int64(4000)), TotalCents: new(int64(5000))}},
				{Key: "monthly_credits", Label: "xai_quota.monthly_credits", Percent: new(float64(67)), Value: "67%", ResetAtMs: quotaMillis(t, monthlyEnd), Format: &QuotaFormat{Kind: "usd_ratio", RemainingCents: new(int64(10000)), TotalCents: new(int64(15000))}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestsMu sync.Mutex
			requests := make([]quotaObservedRequest, 0, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
					return
				}
				requestsMu.Lock()
				requests = append(requests, quotaObservedRequest{method: r.Method, path: r.URL.Path, body: string(body)})
				requestsMu.Unlock()
				tt.serve(t, w, r)
			}))
			defer server.Close()

			store := &quotaTestStore{}
			manager := coreauth.NewManager(store, nil, nil)
			auth := tt.auth.Clone()
			auth.ID, auth.TenantID = "auth-"+tt.name, "tenant-a"
			auth = registerQuotaTestAuth(t, manager, auth)
			got, err := NewForTenant("tenant-a", nil, manager, tt.deps(server.URL)).Fetch(context.Background(), auth.Index)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			assertQuotaResult(t, got, tt.want)
			if tt.verifyReq != nil {
				requestsMu.Lock()
				observed := append([]quotaObservedRequest(nil), requests...)
				requestsMu.Unlock()
				tt.verifyReq(t, observed)
			}
		})
	}
}

type quotaObservedRequest struct {
	method string
	path   string
	body   string
}

func TestFetchCodexUsesFixedEndpointAndReconcilesPlan(t *testing.T) {
	var usageCalls, resetCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backend-api/wham/usage":
			usageCalls++
			if r.Method != http.MethodGet {
				t.Errorf("usage method = %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer codex-token" {
				t.Errorf("authorization = %q", got)
			}
			if got := r.Header.Get("Chatgpt-Account-Id"); got != "account-123" {
				t.Errorf("account header = %q", got)
			}
			_, _ = io.WriteString(w, `{"plan_type":"Pro","rate_limit":{"primary_window":{"limit_window_seconds":18000,"used_percent":25}},"rate_limit_reset_credits":{"available_count":1}}`)
		case "/backend-api/wham/rate-limit-reset-credits":
			resetCalls++
			_, _ = io.WriteString(w, `{"credits":[{"expires_at":"2026-01-02T03:04:05Z"}]}`)
		default:
			t.Errorf("unexpected target %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store := &quotaTestStore{}
	manager := coreauth.NewManager(store, nil, nil)
	auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{
		ID: "codex-auth", TenantID: "tenant-a", Provider: "codex", FileName: "codex.json",
		Metadata: map[string]any{
			"access_token": "codex-token", "chatgpt_account_id": "account-123", "display_tags": []string{"codex", "plus", "release"},
		},
	})
	service := NewForTenant("tenant-a", nil, manager, Dependencies{Endpoints: Endpoints{
		CodexUsage: server.URL + "/backend-api/wham/usage", CodexResetCredits: server.URL + "/backend-api/wham/rate-limit-reset-credits",
	}})

	result, err := service.Fetch(context.Background(), auth.Index)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.Provider != "codex" || usageCalls != 1 || resetCalls != 1 {
		t.Fatalf("unexpected result/provider calls: %#v usage=%d reset=%d", result, usageCalls, resetCalls)
	}
	if result.PlanType == nil || *result.PlanType != "pro" {
		t.Fatalf("plan type = %#v", result.PlanType)
	}
	if result.ResetCreditCount == nil || *result.ResetCreditCount != 1 {
		t.Fatalf("reset count = %#v", result.ResetCreditCount)
	}
	if len(result.ResetCreditExpirations) != 1 {
		t.Fatalf("expirations = %#v", result.ResetCreditExpirations)
	}
	stored := service.AuthByIndex(auth.Index)
	if got := stringAt(stored.Metadata, "plan_type"); got != "pro" {
		t.Fatalf("persisted plan = %q", got)
	}
	if got := stringAt(stored.Metadata, "type"); got != "codex" {
		t.Fatalf("persisted type = %q", got)
	}
	if got := stored.Metadata["display_tags"]; !reflect.DeepEqual(got, []string{"codex", "pro"}) {
		t.Fatalf("persisted display tags = %#v, want [codex pro]", got)
	}
	if stored.UpdatedAt.IsZero() {
		t.Fatal("expected plan reconciliation to update UpdatedAt")
	}
}

func TestConsumeCodexResetCreditGeneratesServerUUID(t *testing.T) {
	var redeemID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/wham/rate-limit-reset-credits/consume" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var payload struct {
			RedeemRequestID string `json:"redeem_request_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		redeemID = payload.RedeemRequestID
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	manager := coreauth.NewManager(&quotaTestStore{}, nil, nil)
	auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "codex-reset", TenantID: "tenant-a", Provider: "codex", FileName: "codex-reset.json", Metadata: map[string]any{"access_token": "token"}})
	service := NewForTenant("tenant-a", nil, manager, Dependencies{Endpoints: Endpoints{CodexConsumeResetCredit: server.URL + "/backend-api/wham/rate-limit-reset-credits/consume"}})
	if err := service.ConsumeCodexResetCredit(context.Background(), auth.Index); err != nil {
		t.Fatalf("ConsumeCodexResetCredit: %v", err)
	}
	if _, err := uuid.Parse(redeemID); err != nil {
		t.Fatalf("redeem_request_id %q is not a UUID: %v", redeemID, err)
	}
}

func TestFetchAntigravityFallsBackToNextFixedEndpoint(t *testing.T) {
	var firstCalls, secondCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstCalls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/fallback" {
			t.Errorf("fallback request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"models":{"gemini-3-pro-low":{"quotaInfo":{"remainingFraction":0.5}}}}`)
	}))
	defer second.Close()

	manager := coreauth.NewManager(&quotaTestStore{}, nil, nil)
	auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "fallback", TenantID: "tenant-a", Provider: "antigravity", FileName: "fallback.json", Metadata: map[string]any{"access_token": "token", "expires_in": int64(3600), "timestamp": time.Now().UnixMilli()}})
	result, err := NewForTenant("tenant-a", nil, manager, Dependencies{Endpoints: Endpoints{Antigravity: []string{first.URL + "/primary", second.URL + "/fallback"}}}).Fetch(context.Background(), auth.Index)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("fallback calls = %d / %d, want 1 / 1", firstCalls.Load(), secondCalls.Load())
	}
	assertQuotaResult(t, result, QuotaResult{Provider: "antigravity", Items: []QuotaItem{{Key: "provider:gemini3-pro", Label: "antigravity_quota.gemini3_pro", Percent: new(float64(50))}}})
}

func TestFetchXAIPartialSuccessReturnsAvailableQuota(t *testing.T) {
	var weeklyCalls, monthlyCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/weekly":
			weeklyCalls.Add(1)
			_, _ = io.WriteString(w, `{"config":{"currentPeriod":{"type":"WEEKLY","end":"2026-01-11T00:00:00Z"},"creditUsagePercent":25}}`)
		case "/monthly":
			monthlyCalls.Add(1)
			http.Error(w, "hidden upstream failure", http.StatusBadGateway)
		default:
			t.Errorf("unexpected target %s", r.URL.Path)
		}
	}))
	defer server.Close()

	manager := coreauth.NewManager(&quotaTestStore{}, nil, nil)
	auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "xai-partial", TenantID: "tenant-a", Provider: "xai", FileName: "xai-partial.json", Metadata: map[string]any{"access_token": "token"}})
	result, err := NewForTenant("tenant-a", nil, manager, Dependencies{Endpoints: Endpoints{XAIWeeklyBilling: server.URL + "/weekly", XAIMonthlyBilling: server.URL + "/monthly"}}).Fetch(context.Background(), auth.Index)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if weeklyCalls.Load() != 1 || monthlyCalls.Load() != 1 {
		t.Fatalf("xai calls = %d / %d, want 1 / 1", weeklyCalls.Load(), monthlyCalls.Load())
	}
	assertQuotaResult(t, result, QuotaResult{Provider: "xai", Items: []QuotaItem{
		{Key: "weekly_limit", Label: "xai_quota.weekly_limit", Percent: new(float64(75)), Value: "75%", ResetAtMs: quotaMillis(t, "2026-01-11T00:00:00Z"), WindowSeconds: 604800, Format: &QuotaFormat{Kind: "date_range", EndAtMs: quotaMillis(t, "2026-01-11T00:00:00Z")}},
		{Key: "pay_as_you_go", Label: "xai_quota.pay_as_you_go_label", Percent: new(float64(100)), Value: "100%"},
	}})
}

func TestFetchRejectsUnsupportedMissingAndCrossTenantAuth(t *testing.T) {
	manager := coreauth.NewManager(&quotaTestStore{}, nil, nil)
	unknown := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "unknown", TenantID: "tenant-a", Provider: "other", FileName: "unknown.json", Metadata: map[string]any{"access_token": "token"}})
	claudeKey := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "claude-key", TenantID: "tenant-a", Provider: "claude", FileName: "claude-key.json", Metadata: map[string]any{"api_key": "sk-secret"}})
	claudeKind := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "claude-kind", TenantID: "tenant-a", Provider: "claude", FileName: "claude-kind.json", Metadata: map[string]any{"access_token": "token", "auth_kind": "api_key"}})
	missing := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "missing", TenantID: "tenant-a", Provider: "claude", FileName: "missing.json"})

	service := NewForTenant("tenant-a", nil, manager, Dependencies{})
	for _, tt := range []struct {
		name  string
		index string
		want  error
	}{
		{name: "unknown provider", index: unknown.Index, want: ErrUnsupportedProvider},
		{name: "claude api key field", index: claudeKey.Index, want: ErrUnsupportedProvider},
		{name: "claude api key kind", index: claudeKind.Index, want: ErrUnsupportedProvider},
		{name: "missing credential", index: missing.Index, want: ErrAuthTokenNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Fetch(context.Background(), tt.index)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Fetch error = %v, want %v", err, tt.want)
			}
		})
	}

	if _, err := NewForTenant("tenant-b", nil, manager, Dependencies{}).Fetch(context.Background(), missing.Index); !errors.Is(err, ErrAuthNotFound) {
		t.Fatalf("cross-tenant Fetch error = %v, want ErrAuthNotFound", err)
	}
}

func TestQuotaAndOAuthResponsesAreBounded(t *testing.T) {
	t.Run("quota response cap", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", (4<<20)+1))
		}))
		defer server.Close()
		manager := coreauth.NewManager(&quotaTestStore{}, nil, nil)
		auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "large-quota", TenantID: "tenant-a", Provider: "claude", FileName: "large-quota.json", Metadata: map[string]any{"access_token": "token"}})
		_, err := NewForTenant("tenant-a", nil, manager, Dependencies{Endpoints: Endpoints{ClaudeUsage: server.URL}}).Fetch(context.Background(), auth.Index)
		if !errors.Is(err, ErrQuotaRequest) {
			t.Fatalf("Fetch error = %v, want ErrQuotaRequest", err)
		}
	})

	t.Run("oauth token response cap", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", (64<<10)+1))
		}))
		defer server.Close()
		manager := coreauth.NewManager(&quotaTestStore{}, nil, nil)
		auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "large-oauth", TenantID: "tenant-a", Provider: "xai", FileName: "large-oauth.json", Metadata: map[string]any{"refresh_token": "refresh", "token_endpoint": server.URL}})
		_, err := NewForTenant("tenant-a", nil, manager, Dependencies{Endpoints: Endpoints{XAIWeeklyBilling: server.URL + "/weekly", XAIMonthlyBilling: server.URL + "/monthly"}}).Fetch(context.Background(), auth.Index)
		if !errors.Is(err, ErrTokenRefresh) {
			t.Fatalf("Fetch error = %v, want ErrTokenRefresh", err)
		}
	})
}

type quotaClaudeRefresher struct {
	gotRefresh string
	token      *claudeauth.ClaudeTokenData
	err        error
}

func (r *quotaClaudeRefresher) RefreshTokens(_ context.Context, refreshToken string) (*claudeauth.ClaudeTokenData, error) {
	r.gotRefresh = refreshToken
	return r.token, r.err
}

func TestClaudeRefreshPersistsToken(t *testing.T) {
	store := &quotaTestStore{}
	manager := coreauth.NewManager(store, nil, nil)
	auth := registerQuotaTestAuth(t, manager, &coreauth.Auth{ID: "refresh", TenantID: "tenant-a", Provider: "claude", FileName: "refresh.json", Metadata: map[string]any{
		"access_token": "expired", "refresh_token": "refresh-token", "expired": "2000-01-01T00:00:00Z",
	}})
	refresher := &quotaClaudeRefresher{token: &claudeauth.ClaudeTokenData{AccessToken: "fresh", RefreshToken: "next-refresh", Email: "user@example.test", Expire: "2030-01-01T00:00:00Z"}}
	service := NewForTenant("tenant-a", nil, manager, Dependencies{NewClaudeOAuthRefresher: func(*config.Config) ClaudeOAuthRefresher { return refresher }})

	token, err := service.ResolveTokenForAuth(context.Background(), service.AuthByIndex(auth.Index))
	if err != nil {
		t.Fatalf("ResolveTokenForAuth: %v", err)
	}
	if token != "fresh" || refresher.gotRefresh != "refresh-token" {
		t.Fatalf("refresh token/result = %q / %q", refresher.gotRefresh, token)
	}
	stored := service.AuthByIndex(auth.Index)
	if got := stringAt(stored.Metadata, "access_token"); got != "fresh" {
		t.Fatalf("persisted access token = %q", got)
	}
	if got := stringAt(stored.Metadata, "refresh_token"); got != "next-refresh" {
		t.Fatalf("persisted refresh token = %q", got)
	}
	if stored.LastRefreshedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Fatalf("refresh timestamps = %v / %v", stored.LastRefreshedAt, stored.UpdatedAt)
	}
	store.mu.Lock()
	saveCount := len(store.saves)
	store.mu.Unlock()
	if saveCount < 2 {
		t.Fatalf("saved auth records = %d, want register and refreshed update", saveCount)
	}
}

func TestQuotaTransportProxyPrecedence(t *testing.T) {
	requestURL, err := url.Parse("https://quota.example/path")
	if err != nil {
		t.Fatalf("parse request URL: %v", err)
	}
	for _, tt := range []struct {
		name string
		cfg  *config.Config
		auth *coreauth.Auth
		want string
	}{
		{
			name: "proxy id overrides auth and config fallback",
			cfg:  &config.Config{SDKConfig: config.SDKConfig{ProxyURL: "http://config-proxy.test"}, ProxyPool: []config.ProxyPoolEntry{{ID: "managed", URL: "http://pool-proxy.test", Enabled: true}}},
			auth: &coreauth.Auth{ProxyID: "managed", ProxyURL: "http://auth-proxy.test"},
			want: "http://pool-proxy.test",
		},
		{
			name: "auth proxy overrides config fallback",
			cfg:  &config.Config{SDKConfig: config.SDKConfig{ProxyURL: "http://config-proxy.test"}},
			auth: &coreauth.Auth{ProxyURL: "http://auth-proxy.test"},
			want: "http://auth-proxy.test",
		},
		{
			name: "config fallback",
			cfg:  &config.Config{SDKConfig: config.SDKConfig{ProxyURL: "http://config-proxy.test"}},
			auth: &coreauth.Auth{},
			want: "http://config-proxy.test",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			transport, ok := New(tt.cfg, nil, Dependencies{}).QuotaTransport(tt.auth).(*http.Transport)
			if !ok || transport.Proxy == nil {
				t.Fatalf("quota transport = %#v, want proxy transport", transport)
			}
			got, err := transport.Proxy(&http.Request{URL: requestURL})
			if err != nil {
				t.Fatalf("resolve proxy: %v", err)
			}
			if got == nil || got.String() != tt.want {
				t.Fatalf("proxy URL = %v, want %s", got, tt.want)
			}
		})
	}
}
