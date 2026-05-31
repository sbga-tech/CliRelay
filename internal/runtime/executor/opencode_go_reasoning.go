package executor

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var (
	reasoningContentCacheTTL        = 30 * time.Minute
	reasoningCacheCleanupInterval   = 5 * time.Minute
	reasoningCacheMaxEntriesPerKey  = 1
)

var (
	reasoningCache     sync.Map
	reasoningCacheOnce sync.Once
)

type reasoningEntry struct {
	content   string
	timestamp time.Time
}

func startReasoningCacheCleanup() {
	reasoningCacheOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(reasoningCacheCleanupInterval)
			defer ticker.Stop()
			for range ticker.C {
				purgeExpiredReasoningEntries()
			}
		}()
	})
}

func purgeExpiredReasoningEntries() {
	now := time.Now()
	reasoningCache.Range(func(key, value any) bool {
		entry := value.(reasoningEntry)
		if now.Sub(entry.timestamp) > reasoningContentCacheTTL {
			reasoningCache.Delete(key)
		}
		return true
	})
}

// opencodeGoSessionID extracts the session identifier from executor options.
// Returns empty string if no session identifier is found.
func opencodeGoSessionID(opts cliproxyexecutor.Options) string {
	if opts.Headers != nil {
		if sessionID := opts.Headers.Get("Session-Id"); sessionID != "" {
			return sessionID
		}
		if sessionID := opts.Headers.Get("X-Client-Request-Id"); sessionID != "" {
			return sessionID
		}
	}
	if raw, ok := opts.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey]; ok {
		if s, ok := raw.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// opencodeGoNeedsReasoningInjection checks if the model requires reasoning_content
// tracking for multi-turn conversations (e.g., DeepSeek thinking mode).
func opencodeGoNeedsReasoningInjection(model string) bool {
	base := strings.ToLower(strings.TrimSpace(thinking.ParseSuffix(model).ModelName))
	return strings.HasPrefix(base, "deepseek")
}

// opencodeGoCacheReasoningContent stores reasoning_content for a given model and session.
func opencodeGoCacheReasoningContent(model, sessionID, content string) {
	if model == "" || sessionID == "" || content == "" {
		return
	}
	startReasoningCacheCleanup()
	key := model + ":" + sessionID
	reasoningCache.Store(key, reasoningEntry{
		content:   content,
		timestamp: time.Now(),
	})
}

// opencodeGoGetCachedReasoningContent retrieves reasoning_content for a given model and session.
// Returns empty string if not found or expired.
func opencodeGoGetCachedReasoningContent(model, sessionID string) string {
	if model == "" || sessionID == "" {
		return ""
	}
	val, ok := reasoningCache.Load(model + ":" + sessionID)
	if !ok {
		return ""
	}
	entry := val.(reasoningEntry)
	if time.Since(entry.timestamp) > reasoningContentCacheTTL {
		reasoningCache.Delete(model + ":" + sessionID)
		return ""
	}
	// Refresh TTL on access (sliding expiration)
	entry.timestamp = time.Now()
	reasoningCache.Store(model+":"+sessionID, entry)
	return entry.content
}

// opencodeGoCacheReasoningFromNonStream extracts reasoning_content from a non-streaming
// response payload and caches it for future requests.
func opencodeGoCacheReasoningFromNonStream(payload []byte, model, sessionID string) {
	if len(payload) == 0 || model == "" || sessionID == "" || !gjson.ValidBytes(payload) {
		return
	}
	// OpenAI chat completions format
	if content := gjson.GetBytes(payload, "choices.0.message.reasoning_content").String(); content != "" {
		opencodeGoCacheReasoningContent(model, sessionID, content)
	}
	// Anthropic messages format (via executeMessages / executeMessagesStream)
	// The response has been translated back, so reasoning_content might be in the
	// translated payload too.
}

// opencodeGoCacheReasoningFromStreamChunk extracts reasoning_content from a streaming
// SSE chunk and caches it for future requests. It should be called for every streaming
// chunk that contains a reasoning_content delta.
func opencodeGoCacheReasoningFromStreamChunk(payload []byte, model, sessionID string) {
	if len(payload) == 0 || model == "" || sessionID == "" {
		return
	}
	// Handle SSE format: "data: {...}\n\n"
	raw := payload
	dataPrefix := []byte("data: ")
	if bytes.HasPrefix(bytes.TrimSpace(payload), dataPrefix) {
		raw = bytes.TrimSpace(payload[len(dataPrefix):])
	}
	if !gjson.ValidBytes(raw) {
		return
	}
	// OpenAI chat completions streaming format
	content := gjson.GetBytes(raw, "choices.0.delta.reasoning_content").String()
	if content == "" {
		return
	}
	key := model + ":" + sessionID
	// Accumulate: append to existing entry if it exists
	val, ok := reasoningCache.Load(key)
	if ok {
		entry := val.(reasoningEntry)
		if time.Since(entry.timestamp) <= reasoningContentCacheTTL {
			content = entry.content + content
		}
	}
	opencodeGoCacheReasoningContent(model, sessionID, content)
}

// opencodeGoInjectReasoningContentIntoPayload scans the request payload for assistant
// messages that are missing reasoning_content and injects the cached content when available.
// This is needed for DeepSeek models that require reasoning_content in multi-turn thinking mode.
func opencodeGoInjectReasoningContentIntoPayload(payload []byte, model, sessionID string) []byte {
	if len(payload) == 0 || model == "" || sessionID == "" || !gjson.ValidBytes(payload) {
		return payload
	}

	reasoningContent := opencodeGoGetCachedReasoningContent(model, sessionID)
	if reasoningContent == "" {
		return payload
	}

	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() || len(messages.Array()) == 0 {
		// Also check for Responses API format (input array)
		input := gjson.GetBytes(payload, "input")
		if input.Exists() && input.IsArray() && len(input.Array()) > 0 {
			return opencodeGoInjectInputArrayReasoning(payload, model, reasoningContent)
		}
		return payload
	}

	msgs := messages.Array()
	modified := false

	// Find the LAST assistant message that is missing reasoning_content
	// This is the message from the previous turn that needs injection
	for i := len(msgs) - 1; i >= 0; i-- {
		msg := msgs[i]
		role := msg.Get("role").String()
		if role != "assistant" {
			continue
		}
		// Skip if already has reasoning_content
		if msg.Get("reasoning_content").Exists() && msg.Get("reasoning_content").String() != "" {
			continue
		}
		// Skip pure tool_call messages
		if msg.Get("tool_calls").Exists() && msg.Get("tool_calls").IsArray() &&
			len(msg.Get("tool_calls").Array()) > 0 && msg.Get("content").String() == "" {
			continue
		}
		path := fmt.Sprintf("messages.%d.reasoning_content", i)
		var err error
		payload, err = sjson.SetBytes(payload, path, reasoningContent)
		if err == nil {
			modified = true
		}
		break
	}

	if !modified {
		return payload
	}
	return payload
}

// opencodeGoInjectInputArrayReasoning handles the Responses API format (input array).
func opencodeGoInjectInputArrayReasoning(payload []byte, model, content string) []byte {
	input := gjson.GetBytes(payload, "input")
	if !input.Exists() || !input.IsArray() {
		return payload
	}
	items := input.Array()
	modified := false

	for i := len(items) - 1; i >= 0; i-- {
		item := items[i]
		role := item.Get("role").String()
		if role != "assistant" {
			continue
		}
		if item.Get("reasoning_content").Exists() && item.Get("reasoning_content").String() != "" {
			continue
		}
		path := fmt.Sprintf("input.%d.reasoning_content", i)
		var err error
		payload, err = sjson.SetBytes(payload, path, content)
		if err == nil {
			modified = true
		}
		break
	}
	if !modified {
		return payload
	}
	return payload
}

// opencodeGoWrapStreamCacheReasoning wraps a StreamResult's chunk channel to intercept
// and cache reasoning_content from streaming responses.
func opencodeGoWrapStreamCacheReasoning(result *cliproxyexecutor.StreamResult, model, sessionID string) *cliproxyexecutor.StreamResult {
	if result == nil || model == "" || sessionID == "" {
		return result
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		for chunk := range result.Chunks {
			if chunk.Err == nil && len(chunk.Payload) > 0 {
				opencodeGoCacheReasoningFromStreamChunk(chunk.Payload, model, sessionID)
			}
			out <- chunk
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: out}
}
