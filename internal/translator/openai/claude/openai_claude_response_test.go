package claude

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func collectOpenAIToClaudeStream(t *testing.T, chunks ...string) string {
	t.Helper()

	originalRequest := []byte(`{"stream":true}`)
	var param any
	var out []string
	for _, chunk := range chunks {
		out = append(out, ConvertOpenAIResponseToClaude(context.Background(), "m", originalRequest, nil, []byte(chunk), &param)...)
	}
	return strings.Join(out, "")
}

func assertNoOrphanContentBlockEvents(t *testing.T, stream string) {
	t.Helper()

	openBlocks := make(map[int]bool)
	for _, segment := range strings.Split(stream, "\n\n") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		var eventType, data string
		for _, line := range strings.Split(segment, "\n") {
			switch {
			case strings.HasPrefix(line, "event:"):
				eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
		}
		if data == "" {
			continue
		}

		payload := gjson.Parse(data)
		switch eventType {
		case "content_block_start":
			idx := int(payload.Get("index").Int())
			openBlocks[idx] = true
		case "content_block_delta":
			idx := int(payload.Get("index").Int())
			if !openBlocks[idx] {
				t.Fatalf("content_block_delta without matching content_block_start at index %d:\n%s", idx, stream)
			}
		case "content_block_stop":
			idx := int(payload.Get("index").Int())
			if !openBlocks[idx] {
				t.Fatalf("content_block_stop without matching content_block_start at index %d:\n%s", idx, stream)
			}
			delete(openBlocks, idx)
		}
	}
}

func TestOpenAIStreamingEmptyToolNameSkipsOrphanToolEvents(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-empty-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_empty","type":"function","function":{"name":"","arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-empty-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if strings.Contains(out, `"type":"tool_use"`) {
		t.Fatalf("empty function.name must not emit tool_use block:\n%s", out)
	}
	if strings.Contains(out, `"type":"input_json_delta"`) {
		t.Fatalf("empty function.name must not emit input_json_delta:\n%s", out)
	}
	if strings.Contains(out, `"type":"content_block_stop"`) {
		t.Fatalf("empty function.name must not emit orphan content_block_stop:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("empty-only tool_calls finish should become end_turn:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingWhitespaceToolNameSkipped(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-space-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_space","type":"function","function":{"name":"   ","arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-space-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if strings.Contains(out, `"type":"tool_use"`) || strings.Contains(out, `"type":"input_json_delta"`) {
		t.Fatalf("whitespace function.name must not emit tool events:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("whitespace-only tool_calls finish should become end_turn:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingTextWithEmptyToolNameKeepsTextOnly(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-text-empty-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-text-empty-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_empty","type":"function","function":{"name":"","arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-text-empty-tool","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if !strings.Contains(out, `"type":"text_delta","text":"hello"`) {
		t.Fatalf("text before empty-name tool call should be preserved:\n%s", out)
	}
	if strings.Contains(out, `"type":"tool_use"`) || strings.Contains(out, `"type":"input_json_delta"`) {
		t.Fatalf("empty-name tool call must not emit tool events after text:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("empty-only tool_calls finish after text should become end_turn:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingEmptyToolNameWithUsageChunkStopReasonEndTurn(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-empty-tool-usage","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_empty","type":"function","function":{"name":"","arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-empty-tool-usage","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: {"id":"chatcmpl-empty-tool-usage","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}`,
		`data: [DONE]`,
	)

	if strings.Contains(out, `"type":"tool_use"`) || strings.Contains(out, `"type":"input_json_delta"`) {
		t.Fatalf("empty-name tool call must not emit tool events with usage chunk:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("usage message_delta should use end_turn when no valid tool was emitted:\n%s", out)
	}
	if strings.Count(out, `"type":"message_stop"`) != 1 {
		t.Fatalf("stream should emit exactly one message_stop:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingToolArgumentsBeforeNamePreserved(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_late","type":"function","function":{"arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"type":"function","function":{"name":"Read"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	start := strings.Index(out, `"type":"tool_use"`)
	delta := strings.Index(out, `"type":"input_json_delta"`)
	stop := strings.Index(out, `"type":"content_block_stop"`)
	if start == -1 || delta == -1 || stop == -1 {
		t.Fatalf("late valid name should emit complete tool block:\n%s", out)
	}
	if !(start < delta && delta < stop) {
		t.Fatalf("tool block events out of order:\n%s", out)
	}
	if !strings.Contains(out, `"name":"Read"`) || !strings.Contains(out, `"partial_json":"{\"path\":\"x\"}"`) {
		t.Fatalf("late valid name should preserve name and buffered arguments:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Fatalf("valid tool call should keep tool_use stop_reason:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingToolArgumentsWithoutValidNameSkipped(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-missing-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_missing","type":"function","function":{"arguments":"{\"path\":\"a.go\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-missing-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"extra\":true}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-missing-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if strings.Contains(out, `"type":"tool_use"`) {
		t.Fatalf("arguments without a valid function.name must not emit tool_use:\n%s", out)
	}
	if strings.Contains(out, `"type":"input_json_delta"`) {
		t.Fatalf("arguments without a valid function.name must not emit input_json_delta:\n%s", out)
	}
	if strings.Contains(out, `"type":"content_block_stop"`) {
		t.Fatalf("arguments without a valid function.name must not emit orphan content_block_stop:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("tool_calls finish without a valid tool block should become end_turn:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingWhitespaceNameAfterBufferedArgumentsSkipped(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-blank-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_blank","type":"function","function":{"arguments":"{\"path\":\"a.go\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-blank-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"   "}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-blank-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"tail\":1}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-blank-late-name","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if strings.Contains(out, `"type":"tool_use"`) || strings.Contains(out, `"type":"input_json_delta"`) {
		t.Fatalf("buffered arguments with whitespace-only function.name must not emit tool events:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("whitespace-only late tool name should leave stop_reason=end_turn:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingMixedValidAndEmptyToolCalls(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-mixed-tools","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_valid","type":"function","function":{"name":"Read","arguments":"{\"file_path\":\"a.go\"}"}},{"index":1,"id":"call_empty","type":"function","function":{"name":"","arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-mixed-tools","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if got := strings.Count(out, `"type":"tool_use"`); got != 1 {
		t.Fatalf("expected exactly one valid tool_use, got %d:\n%s", got, out)
	}
	if strings.Contains(out, `call_empty`) {
		t.Fatalf("empty-name tool call must not be emitted:\n%s", out)
	}
	if !strings.Contains(out, `"name":"Read"`) || !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Fatalf("valid tool call should be preserved:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAIStreamingEmptyIndexBeforeValidIndexKeepsValidOnly(t *testing.T) {
	out := collectOpenAIToClaudeStream(t,
		`data: {"id":"chatcmpl-empty-first-index","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_empty","type":"function","function":{"arguments":"{\"path\":\"x\"}"}},{"index":1,"id":"call_valid","type":"function","function":{"name":"Read","arguments":"{\"file_path\":\"a.go\""}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-empty-first-index","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":""}},{"index":1,"function":{"arguments":",\"tail\":true}"}}]},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-empty-first-index","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	if got := strings.Count(out, `"type":"tool_use"`); got != 1 {
		t.Fatalf("expected exactly one valid tool_use, got %d:\n%s", got, out)
	}
	if strings.Contains(out, `call_empty`) {
		t.Fatalf("empty first-index tool call must not be emitted:\n%s", out)
	}
	if !strings.Contains(out, `"name":"Read"`) || !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Fatalf("valid second-index tool call should be preserved:\n%s", out)
	}
	assertNoOrphanContentBlockEvents(t, out)
}

func TestOpenAINonStreamingEmptyToolNameSkippedAndStopReasonEndTurn(t *testing.T) {
	raw := []byte(`{"id":"chatcmpl-empty-tool","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_empty","type":"function","function":{"name":"","arguments":"{\"path\":\"x\"}"}}]},"finish_reason":"tool_calls"}]}`)

	streamCompat := strings.Join(convertOpenAINonStreamingToAnthropic(raw), "")
	if strings.Contains(streamCompat, `"type":"tool_use"`) || strings.Contains(streamCompat, `"name":""`) {
		t.Fatalf("empty function.name must not emit non-streaming tool_use:\n%s", streamCompat)
	}
	if got := gjson.Get(streamCompat, "stop_reason").String(); got != "end_turn" {
		t.Fatalf("stream-compatible non-stream stop_reason = %q, want end_turn; payload=%s", got, streamCompat)
	}

	nonStream := ConvertOpenAIResponseToClaudeNonStream(context.Background(), "m", nil, nil, raw, nil)
	if strings.Contains(nonStream, `"type":"tool_use"`) || strings.Contains(nonStream, `"name":""`) {
		t.Fatalf("empty function.name must not emit non-streaming tool_use:\n%s", nonStream)
	}
	if got := gjson.Get(nonStream, "stop_reason").String(); got != "end_turn" {
		t.Fatalf("non-stream stop_reason = %q, want end_turn; payload=%s", got, nonStream)
	}
}

func TestOpenAINonStreamingContentArrayEmptyToolNameSkipped(t *testing.T) {
	raw := []byte(`{"id":"chatcmpl-empty-tool-array","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":[{"type":"tool_calls","tool_calls":[{"id":"call_empty","type":"function","function":{"name":"","arguments":"{\"path\":\"x\"}"}}]}]},"finish_reason":"tool_calls"}]}`)

	out := ConvertOpenAIResponseToClaudeNonStream(context.Background(), "m", nil, nil, raw, nil)
	if strings.Contains(out, `"type":"tool_use"`) || strings.Contains(out, `"name":""`) {
		t.Fatalf("empty function.name in content-array tool_calls must be skipped:\n%s", out)
	}
	if got := gjson.Get(out, "stop_reason").String(); got != "end_turn" {
		t.Fatalf("stop_reason = %q, want end_turn; payload=%s", got, out)
	}
}
