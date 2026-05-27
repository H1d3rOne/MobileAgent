package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message is the OpenAI chat-completions message envelope.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type Client struct {
	baseURL string
	apiKey  string
	model   string
	apiType string
	http    *http.Client
}

func NewClient(baseURL, apiKey, model, apiType string) *Client {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if apiType == "" {
		apiType = "chat_completions"
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		apiType: apiType,
		http:    &http.Client{Timeout: 10 * time.Minute},
	}
}

type chatRequest struct {
	Model      string    `json:"model"`
	Messages   []Message `json:"messages"`
	Stream     bool      `json:"stream"`
	Tools      []Tool    `json:"tools,omitempty"`
	ToolChoice string    `json:"tool_choice,omitempty"`
}

type responsesRequest struct {
	Model      string `json:"model"`
	Input      any    `json:"input"`
	Stream     bool   `json:"stream"`
	Tools      []any  `json:"tools,omitempty"`
	ToolChoice string `json:"tool_choice,omitempty"`
}

type streamDelta struct {
	Content   string `json:"content,omitempty"`
	ToolCalls []struct {
		Index    int    `json:"index"`
		ID       string `json:"id,omitempty"`
		Type     string `json:"type,omitempty"`
		Function struct {
			Name      string `json:"name,omitempty"`
			Arguments string `json:"arguments,omitempty"`
		} `json:"function,omitempty"`
	} `json:"tool_calls,omitempty"`
}

type streamChunk struct {
	Choices []struct {
		Delta        streamDelta `json:"delta"`
		FinishReason *string     `json:"finish_reason"`
	} `json:"choices"`
}

type StreamEvent struct {
	Kind         string
	Content      string
	ToolCall     *ToolCall
	FinishReason string
}

func (c *Client) StreamChat(ctx context.Context, messages []Message, tools []Tool, onEvent func(StreamEvent) error) (Message, string, error) {
	if c.apiType == "responses" {
		return c.streamResponses(ctx, messages, tools, onEvent)
	}
	return c.streamChatCompletions(ctx, messages, tools, onEvent)
}

func (c *Client) streamChatCompletions(ctx context.Context, messages []Message, tools []Tool, onEvent func(StreamEvent) error) (Message, string, error) {
	reqBody := chatRequest{Model: c.model, Messages: messages, Stream: true, Tools: tools}
	if len(tools) > 0 {
		reqBody.ToolChoice = "auto"
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return Message{}, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Message{}, "", err
	}
	resp, err := c.do(req)
	if err != nil {
		return Message{}, "", err
	}
	defer resp.Body.Close()

	var (
		assembledContent strings.Builder
		toolCallsByIdx   = map[int]*ToolCall{}
		finish           string
	)

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		payload, ok := ssePayload(scanner.Text())
		if !ok {
			continue
		}
		if payload == "[DONE]" {
			break
		}
		var chunk streamChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]
		if choice.FinishReason != nil {
			finish = *choice.FinishReason
		}
		if d := choice.Delta.Content; d != "" {
			assembledContent.WriteString(d)
			if err := onEvent(StreamEvent{Kind: "content", Content: d}); err != nil {
				return Message{}, finish, err
			}
		}
		for _, tc := range choice.Delta.ToolCalls {
			cur := ensureToolCallByIndex(toolCallsByIdx, tc.Index)
			if tc.ID != "" {
				cur.ID = tc.ID
			}
			if tc.Type != "" {
				cur.Type = tc.Type
			}
			if tc.Function.Name != "" {
				cur.Function.Name += tc.Function.Name
			}
			if tc.Function.Arguments != "" {
				cur.Function.Arguments += tc.Function.Arguments
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Message{}, finish, fmt.Errorf("read stream: %w", err)
	}

	calls, err := emitToolCallsByIndex(toolCallsByIdx, onEvent)
	if err != nil {
		return Message{}, finish, err
	}
	asst := Message{Role: "assistant", Content: assembledContent.String(), ToolCalls: calls}
	_ = onEvent(StreamEvent{Kind: "finish", FinishReason: finish})
	return asst, finish, nil
}

func (c *Client) streamResponses(ctx context.Context, messages []Message, tools []Tool, onEvent func(StreamEvent) error) (Message, string, error) {
	reqBody := responsesRequest{
		Model:  c.model,
		Input:  toResponsesInput(messages),
		Stream: true,
		Tools:  toResponsesTools(tools),
	}
	if len(tools) > 0 {
		reqBody.ToolChoice = "auto"
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return Message{}, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/responses", bytes.NewReader(body))
	if err != nil {
		return Message{}, "", err
	}
	resp, err := c.do(req)
	if err != nil {
		return Message{}, "", err
	}
	defer resp.Body.Close()

	var (
		assembledContent strings.Builder
		toolCallsByID    = map[string]*ToolCall{}
		toolOrder        []string
		finish           string
	)

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		payload, ok := ssePayload(scanner.Text())
		if !ok {
			continue
		}
		if payload == "[DONE]" {
			break
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(payload), &raw); err != nil {
			continue
		}
		switch stringValue(raw["type"]) {
		case "response.output_text.delta":
			delta := stringValue(raw["delta"])
			if delta == "" {
				continue
			}
			assembledContent.WriteString(delta)
			if err := onEvent(StreamEvent{Kind: "content", Content: delta}); err != nil {
				return Message{}, finish, err
			}
		case "response.function_call_arguments.delta":
			id := firstNonEmpty(stringValue(raw["item_id"]), stringValue(raw["call_id"]), stringValue(raw["id"]))
			if id == "" {
				continue
			}
			tc := ensureToolCall(toolCallsByID, &toolOrder, id)
			tc.Function.Arguments += stringValue(raw["delta"])
		case "response.function_call_arguments.done":
			id := firstNonEmpty(stringValue(raw["item_id"]), stringValue(raw["call_id"]), stringValue(raw["id"]))
			if id == "" {
				continue
			}
			tc := ensureToolCall(toolCallsByID, &toolOrder, id)
			if args := stringValue(raw["arguments"]); args != "" {
				tc.Function.Arguments = args
			}
		case "response.output_item.added", "response.output_item.done":
			item, _ := raw["item"].(map[string]any)
			if stringValue(item["type"]) != "function_call" {
				continue
			}
			id := firstNonEmpty(stringValue(item["call_id"]), stringValue(item["id"]))
			if id == "" {
				continue
			}
			tc := ensureToolCall(toolCallsByID, &toolOrder, id)
			tc.ID = id
			tc.Type = "function"
			if name := stringValue(item["name"]); name != "" {
				tc.Function.Name = name
			}
			if args := stringValue(item["arguments"]); args != "" {
				tc.Function.Arguments = args
			}
		case "response.completed":
			finish = "stop"
		case "response.failed":
			return Message{}, finish, fmt.Errorf("responses api failed: %s", payload)
		}
	}
	if err := scanner.Err(); err != nil {
		return Message{}, finish, fmt.Errorf("read stream: %w", err)
	}

	calls, err := emitToolCallsByOrder(toolCallsByID, toolOrder, onEvent)
	if err != nil {
		return Message{}, finish, err
	}
	asst := Message{Role: "assistant", Content: assembledContent.String(), ToolCalls: calls}
	_ = onEvent(StreamEvent{Kind: "finish", FinishReason: finish})
	return asst, finish, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("upstream %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return resp, nil
}

func ssePayload(line string) (string, bool) {
	if !strings.HasPrefix(line, "data:") {
		return "", false
	}
	payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
	if payload == "" {
		return "", false
	}
	return payload, true
}

func ensureToolCallByIndex(toolCallsByIdx map[int]*ToolCall, index int) *ToolCall {
	if tc, ok := toolCallsByIdx[index]; ok {
		return tc
	}
	tc := &ToolCall{Type: "function"}
	toolCallsByIdx[index] = tc
	return tc
}

func emitToolCallsByIndex(toolCallsByIdx map[int]*ToolCall, onEvent func(StreamEvent) error) ([]ToolCall, error) {
	maxIdx := -1
	for i := range toolCallsByIdx {
		if i > maxIdx {
			maxIdx = i
		}
	}
	var calls []ToolCall
	for i := 0; i <= maxIdx; i++ {
		if tc, ok := toolCallsByIdx[i]; ok && tc.Function.Name != "" {
			if tc.ID == "" {
				tc.ID = fmt.Sprintf("call_%d_%d", time.Now().UnixNano(), i)
			}
			calls = append(calls, *tc)
			callCopy := *tc
			if err := onEvent(StreamEvent{Kind: "tool_call", ToolCall: &callCopy}); err != nil {
				return nil, err
			}
		}
	}
	return calls, nil
}

func ensureToolCall(toolCallsByID map[string]*ToolCall, order *[]string, id string) *ToolCall {
	if tc, ok := toolCallsByID[id]; ok {
		return tc
	}
	tc := &ToolCall{ID: id, Type: "function"}
	toolCallsByID[id] = tc
	*order = append(*order, id)
	return tc
}

func emitToolCallsByOrder(toolCallsByID map[string]*ToolCall, order []string, onEvent func(StreamEvent) error) ([]ToolCall, error) {
	var calls []ToolCall
	for i, id := range order {
		tc := toolCallsByID[id]
		if tc == nil || tc.Function.Name == "" {
			continue
		}
		if tc.ID == "" {
			tc.ID = fmt.Sprintf("call_%d_%d", time.Now().UnixNano(), i)
		}
		calls = append(calls, *tc)
		callCopy := *tc
		if err := onEvent(StreamEvent{Kind: "tool_call", ToolCall: &callCopy}); err != nil {
			return nil, err
		}
	}
	return calls, nil
}

func toResponsesInput(messages []Message) []any {
	items := make([]any, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case "system", "user", "assistant":
			if m.Content != "" {
				items = append(items, map[string]any{
					"role":    m.Role,
					"content": m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				items = append(items, map[string]any{
					"type":      "function_call",
					"call_id":   tc.ID,
					"name":      tc.Function.Name,
					"arguments": tc.Function.Arguments,
				})
			}
		case "tool":
			items = append(items, map[string]any{
				"type":    "function_call_output",
				"call_id": m.ToolCallID,
				"output":  m.Content,
			})
		}
	}
	return items
}

func toResponsesTools(tools []Tool) []any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		params := t.Function.Parameters
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{
			"type":        "function",
			"name":        t.Function.Name,
			"description": t.Function.Description,
			"parameters":  params,
		})
	}
	return out
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
