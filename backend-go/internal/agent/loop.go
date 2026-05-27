package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/mobileagent/backend-go/internal/agent/extskill"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/llm"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

// Engine bundles all dependencies needed to run an agent turn.
type Engine struct {
	Registry     *Registry
	ADB          *runner.ADBRunner
	APK          *runner.APKRunner
	AgentStore   *store.AgentStore
	Cfg          *config.Config
	ExtManifests []extskill.Manifest

	ApprovalMode string // "deny", "approval", "yolo"

	// approvalChans is Engine-level (not per-Run) so that approval decisions
	// survive SSE reconnects. Keyed by toolCallID.
	approvalMu    sync.Mutex
	approvalChans map[string]chan bool
}

// InitApprovalStore must be called once at startup to initialize the map.
func (e *Engine) InitApprovalStore() {
	e.approvalMu.Lock()
	defer e.approvalMu.Unlock()
	if e.approvalChans == nil {
		e.approvalChans = map[string]chan bool{}
	}
}

// ApproveCall resolves a pending approval request for a dangerous tool call.
// If the original Run is still alive (channel exists), it signals the channel.
// If the Run already died (SSE disconnect), it executes the tool directly and
// persists the result so the next conversation turn picks it up.
func (e *Engine) ApproveCall(toolCallID string, approved bool) (executed bool, result string, err error) {
	// Always resolve in DB first.
	if e.AgentStore != nil {
		_ = e.AgentStore.ResolvePendingApproval(toolCallID, approved)
	}

	e.approvalMu.Lock()
	ch, ok := e.approvalChans[toolCallID]
	if ok {
		delete(e.approvalChans, toolCallID)
	}
	e.approvalMu.Unlock()

	if ok {
		// Run is still alive — signal it.
		select {
		case ch <- approved:
		default:
		}
		return false, "", nil
	}

	// Run already died. If approved, execute the tool now and persist the result.
	if !approved {
		// Denied after disconnect — just persist the denial as a tool_result.
		e.persistLateToolResult(toolCallID, "Denied by user (after reconnect)", true)
		return true, "Denied by user", nil
	}

	// Find the pending_approval action to get tool name and args.
	action := e.findPendingApproval(toolCallID)
	if action == nil {
		return false, "", fmt.Errorf("pending approval not found: %s", toolCallID)
	}

	args := parseArgs(action.ToolArgsJSON)
	res, runErr := e.Registry.Call(context.Background(), action.ToolName, args)
	content := res
	if runErr != nil {
		content = fmt.Sprintf("ERROR: %s", runErr.Error())
	}
	e.persistLateToolResult(toolCallID, content, runErr != nil)
	return true, content, runErr
}

func (e *Engine) findPendingApproval(toolCallID string) *model.AgentAction {
	if e.AgentStore == nil {
		return nil
	}
	// Search across all sessions for this toolCallID.
	var action model.AgentAction
	err := e.AgentStore.DB().
		Where("tool_call_id = ? AND type = ?", toolCallID, "pending_approval").
		First(&action).Error
	if err != nil {
		return nil
	}
	return &action
}

func (e *Engine) persistLateToolResult(toolCallID, content string, isError bool) {
	if e.AgentStore == nil {
		return
	}
	// Find the session from the pending_approval action.
	action := e.findPendingApproval(toolCallID)
	sessionID := ""
	toolName := ""
	if action != nil {
		sessionID = action.SessionID
		toolName = action.ToolName
	}
	if sessionID == "" {
		return
	}
	_ = e.AgentStore.CreateAction(&model.AgentAction{
		ID:         util.NewID(),
		SessionID:  sessionID,
		Type:       "tool_result",
		ToolCallID: toolCallID,
		ToolName:   toolName,
		Content:    content,
	})
}

// EventCallback is what the handler uses to fan out SSE events.
// Kinds: "token", "tool_call", "tool_result", "approval_request", "error".
type EventCallback func(kind string, data map[string]any)

// LLMConfig is the per-request LLM credentials/model.
type LLMConfig struct {
	BaseURL string
	APIKey  string
	Model   string
	APIType string
}

// Run executes one full agent turn (potentially multiple LLM ↔ tool iterations).
// `userMessage` has already been persisted as a user_message action.
func (e *Engine) Run(ctx context.Context, sessionID, userMessage, selectedDevice string, lc LLMConfig, emit EventCallback) error {
	if lc.APIKey == "" {
		emit("error", map[string]any{"content": "LLM API key not configured"})
		return fmt.Errorf("missing api key")
	}
	if lc.Model == "" {
		emit("error", map[string]any{"content": "LLM model not configured"})
		return fmt.Errorf("missing model")
	}

	system := BuildSystemPrompt(e.Registry, e.ADB, e.AgentStore, e.Cfg, PromptContext{
		SelectedDeviceSerial: selectedDevice,
		SessionID:            sessionID,
		UserMessage:          userMessage,
		ExtManifests:         e.ExtManifests,
	})

	messages := []llm.Message{{Role: "system", Content: system}}
	messages = append(messages, e.loadHistory(sessionID)...)

	tools := e.Registry.AsLLMTools()
	client := llm.NewClient(lc.BaseURL, lc.APIKey, lc.Model, lc.APIType)

	// Ensure approval channels map is initialized (Engine-level, not per-Run).
	e.approvalMu.Lock()
	if e.approvalChans == nil {
		e.approvalChans = map[string]chan bool{}
	}
	e.approvalMu.Unlock()

	maxIter := e.Cfg.Agent.MaxIterations
	if maxIter <= 0 {
		maxIter = 10
	}

	approvalMode := e.ApprovalMode
	if approvalMode == "" {
		approvalMode = "approval"
	}

	for iter := 0; iter < maxIter; iter++ {
		asst, finish, err := client.StreamChat(ctx, messages, tools, func(ev llm.StreamEvent) error {
			switch ev.Kind {
			case "content":
				emit("token", map[string]any{"content": ev.Content})
			case "tool_call":
				if ev.ToolCall != nil {
					emit("tool_call", map[string]any{
						"id":        ev.ToolCall.ID,
						"name":      ev.ToolCall.Function.Name,
						"arguments": parseArgs(ev.ToolCall.Function.Arguments),
					})
				}
			}
			return nil
		})
		if err != nil {
			emit("error", map[string]any{"content": err.Error()})
			return err
		}

		// Persist assistant message (text + tool_calls if any)
		if asst.Content != "" || len(asst.ToolCalls) > 0 {
			e.persistAssistant(sessionID, asst)
		}

		messages = append(messages, asst)

		// No tool calls → done
		if len(asst.ToolCalls) == 0 {
			_ = finish
			return nil
		}

		// Execute every tool call, append tool results to messages.
		for _, tc := range asst.ToolCalls {
			args := parseArgs(tc.Function.Arguments)

			// Check approval for dangerous tools.
			content, runErr := e.executeWithApproval(ctx, sessionID, tc, args, approvalMode, emit)
			if runErr != nil && content == "" {
				content = fmt.Sprintf("ERROR: %s", runErr.Error())
			}

			emit("tool_result", map[string]any{
				"id":      tc.ID,
				"name":    tc.Function.Name,
				"content": content,
				"error":   runErr != nil,
			})
			e.persistToolResult(sessionID, tc, content, runErr != nil)
			messages = append(messages, llm.Message{
				Role:       "tool",
				Content:    content,
				ToolCallID: tc.ID,
				Name:       tc.Function.Name,
			})
		}
	}

	emit("error", map[string]any{"content": fmt.Sprintf("max iterations (%d) reached without final answer", maxIter)})
	return fmt.Errorf("max iterations reached")
}

// executeWithApproval checks if a tool is dangerous and handles approval flow
// before executing it.
func (e *Engine) executeWithApproval(ctx context.Context, sessionID string, tc llm.ToolCall, args map[string]any, mode string, emit EventCallback) (string, error) {
	isDangerous := e.Registry.IsDangerous(tc.Function.Name)

	if isDangerous {
		switch mode {
		case "deny":
			return "", fmt.Errorf("tool %s is blocked (dangerous tool, approval mode: deny)", tc.Function.Name)

		case "approval":
			// Create a channel for this tool call (Engine-level, survives reconnects).
			ch := make(chan bool, 1)
			e.approvalMu.Lock()
			e.approvalChans[tc.ID] = ch
			e.approvalMu.Unlock()

			// Persist pending approval to DB for session recovery.
			argsJSON, _ := json.Marshal(args)
			_ = e.AgentStore.CreateAction(&model.AgentAction{
				ID:           util.NewID(),
				SessionID:    sessionID,
				Type:         "pending_approval",
				ToolCallID:   tc.ID,
				ToolName:     tc.Function.Name,
				ToolArgsJSON: string(argsJSON),
			})

			// Emit approval request to frontend.
			emit("approval_request", map[string]any{
				"id":        tc.ID,
				"name":      tc.Function.Name,
				"arguments": args,
			})

			// Wait for approval or context cancellation.
			select {
			case approved := <-ch:
				if !approved {
					return "", fmt.Errorf("tool %s denied by user", tc.Function.Name)
				}
				// Approved — fall through to execute.
			case <-ctx.Done():
				// SSE disconnected while waiting. The pending_approval stays in DB.
				// When user reconnects and approves, ApproveCall will execute the tool.
				return "", fmt.Errorf("approval interrupted (client disconnected)")
			}

		case "yolo":
			// Execute directly.
		}
	}

	return e.Registry.Call(ctx, tc.Function.Name, args)
}

// loadHistory rebuilds the LLM message list from persisted actions.
func (e *Engine) loadHistory(sessionID string) []llm.Message {
	actions, err := e.AgentStore.ListActions(sessionID)
	if err != nil {
		return nil
	}
	limit := e.Cfg.Agent.HistoryMaxMessages
	if limit <= 0 {
		limit = 40
	}
	if len(actions) > limit {
		actions = actions[len(actions)-limit:]
	}

	var msgs []llm.Message
	// Group consecutive tool_calls/tool_results from the same assistant turn.
	for i := 0; i < len(actions); i++ {
		a := actions[i]
		switch a.Type {
		case "user_message":
			msgs = append(msgs, llm.Message{Role: "user", Content: a.Content})
		case "assistant_message":
			// Check if followed by tool calls in the same logical turn (rare in this loader).
			msgs = append(msgs, llm.Message{Role: "assistant", Content: a.Content})
		case "tool_call":
			// Embed as assistant with a tool_call (best-effort reconstruction).
			args := parseArgs(a.ToolArgsJSON)
			argsJSON, _ := json.Marshal(args)
			msgs = append(msgs, llm.Message{
				Role: "assistant",
				ToolCalls: []llm.ToolCall{{
					ID:       a.ToolCallID,
					Type:     "function",
					Function: llm.FunctionCall{Name: a.ToolName, Arguments: string(argsJSON)},
				}},
			})
		case "tool_result":
			msgs = append(msgs, llm.Message{
				Role:       "tool",
				Content:    a.Content,
				ToolCallID: a.ToolCallID,
				Name:       a.ToolName,
			})
		}
	}
	return msgs
}

func (e *Engine) persistAssistant(sessionID string, asst llm.Message) {
	if asst.Content != "" {
		_ = e.AgentStore.CreateAction(&model.AgentAction{
			ID:        util.NewID(),
			SessionID: sessionID,
			Type:      "assistant_message",
			Content:   asst.Content,
		})
	}
	for _, tc := range asst.ToolCalls {
		_ = e.AgentStore.CreateAction(&model.AgentAction{
			ID:           util.NewID(),
			SessionID:    sessionID,
			Type:         "tool_call",
			ToolCallID:   tc.ID,
			ToolName:     tc.Function.Name,
			ToolArgsJSON: tc.Function.Arguments,
		})
	}
}

func (e *Engine) persistToolResult(sessionID string, tc llm.ToolCall, content string, isError bool) {
	t := "tool_result"
	_ = e.AgentStore.CreateAction(&model.AgentAction{
		ID:         util.NewID(),
		SessionID:  sessionID,
		Type:       t,
		ToolCallID: tc.ID,
		ToolName:   tc.Function.Name,
		Content:    content,
	})
	_ = isError
}

// parseArgs decodes the JSON arguments string emitted by OpenAI tool_calls.
func parseArgs(s string) map[string]any {
	if s == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string]any{"_raw": s}
	}
	if out == nil {
		out = map[string]any{}
	}
	return out
}
