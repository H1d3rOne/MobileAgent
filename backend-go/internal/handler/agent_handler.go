package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/agent"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/sandbox"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

type AgentHandler struct {
	store   *store.AgentStore
	cfg     *config.Config
	engine  *agent.Engine
	sandbox *sandbox.Checker
}

func NewAgentHandler(s *store.AgentStore, cfg *config.Config, engine *agent.Engine) *AgentHandler {
	var sc *sandbox.Checker
	if cfg.Sandbox.Enabled {
		if len(cfg.Sandbox.AllowedCommands) > 0 {
			sc = sandbox.NewChecker(cfg.Sandbox.AllowedCommands)
		} else {
			sc = sandbox.NewChecker(nil) // uses DefaultAllowedCommands
		}
	}
	return &AgentHandler{store: s, cfg: cfg, engine: engine, sandbox: sc}
}

// Chat handles SSE streaming chat with the agent (multi-turn tool calling).
func (h *AgentHandler) Chat(c *gin.Context) {
	var req struct {
		Message      string `json:"message"`
		Conversation string `json:"conversation_id"`
		DeviceSerial string `json:"device_serial"`
		LLM          *struct {
			Provider string `json:"provider"`
			APIKey   string `json:"api_key"`
			BaseURL  string `json:"base_url"`
			Model    string `json:"model"`
			APIType  string `json:"api_type"`
		} `json:"llm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	// Resolve LLM credentials: per-request overrides server defaults.
	llmProvider := h.cfg.LLM.Provider
	llmModel := h.cfg.LLM.Model
	llmAPIKey := h.cfg.LLM.APIKey
	llmBaseURL := h.cfg.LLM.BaseURL
	llmAPIType := h.cfg.LLM.APIType
	if req.LLM != nil {
		if req.LLM.Provider != "" {
			llmProvider = req.LLM.Provider
		}
		if req.LLM.Model != "" {
			llmModel = req.LLM.Model
		}
		if req.LLM.APIKey != "" {
			llmAPIKey = req.LLM.APIKey
		}
		if req.LLM.BaseURL != "" {
			llmBaseURL = req.LLM.BaseURL
		}
		if req.LLM.APIType != "" {
			llmAPIType = req.LLM.APIType
		}
	}

	// Resolve session.
	sessionID := req.Conversation
	if sessionID == "" {
		sessionID = util.NewID()
	}
	session, _ := h.store.GetSession(sessionID)
	if session == nil {
		title := req.Message
		if len([]rune(title)) > 30 {
			title = string([]rune(title)[:30]) + "…"
		}
		if title == "" {
			title = "New Chat"
		}
		session = &model.AgentSession{
			ID:          sessionID,
			Title:       title,
			LLMProvider: llmProvider,
			LLMModel:    llmModel,
			Description: req.Message,
			Status:      "active",
			DeviceID:    req.DeviceSerial,
		}
		h.store.CreateSession(session)
	}

	// Persist user message before invoking agent.
	h.store.CreateAction(&model.AgentAction{
		ID:        util.NewID(),
		SessionID: sessionID,
		Type:      "user_message",
		Content:   req.Message,
	})

	// SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: "streaming unsupported"})
		return
	}

	writeEvent := func(event string, payload any) {
		raw, _ := json.Marshal(payload)
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, raw)
		flusher.Flush()
	}

	writeEvent("meta", map[string]string{"conversation_id": sessionID})

	// Run the agent loop.
	emit := func(kind string, data map[string]any) {
		writeEvent(kind, data)
	}
	if err := h.engine.Run(c.Request.Context(), sessionID, req.Message, req.DeviceSerial, agent.LLMConfig{
		BaseURL: llmBaseURL,
		APIKey:  llmAPIKey,
		Model:   llmModel,
		APIType: llmAPIType,
	}, emit); err != nil {
		// error already emitted by engine; ensure done is still sent so the client can finalize.
	}

	session.Status = "active"
	h.store.UpdateSession(session)

	writeEvent("done", map[string]string{"conversation_id": sessionID})
}

// ListConversations lists all conversation sessions
func (h *AgentHandler) ListConversations(c *gin.Context) {
	sessions, err := h.store.ListSessions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: sessions})
}

// GetConversation gets a single conversation by ID
func (h *AgentHandler) GetConversation(c *gin.Context) {
	id := c.Param("id")
	session, err := h.store.GetSession(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if session == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "conversation not found"})
		return
	}
	// Also fetch actions for this conversation
	actions, _ := h.store.ListActions(id)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]interface{}{
		"session": session,
		"actions": actions,
	}})
}

// DeleteConversation deletes a conversation by ID
func (h *AgentHandler) DeleteConversation(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteSession(id); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

// RollbackConversation deletes actions from a given action ID onward.
func (h *AgentHandler) RollbackConversation(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		ActionID string `json:"action_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ActionID == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "action_id required"})
		return
	}
	if err := h.store.DeleteActionsFrom(id, req.ActionID); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

// SystemStatus returns current system status
func (h *AgentHandler) SystemStatus(c *gin.Context) {
	status := map[string]interface{}{
		"status":      "running",
		"version":     "0.1.0",
		"uptime":      time.Since(startTime).String(),
		"llm_provider": h.cfg.LLM.Provider,
		"llm_model":   h.cfg.LLM.Model,
		"adb_path":    h.cfg.ADB.Path,
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: status})
}

// ListSkills returns the agent's registered skills with their JSON schema.
func (h *AgentHandler) ListSkills(c *gin.Context) {
	if h.engine == nil || h.engine.Registry == nil {
		c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: []any{}})
		return
	}
	tools := h.engine.Registry.AsLLMTools()
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"name":        t.Function.Name,
			"description": t.Function.Description,
			"parameters":  t.Function.Parameters,
		})
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: out})
}

// ListMCPTools returns available MCP tools
func (h *AgentHandler) ListMCPTools(c *gin.Context) {
	// Placeholder - MCP integration to be implemented
	tools := []map[string]interface{}{}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: tools})
}

// ApproveToolCall handles user approval/denial of a dangerous tool call.
// If the original Run is still alive, it signals the waiting channel.
// If the Run already died (SSE disconnect), it executes the tool directly.
func (h *AgentHandler) ApproveToolCall(c *gin.Context) {
	var req struct {
		ToolCallID string `json:"tool_call_id"`
		Approved   bool   `json:"approved"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if req.ToolCallID == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "tool_call_id required"})
		return
	}
	if h.engine == nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: "engine not initialized"})
		return
	}
	executed, result, err := h.engine.ApproveCall(req.ToolCallID, req.Approved)
	resp := map[string]any{
		"tool_call_id": req.ToolCallID,
		"approved":     req.Approved,
		"executed":     executed,
	}
	if executed {
		resp["result"] = result
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: resp})
}

// ListPendingApprovals returns unresolved approval requests for a conversation.
func (h *AgentHandler) ListPendingApprovals(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "conversation id required"})
		return
	}
	actions, err := h.store.ListPendingApprovals(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(actions))
	for _, a := range actions {
		args := map[string]any{}
		if a.ToolArgsJSON != "" {
			_ = json.Unmarshal([]byte(a.ToolArgsJSON), &args)
		}
		out = append(out, map[string]any{
			"id":        a.ToolCallID,
			"name":      a.ToolName,
			"arguments": args,
		})
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: out})
}

// Keep existing session handlers for backward compatibility
func (h *AgentHandler) ListSessions(c *gin.Context) {
	sessions, err := h.store.ListSessions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: sessions})
}

func (h *AgentHandler) GetSession(c *gin.Context) {
	id := c.Param("id")
	session, err := h.store.GetSession(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if session == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "session not found"})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: session})
}

func (h *AgentHandler) CreateSession(c *gin.Context) {
	var req struct {
		DeviceID    string `json:"device_id"`
		LLMProvider string `json:"llm_provider"`
		LLMModel    string `json:"llm_model"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	session := &model.AgentSession{
		ID:          util.NewID(),
		DeviceID:    req.DeviceID,
		LLMProvider: req.LLMProvider,
		LLMModel:    req.LLMModel,
		Description: req.Description,
		Status:      "created",
	}
	if session.LLMProvider == "" {
		session.LLMProvider = h.cfg.LLM.Provider
	}
	if session.LLMModel == "" {
		session.LLMModel = h.cfg.LLM.Model
	}

	if err := h.store.CreateSession(session); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, model.APIResponse{Success: true, Data: session})
}

func (h *AgentHandler) DeleteSession(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteSession(id); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

func (h *AgentHandler) ExecuteSession(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Task string `json:"task"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	session, err := h.store.GetSession(id)
	if err != nil || session == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "session not found"})
		return
	}

	action := &model.AgentAction{
		ID:        util.NewID(),
		SessionID: session.ID,
		Type:      "execute",
		Content:   req.Task,
	}
	if err := h.store.CreateAction(action); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	session.Status = "running"
	h.store.UpdateSession(session)

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: action})
}

func (h *AgentHandler) ListActions(c *gin.Context) {
	sessionID := c.Param("id")
	actions, err := h.store.ListActions(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: actions})
}

// ToolsStatus checks which Android tools are available.
func (h *AgentHandler) ToolsStatus(c *gin.Context) {
	type toolInfo struct {
		Name      string `json:"name"`
		Path      string `json:"path"`
		Available bool   `json:"available"`
		Version   string `json:"version,omitempty"`
	}

	check := func(name, path, versionFlag string) toolInfo {
		info := toolInfo{Name: name, Path: path}
		resolved, err := exec.LookPath(path)
		if err != nil {
			info.Available = false
			return info
		}
		info.Available = true
		info.Path = resolved
		if versionFlag != "" {
			out, err := exec.Command(resolved, versionFlag).CombinedOutput()
			if err == nil {
				ver := string(out)
				if len(ver) > 80 {
					ver = ver[:80]
				}
				info.Version = strings.TrimSpace(ver)
			}
		}
		return info
	}

	tools := []toolInfo{
		check("adb", h.cfg.ADB.Path, "version"),
		check("apktool", h.cfg.Tools.APKTool, "--version"),
		check("jadx", h.cfg.Tools.JADX, "--version"),
		check("frida", h.cfg.Tools.Frida, "--version"),
		check("radare2", h.cfg.Tools.Radare2, "-v"),
		check("androguard", h.cfg.Tools.Androguard, "--version"),
		check("uber-apk-signer", h.cfg.Tools.UberApkSigner, "--help"),
		check("bundletool", h.cfg.Tools.Bundletool, "version"),
		check("mitmproxy", h.cfg.Tools.Mitmproxy, "--version"),
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: tools})
}

// startTime tracks server uptime for SystemStatus
var startTime = time.Now()

// RunTool executes a tool command on the server and returns its output.
// Commands are validated against the sandbox whitelist before execution.
func (h *AgentHandler) RunTool(c *gin.Context) {
	var req struct {
		Command string `json:"command"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Command == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "command required"})
		return
	}

	// Validate command against sandbox whitelist.
	if h.sandbox != nil {
		if err := h.sandbox.Validate(req.Command); err != nil {
			c.JSON(http.StatusForbidden, model.APIResponse{
				Success: false,
				Error:   fmt.Sprintf("command blocked by sandbox: %s", err.Error()),
			})
			return
		}
	}

	cmd := exec.CommandContext(c.Request.Context(), "bash", "-c", req.Command)
	cmd.Dir = h.cfg.Storage.WorkspaceDir

	toolsBin := "../tools/bin"
	existingPath := ""
	for _, e := range cmd.Environ() {
		if strings.HasPrefix(e, "PATH=") {
			existingPath = e[5:]
			break
		}
	}
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("PATH=%s:%s", toolsBin, existingPath))

	out, err := cmd.CombinedOutput()
	result := map[string]any{
		"output":  string(out),
		"command": req.Command,
	}
	if err != nil {
		result["error"] = err.Error()
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}
