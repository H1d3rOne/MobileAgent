package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
)

// Server represents one connected MCP server (over stdio).
type Server struct {
	Name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	mu      sync.Mutex
	pending map[int64]chan rpcResponse
	nextID  atomic.Int64
	tools   []Tool
}

// Tool is the MCP tool descriptor (a subset of the spec we use).
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Start spawns the MCP server process and runs the initial handshake.
func Start(ctx context.Context, name string, command []string, env map[string]string) (*Server, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("empty command for mcp server %s", name)
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil // suppress; could pipe to logger later

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	srv := &Server{
		Name:    name,
		cmd:     cmd,
		stdin:   stdin,
		stdout:  bufio.NewReader(stdout),
		pending: map[int64]chan rpcResponse{},
	}
	go srv.readLoop()

	// Initialize handshake.
	if _, err := srv.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mobileagent", "version": "0.1.0"},
	}); err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	// notifications/initialized (no response expected)
	_ = srv.notify("notifications/initialized", nil)

	if err := srv.refreshTools(ctx); err != nil {
		// Tool listing failure is non-fatal; some servers expose only resources.
		srv.tools = nil
	}

	return srv, nil
}

func (s *Server) Tools() []Tool { return s.tools }

func (s *Server) refreshTools(ctx context.Context) error {
	raw, err := s.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return err
	}
	var resp struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	s.tools = resp.Tools
	return nil
}

// CallTool invokes an MCP tool by name.
func (s *Server) CallTool(ctx context.Context, name string, args map[string]any) (string, error) {
	raw, err := s.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return "", err
	}
	// MCP returns content as an array of blocks; extract text.
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return string(raw), nil
	}
	var out []byte
	for i, b := range resp.Content {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, []byte(b.Text)...)
	}
	if resp.IsError {
		return string(out), fmt.Errorf("mcp tool %s reported error", name)
	}
	return string(out), nil
}

func (s *Server) Close() error {
	if s.stdin != nil {
		_ = s.stdin.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return nil
}

// --- internal ---

func (s *Server) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := s.nextID.Add(1)
	req := rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ch := make(chan rpcResponse, 1)
	s.mu.Lock()
	s.pending[id] = ch
	s.mu.Unlock()

	if _, err := fmt.Fprintf(s.stdin, "%s\n", body); err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, ctx.Err()
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
}

func (s *Server) notify(method string, params any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	_, err := fmt.Fprintf(s.stdin, "%s\n", body)
	return err
}

func (s *Server) readLoop() {
	for {
		line, err := s.stdout.ReadBytes('\n')
		if err != nil {
			return
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}
		if resp.ID == 0 {
			// notification or unsolicited; ignore for now
			continue
		}
		s.mu.Lock()
		ch, ok := s.pending[resp.ID]
		if ok {
			delete(s.pending, resp.ID)
		}
		s.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
}
