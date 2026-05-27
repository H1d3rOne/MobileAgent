package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/mcp"
	"github.com/mobileagent/backend-go/internal/model"
)

type MCPHandler struct {
	mgr *mcp.Manager
}

func NewMCPHandler(mgr *mcp.Manager) *MCPHandler {
	return &MCPHandler{mgr: mgr}
}

// GET /api/v1/mcp/servers — list MCP server status (alive, tool counts).
func (h *MCPHandler) Servers(c *gin.Context) {
	if h.mgr == nil {
		c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]any{}})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: h.mgr.Status()})
}

// GET /api/v1/mcp/tools — placeholder, kept for backward compatibility.
// The actual tool listing is exposed through /api/v1/skills (which already
// merges built-in skills and MCP-provided tools).
func (h *MCPHandler) Tools(c *gin.Context) {
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: []any{}})
}
