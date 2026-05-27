package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

type MemoryHandler struct {
	store *store.AgentStore
}

func NewMemoryHandler(s *store.AgentStore) *MemoryHandler {
	return &MemoryHandler{store: s}
}

// List GET /api/v1/memory?scope=&q=&limit=
func (h *MemoryHandler) List(c *gin.Context) {
	q := c.Query("q")
	scopeParam := c.Query("scope") // CSV
	var scopes []string
	if scopeParam != "" {
		for _, s := range strings.Split(scopeParam, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopes = append(scopes, s)
			}
		}
	}
	limit := 50
	rows, err := h.store.SearchMemory(scopes, q, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: rows})
}

// Create POST /api/v1/memory
func (h *MemoryHandler) Create(c *gin.Context) {
	var req struct {
		Scope string `json:"scope"`
		Key   string `json:"key"`
		Value string `json:"value"`
		Tags  string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if req.Key == "" || req.Value == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "key and value required"})
		return
	}
	scope := req.Scope
	if scope == "" {
		scope = "global"
	}
	m := &model.AgentMemory{
		ID:    util.NewID(),
		Scope: scope,
		Key:   req.Key,
		Value: req.Value,
		Tags:  req.Tags,
	}
	if err := h.store.SaveMemory(m); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, model.APIResponse{Success: true, Data: m})
}

// Delete DELETE /api/v1/memory/:id
func (h *MemoryHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteMemory(id); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}
