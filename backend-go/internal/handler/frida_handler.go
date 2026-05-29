package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/frida"
	"github.com/mobileagent/backend-go/internal/runner"
)

type FridaHandler struct {
	runner *runner.FridaRunner
}

func NewFridaHandler(r *runner.FridaRunner) *FridaHandler {
	return &FridaHandler{runner: r}
}

func (h *FridaHandler) ListScripts(c *gin.Context) {
	category := c.Query("category")
	if category != "" {
		c.JSON(http.StatusOK, gin.H{
			"scripts": frida.ListByCategory(category),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"scripts": frida.ListScripts(),
	})
}

func (h *FridaHandler) GetScript(c *gin.Context) {
	id := c.Param("id")
	script := frida.GetScript(id)
	if script == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "script not found"})
		return
	}
	c.JSON(http.StatusOK, script)
}

func (h *FridaHandler) ListCategories(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"categories": frida.Categories(),
	})
}

func (h *FridaHandler) RunScript(c *gin.Context) {
	var req struct {
		Serial  string `json:"serial" binding:"required"`
		Target  string `json:"target" binding:"required"`
		Script  string `json:"script" binding:"required"`
		Timeout int    `json:"timeout"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.runner == nil || !h.runner.IsAvailable() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "frida is not available on this system"})
		return
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	output, err := h.runner.RunScript(context.Background(), req.Serial, req.Target, req.Script, timeout)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"output": output, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": output})
}

func (h *FridaHandler) RunScriptByID(c *gin.Context) {
	id := c.Param("id")
	script := frida.GetScript(id)
	if script == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "script not found"})
		return
	}

	var req struct {
		Serial  string `json:"serial" binding:"required"`
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.runner == nil || !h.runner.IsAvailable() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "frida is not available on this system"})
		return
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	output, err := h.runner.RunScript(context.Background(), req.Serial, req.Target, script.Code, timeout)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"output": output, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": output})
}
