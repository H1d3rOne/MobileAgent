package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/analyzer"
	"github.com/mobileagent/backend-go/internal/frida"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

type FridaHandler struct {
	runner   *runner.FridaRunner
	apkStore *store.APKStore
}

func NewFridaHandler(r *runner.FridaRunner, apkStore ...*store.APKStore) *FridaHandler {
	var s *store.APKStore
	if len(apkStore) > 0 {
		s = apkStore[0]
	}
	return &FridaHandler{runner: r, apkStore: s}
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
		APKID   string `json:"apk_id"`
		HookID  string `json:"hook_id"`
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
	data := gin.H{
		"output":   output,
		"evidence": frida.ParseRuntimeEvidence(output),
	}
	if saved, saveErr := h.persistRuntimeEvidence(req.APKID, req.Serial, req.Target, req.HookID, "", output, data["evidence"], err); saveErr != nil {
		data["evidence_persist_error"] = saveErr.Error()
	} else if saved {
		data["evidence_persisted"] = true
	}
	if err != nil {
		data["error"] = err.Error()
		c.JSON(http.StatusOK, gin.H{"success": true, "data": data, "output": output, "error": err.Error(), "evidence": data["evidence"]})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data, "output": output, "evidence": data["evidence"]})
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
		APKID   string `json:"apk_id"`
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
	data := gin.H{
		"output":   output,
		"evidence": frida.ParseRuntimeEvidence(output),
	}
	if saved, saveErr := h.persistRuntimeEvidence(req.APKID, req.Serial, req.Target, script.ID, id, output, data["evidence"], err); saveErr != nil {
		data["evidence_persist_error"] = saveErr.Error()
	} else if saved {
		data["evidence_persisted"] = true
	}
	if err != nil {
		data["error"] = err.Error()
		c.JSON(http.StatusOK, gin.H{"success": true, "data": data, "output": output, "error": err.Error(), "evidence": data["evidence"]})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data, "output": output, "evidence": data["evidence"]})
}

func (h *FridaHandler) persistRuntimeEvidence(apkID, serial, target, hookID, scriptID, output string, evidence any, runErr error) (bool, error) {
	if h.apkStore == nil || apkID == "" {
		return false, nil
	}
	ev, ok := evidence.(frida.RuntimeEvidence)
	if !ok || ev.Summary.Total == 0 {
		return false, nil
	}
	apk, err := h.apkStore.Get(apkID)
	if err != nil {
		return false, err
	}
	if apk == nil {
		return false, nil
	}
	payload := map[string]any{
		"apk_id":     apkID,
		"serial":     serial,
		"target":     target,
		"hook_id":    hookID,
		"script_id":  scriptID,
		"evidence":   ev,
		"output":     output,
		"created_at": time.Now(),
	}
	if runErr != nil {
		payload["error"] = runErr.Error()
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	return true, h.apkStore.UpsertAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apkID,
		Type:      analyzer.TypeRuntimeEvidence,
		Result:    string(raw),
		CreatedAt: time.Now(),
	})
}
