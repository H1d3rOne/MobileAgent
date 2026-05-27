package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

type DeviceHandler struct {
	store  *store.DeviceStore
	runner *runner.ADBRunner
	cfg    *config.Config
}

func NewDeviceHandler(s *store.DeviceStore, r *runner.ADBRunner, cfg *config.Config) *DeviceHandler {
	return &DeviceHandler{store: s, runner: r, cfg: cfg}
}

func (h *DeviceHandler) List(c *gin.Context) {
	devices, err := h.store.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: devices})
}

func (h *DeviceHandler) Get(c *gin.Context) {
	serial := c.Param("serial")
	device, err := h.store.GetBySerial(serial)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if device == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "device not found"})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: device})
}

func (h *DeviceHandler) Connect(c *gin.Context) {
	var req struct {
		Address string `json:"address"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.runner.ConnectDevice(req.Address); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"address": req.Address, "status": "connected"}})
}

func (h *DeviceHandler) Disconnect(c *gin.Context) {
	id := c.Param("id")
	device, err := h.store.Get(id)
	if err != nil || device == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "device not found"})
		return
	}
	addr := device.IPAddress
	if device.Port > 0 {
		addr = addr + ":" + fmt.Sprintf("%d", device.Port)
	}
	_ = h.runner.DisconnectDevice(addr)
	device.Status = "disconnected"
	h.store.Update(device)
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

func (h *DeviceHandler) Refresh(c *gin.Context) {
	id := c.Param("id")
	device, err := h.store.Get(id)
	if err != nil || device == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "device not found"})
		return
	}
	if err := h.runner.RefreshDeviceInfo(device); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	device.UpdatedAt = time.Now()
	h.store.Update(device)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: device})
}

func (h *DeviceHandler) Shell(c *gin.Context) {
	serial := c.Param("serial")
	var req struct {
		Command string `json:"command"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	out, err := h.runner.Shell(serial, req.Command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"output": out}})
}

func (h *DeviceHandler) Screenshot(c *gin.Context) {
	serial := c.Param("serial")
	path, err := h.runner.Screenshot(serial)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"path": path}})
}

func (h *DeviceHandler) Battery(c *gin.Context) {
	serial := c.Param("serial")
	out, err := h.runner.Shell(serial, "dumpsys battery")
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"raw": out}})
}

func (h *DeviceHandler) Packages(c *gin.Context) {
	serial := c.Param("serial")
	var req struct {
		Filter string `json:"filter"`
	}
	_ = c.ShouldBindJSON(&req)
	cmd := "pm list packages"
	if req.Filter != "" {
		cmd += " " + req.Filter
	}
	out, err := h.runner.Shell(serial, cmd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"raw": out}})
}

func (h *DeviceHandler) SyncDevices(c *gin.Context) {
	externalDevices, err := h.runner.ListDevices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	var synced []model.Device
	for _, ed := range externalDevices {
		if ed["status"] != "device" {
			continue
		}
		existing, _ := h.store.GetBySerial(ed["serial"])
		if existing != nil {
			existing.Status = "online"
			existing.UpdatedAt = time.Now()
			h.store.Update(existing)
			synced = append(synced, *existing)
			continue
		}
		d := &model.Device{
			ID:     util.NewID(),
			Serial: ed["serial"],
			Status: "online",
		}
		h.runner.RefreshDeviceInfo(d)
		d.CreatedAt = time.Now()
		d.UpdatedAt = time.Now()
		h.store.Create(d)
		synced = append(synced, *d)
	}
	zap.L().Info("Synced devices", zap.Int("count", len(synced)))
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: synced})
}
