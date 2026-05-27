package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/market"
	"github.com/mobileagent/backend-go/internal/model"
)

type MarketHandler struct {
	service *market.Service
}

func NewMarketHandler(service *market.Service) *MarketHandler {
	return &MarketHandler{service: service}
}

func (h *MarketHandler) ListSkills(c *gin.Context) {
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: h.service.ListVisibleSkills()})
}

func (h *MarketHandler) ListSkillCatalog(c *gin.Context) {
	items, err := h.service.ListSkillCatalog()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: items})
}

func (h *MarketHandler) ListInstalledSkills(c *gin.Context) {
	items, err := h.service.ListInstalledSkills()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: items})
}

func (h *MarketHandler) InstallSkill(c *gin.Context) {
	var req market.SkillInstallInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	item, err := h.service.InstallSkill(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) EnableSkill(c *gin.Context) {
	item, err := h.service.SetSkillEnabled(c.Param("id"), true)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) DisableSkill(c *gin.Context) {
	item, err := h.service.SetSkillEnabled(c.Param("id"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) DeleteSkill(c *gin.Context) {
	if err := h.service.DeleteSkill(c.Param("id")); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

func (h *MarketHandler) Servers(c *gin.Context) {
	items, err := h.service.ListInstalledMCPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: items})
}

func (h *MarketHandler) ListMCPCatalog(c *gin.Context) {
	items, err := h.service.ListMCPCatalog()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: items})
}

func (h *MarketHandler) ListInstalledMCPs(c *gin.Context) {
	items, err := h.service.ListInstalledMCPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: items})
}

func (h *MarketHandler) InstallMCP(c *gin.Context) {
	var req market.MCPInstallInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	item, err := h.service.InstallMCP(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) EnableMCP(c *gin.Context) {
	item, err := h.service.SetMCPEnabled(c.Request.Context(), c.Param("id"), true)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) DisableMCP(c *gin.Context) {
	item, err := h.service.SetMCPEnabled(c.Request.Context(), c.Param("id"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) RestartMCP(c *gin.Context) {
	item, err := h.service.RestartMCP(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) DeleteMCP(c *gin.Context) {
	if err := h.service.DeleteMCP(c.Param("id")); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

func (h *MarketHandler) ListSources(c *gin.Context) {
	items, err := h.service.ListSources()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: items})
}

func (h *MarketHandler) AddSource(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	item, err := h.service.AddSource(req.Name, req.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusCreated, model.APIResponse{Success: true, Data: item})
}

func (h *MarketHandler) DeleteSource(c *gin.Context) {
	if err := h.service.DeleteSource(c.Param("id")); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

func (h *MarketHandler) Refresh(c *gin.Context) {
	cat, err := h.service.RefreshCatalog(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: cat})
}
