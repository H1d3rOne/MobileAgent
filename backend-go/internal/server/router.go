package server

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/handler"
)

func setupRoutes(
	r *gin.Engine,
	dh *handler.DeviceHandler,
	ah *handler.APKHandler,
	agh *handler.AgentHandler,
	mh *handler.MemoryHandler,
	mcph *handler.MCPHandler,
	markh *handler.MarketHandler,
	fh *handler.FridaHandler,
	hub *handler.WSHub,
	cfg *config.Config,
) {
	corsConfig := cors.DefaultConfig()
	if len(cfg.Server.CORSOrigins) > 0 {
		corsConfig.AllowOrigins = cfg.Server.CORSOrigins
	} else {
		corsConfig.AllowAllOrigins = true
	}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Authorization"}
	r.Use(cors.New(corsConfig))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		v1.POST("/chat", agh.Chat)
		v1.POST("/chat/approve", agh.ApproveToolCall)

		v1.GET("/conversations", agh.ListConversations)
		v1.GET("/conversations/:id", agh.GetConversation)
		v1.GET("/conversations/:id/pending-approvals", agh.ListPendingApprovals)
		v1.DELETE("/conversations/:id", agh.DeleteConversation)
		v1.POST("/conversations/:id/rollback", agh.RollbackConversation)

		v1.GET("/devices", dh.List)
		v1.GET("/devices/:serial/info", dh.Get)
		v1.POST("/devices/:serial/shell", dh.Shell)
		v1.POST("/devices/:serial/screenshot", dh.Screenshot)
		v1.GET("/devices/:serial/battery", dh.Battery)
		v1.POST("/devices/:serial/packages", dh.Packages)
		v1.POST("/devices/:serial/connect", dh.Connect)

		v1.GET("/apk", ah.List)
		v1.GET("/apk/:id", ah.Get)
		v1.DELETE("/apk/:id", ah.Delete)
		v1.POST("/apk/analyze", ah.UploadAndAnalyze)
		v1.POST("/apk/decompile", ah.DecompileByPath)
		v1.GET("/apk/file", ah.BrowseFile)
		v1.GET("/apk/dir", ah.BrowseDir)
		v1.POST("/apk/build", ah.Build)
		v1.POST("/apk/sign", ah.Sign)
		v1.POST("/apk/install", ah.InstallByPath)
		v1.GET("/apk/:id/analyses", ah.ListAnalyses)
		v1.POST("/apk/:id/analyze/manifest", ah.AnalyzeManifest)
		v1.POST("/apk/:id/analyze/certificate", ah.AnalyzeCertificate)
		v1.POST("/apk/:id/analyze/risk", ah.AnalyzeRisk)
		v1.POST("/apk/:id/analyze/code", ah.AnalyzeCode)
		v1.POST("/apk/:id/analyze/sdk", ah.AnalyzeSDK)
		v1.POST("/apk/:id/analyze/all", ah.AnalyzeAll)
		v1.GET("/apk/:id/report", ah.GenerateReport)
		v1.GET("/apk/:id/packer", ah.DetectPacker)
		v1.POST("/apk/:id/analyze/strings", ah.ScanStrings)
		v1.POST("/apk/:id/analyze/antidetect", ah.DetectAntiDetection)
		v1.GET("/apk/:id/hooks", ah.GenerateHooks)
		v1.GET("/apk/:id/callgraph", ah.CallGraph)
		v1.GET("/apk/diff", ah.DiffAPKs)
		v1.POST("/network/parse", ah.ParseNetworkCapture)

		v1.GET("/status", agh.SystemStatus)
		v1.GET("/tools/status", agh.ToolsStatus)
		v1.POST("/tools/run", agh.RunTool)
		v1.GET("/skills", markh.ListSkills)
		v1.GET("/skills/catalog", markh.ListSkillCatalog)
		v1.GET("/skills/installed", markh.ListInstalledSkills)
		v1.POST("/skills/install", markh.InstallSkill)
		v1.POST("/skills/:id/enable", markh.EnableSkill)
		v1.POST("/skills/:id/disable", markh.DisableSkill)
		v1.DELETE("/skills/:id", markh.DeleteSkill)

		v1.GET("/memory", mh.List)
		v1.POST("/memory", mh.Create)
		v1.DELETE("/memory/:id", mh.Delete)

		v1.GET("/mcp/servers", markh.Servers)
		v1.GET("/mcp/tools", mcph.Tools)
		v1.GET("/mcp/catalog", markh.ListMCPCatalog)
		v1.GET("/mcp/installed", markh.ListInstalledMCPs)
		v1.POST("/mcp/install", markh.InstallMCP)
		v1.POST("/mcp/manual", markh.InstallMCP)
		v1.POST("/mcp/:id/enable", markh.EnableMCP)
		v1.POST("/mcp/:id/disable", markh.DisableMCP)
		v1.POST("/mcp/:id/restart", markh.RestartMCP)
		v1.DELETE("/mcp/:id", markh.DeleteMCP)

		v1.GET("/market/sources", markh.ListSources)
		v1.POST("/market/sources", markh.AddSource)
		v1.DELETE("/market/sources/:id", markh.DeleteSource)
		v1.POST("/market/refresh", markh.Refresh)

		v1.GET("/frida/scripts", fh.ListScripts)
		v1.GET("/frida/scripts/:id", fh.GetScript)
		v1.POST("/frida/scripts/:id/run", fh.RunScriptByID)
		v1.POST("/frida/run", fh.RunScript)
		v1.GET("/frida/categories", fh.ListCategories)
	}

	r.GET("/ws", handler.HandleWebSocket(hub))
}
