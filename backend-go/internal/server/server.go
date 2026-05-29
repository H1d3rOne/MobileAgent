package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/agent"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/handler"
	"github.com/mobileagent/backend-go/internal/market"
	"github.com/mobileagent/backend-go/internal/mcp"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
)

type Server struct {
	cfg           *config.Config
	store         *store.Store
	router        *gin.Engine
	httpSrv       *http.Server
	hub           *handler.WSHub
	mcpManager    *mcp.Manager
	marketService *market.Service
}

func NewServer(cfg *config.Config, s *store.Store) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)
	if cfg.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	}

	deviceStore := store.NewDeviceStore(s)
	apkStore := store.NewAPKStore(s)
	agentStore := store.NewAgentStore(s)
	marketStore, err := store.NewMarketStore(cfg.Storage.MarketDir)
	if err != nil {
		return nil, err
	}

	adbRunner := runner.NewADBRunner(cfg)
	apkRunner := runner.NewAPKRunner(cfg)
	fridaRunner := runner.NewFridaRunner(cfg)

	hub := handler.NewWSHub()
	go hub.Run()

	registry := agent.NewRegistry()
	agent.RegisterBuiltins(registry, adbRunner, apkRunner, fridaRunner, agentStore, apkStore, cfg)

	mcpManager := mcp.NewManager(cfg, marketStore)
	mcpManager.AttachRegistry(registry)
	mcpManager.Start(context.Background(), registry)

	marketService := market.NewService(marketStore, registry, mcpManager, cfg)
	if err := marketService.Initialize(context.Background()); err != nil {
		return nil, err
	}

	engine := &agent.Engine{
		Registry:     registry,
		ADB:          adbRunner,
		APK:          apkRunner,
		AgentStore:   agentStore,
		Cfg:          cfg,
		ExtManifests: marketService.LoadedManifests(),
		ApprovalMode: cfg.Agent.ApprovalMode,
	}
	engine.InitApprovalStore()

	deviceHandler := handler.NewDeviceHandler(deviceStore, adbRunner, cfg)
	apkHandler := handler.NewAPKHandler(apkStore, apkRunner, cfg)
	agentHandler := handler.NewAgentHandler(agentStore, cfg, engine)
	memoryHandler := handler.NewMemoryHandler(agentStore)
	mcpHandler := handler.NewMCPHandler(mcpManager)
	marketHandler := handler.NewMarketHandler(marketService)
	fridaHandler := handler.NewFridaHandler(fridaRunner)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	setupRoutes(r, deviceHandler, apkHandler, agentHandler, memoryHandler, mcpHandler, marketHandler, fridaHandler, hub, cfg)

	return &Server{
		cfg:           cfg,
		store:         s,
		router:        r,
		hub:           hub,
		mcpManager:    mcpManager,
		marketService: marketService,
	}, nil
}

func (srv *Server) Start() error {
	srv.httpSrv = &http.Server{
		Addr: srv.cfg.Addr(),
		Handler: srv.router,
		ReadTimeout: 30 * time.Second,
	}

	zap.L().Info("Server starting", zap.String("addr", srv.cfg.Addr()))
	go func() {
		if err := srv.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Fatal("Server failed", zap.Error(err))
		}
	}()
	return nil
}

func (srv *Server) WaitForSignal() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	zap.L().Info("Shutdown signal received")
}

func (srv *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if srv.httpSrv != nil {
		if err := srv.httpSrv.Shutdown(ctx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
	}
	if srv.mcpManager != nil {
		srv.mcpManager.Stop()
	}
	if srv.store != nil {
		if err := srv.store.Close(); err != nil {
			zap.L().Error("DB close error", zap.Error(err))
		}
	}
	zap.L().Info("Server stopped")
	return nil
}
