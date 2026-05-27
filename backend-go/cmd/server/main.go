package main

import (
	"flag"
	"os"

	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/server"
	"github.com/mobileagent/backend-go/internal/store"
)

func main() {
	configPath := flag.String("config", "", "config file path")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	logger := cfg.InitLogger()
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	for _, dir := range []string{
		cfg.Storage.UploadDir,
		cfg.Storage.WorkspaceDir,
		cfg.Storage.MemoryDir,
		cfg.Storage.MarketDir,
		cfg.Storage.SkillsDir,
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			zap.L().Fatal("Failed to create directory", zap.String("dir", dir), zap.Error(err))
		}
	}

	s, err := store.NewStore(cfg.Storage.DBPath)
	if err != nil {
		zap.L().Fatal("Failed to initialize store", zap.Error(err))
	}

	srv, err := server.NewServer(cfg, s)
	if err != nil {
		zap.L().Fatal("Failed to create server", zap.Error(err))
	}

	if err := srv.Start(); err != nil {
		zap.L().Fatal("Failed to start server", zap.Error(err))
	}

	go func() {
		adbRunner := runner.NewADBRunner(cfg)
		adbRunner.AutoConnect()
	}()

	srv.WaitForSignal()

	if err := srv.Shutdown(); err != nil {
		zap.L().Error("Server shutdown error", zap.Error(err))
	}
}
