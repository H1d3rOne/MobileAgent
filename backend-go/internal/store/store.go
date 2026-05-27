package store

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/mobileagent/backend-go/internal/model"
)

type Store struct {
	DB *gorm.DB
}

func NewStore(dbPath string) (*Store, error) {
	dir := dbPath[:len(dbPath)-len("/mobileagent.db")]
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	logLevel := gormlogger.Default.LogMode(gormlogger.Warn)
	cfg := &gorm.Config{Logger: logLevel}
	db, err := gorm.Open(sqlite.Open(dbPath), cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := db.AutoMigrate(&model.Device{}, &model.APK{}, &model.APKAnalysis{}, &model.AgentSession{}, &model.AgentAction{}, &model.AgentMemory{}); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	zap.L().Info("Database initialized", zap.String("path", dbPath))
	return &Store{DB: db}, nil
}

func (s *Store) Close() error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
