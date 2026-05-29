package config

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"github.com/spf13/viper"
)

type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	ADB     ADBConfig     `mapstructure:"adb"`
	LLM     LLMConfig     `mapstructure:"llm"`
	Tools   ToolsConfig   `mapstructure:"tools"`
	Storage StorageConfig `mapstructure:"storage"`
	Log     LogConfig     `mapstructure:"log"`
	Agent   AgentConfig   `mapstructure:"agent"`
	Skills  SkillsConfig  `mapstructure:"skills"`
	MCP     MCPConfig     `mapstructure:"mcp"`
	Sandbox SandboxConfig `mapstructure:"sandbox"`
}

type SandboxConfig struct {
	// Enabled controls whether command validation is active. Default: true.
	Enabled bool `mapstructure:"enabled"`
	// AllowedCommands is the whitelist of binary names permitted to execute.
	// If empty and Enabled is true, the built-in default whitelist is used.
	AllowedCommands []string `mapstructure:"allowed_commands"`
}

type ServerConfig struct {
	Host        string   `mapstructure:"host"`
	Port        int      `mapstructure:"port"`
	CORSOrigins []string `mapstructure:"cors_origins"`
}

type ADBConfig struct {
	Path             string   `mapstructure:"path"`
	AutoConnectAddrs []string `mapstructure:"auto_connect_addrs"`
	ConnectTimeout   int      `mapstructure:"connect_timeout"`
	ShellTimeout     int      `mapstructure:"shell_timeout"`
	AutoConnect      bool     `mapstructure:"auto_connect"`
	DiscoverInterval int      `mapstructure:"discover_interval"`
}

type LLMConfig struct {
	Provider string `mapstructure:"provider"`
	Model    string `mapstructure:"model"`
	APIKey   string `mapstructure:"api_key"`
	BaseURL  string `mapstructure:"base_url"`
	APIType  string `mapstructure:"api_type"`
}

type ToolsConfig struct {
	APKTool        string `mapstructure:"apktool"`
	JADX           string `mapstructure:"jadx"`
	Frida          string `mapstructure:"frida"`
	Radare2        string `mapstructure:"radare2"`
	Androguard     string `mapstructure:"androguard"`
	UberApkSigner  string `mapstructure:"uber_apk_signer"`
	Bundletool     string `mapstructure:"bundletool"`
	Mitmproxy      string `mapstructure:"mitmproxy"`
}

type StorageConfig struct {
	DBPath          string `mapstructure:"db_path"`
	UploadDir       string `mapstructure:"upload_dir"`
	WorkspaceDir    string `mapstructure:"workspace_dir"`
	MemoryDir       string `mapstructure:"memory_dir"`
	MarketDir       string `mapstructure:"market_dir"`
	SkillsDir       string `mapstructure:"skills_dir"`
	MaxUploadSizeMB int    `mapstructure:"max_upload_size_mb"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type AgentConfig struct {
	MaxIterations      int    `mapstructure:"max_iterations"`
	HistoryMaxMessages int    `mapstructure:"history_max_messages"`
	MemoryRecallTopK   int    `mapstructure:"memory_recall_top_k"`
	ApprovalMode       string `mapstructure:"approval_mode"`
}

type SkillsConfig struct {
	ShellTimeoutSeconds int      `mapstructure:"shell_timeout_seconds"`
	ShellMaxOutputBytes int      `mapstructure:"shell_max_output_bytes"`
	ShellAllowPrefixes  []string `mapstructure:"shell_allow_prefixes"`
}

type MCPServerConfig struct {
	Command []string          `mapstructure:"command"`
	Env     map[string]string `mapstructure:"env"`
}

type MCPConfig struct {
	Servers map[string]MCPServerConfig `mapstructure:"servers"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
	}

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("adb.path", "../tools/bin/adb")
	v.SetDefault("adb.connect_timeout", 10)
	v.SetDefault("adb.shell_timeout", 30)
	v.SetDefault("adb.auto_connect", true)
	v.SetDefault("adb.discover_interval", 30)
	v.SetDefault("tools.apktool", "../tools/bin/apktool")
	v.SetDefault("tools.jadx", "../tools/bin/jadx")
	v.SetDefault("tools.frida", "../tools/bin/frida")
	v.SetDefault("tools.radare2", "../tools/bin/r2")
	v.SetDefault("tools.androguard", "../tools/bin/androguard")
	v.SetDefault("tools.uber_apk_signer", "../tools/bin/uber-apk-signer")
	v.SetDefault("tools.bundletool", "../tools/bin/bundletool")
	v.SetDefault("tools.mitmproxy", "../tools/bin/mitmproxy")
	v.SetDefault("storage.db_path", "./data/mobileagent.db")
	v.SetDefault("storage.upload_dir", "./data/uploads")
	v.SetDefault("storage.workspace_dir", "./data/workspace")
	v.SetDefault("storage.memory_dir", "./data/memory")
	v.SetDefault("storage.market_dir", "./data/market")
	v.SetDefault("storage.skills_dir", "./data/skills")
	v.SetDefault("storage.max_upload_size_mb", 500)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "console")
	v.SetDefault("agent.max_iterations", 10)
	v.SetDefault("agent.history_max_messages", 40)
	v.SetDefault("agent.memory_recall_top_k", 5)
	v.SetDefault("agent.approval_mode", "approval")
	v.SetDefault("skills.shell_timeout_seconds", 30)
	v.SetDefault("skills.shell_max_output_bytes", 65536)
	v.SetDefault("llm.api_type", "chat_completions")
	v.SetDefault("sandbox.enabled", true)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) ADBConnectTimeout() int {
	if c.ADB.ConnectTimeout <= 0 {
		return 10
	}
	return c.ADB.ConnectTimeout
}

func (c *Config) ADBShellTimeout() int {
	if c.ADB.ShellTimeout <= 0 {
		return 30
	}
	return c.ADB.ShellTimeout
}

func (c *Config) MaxUploadSize() int64 {
	if c.Storage.MaxUploadSizeMB <= 0 {
		return 500 * 1024 * 1024
	}
	return int64(c.Storage.MaxUploadSizeMB) * 1024 * 1024
}

func (c *Config) InitLogger() *zap.Logger {
	level, err := zapcore.ParseLevel(c.Log.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	var encoder zapcore.Encoder
	if c.Log.Format == "console" {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level)
	return zap.New(core, zap.AddCaller())
}

// Addr returns the server listen address
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
