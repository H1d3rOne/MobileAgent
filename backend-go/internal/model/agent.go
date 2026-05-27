package model

import "time"

type AgentSession struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	Title       string    `json:"title"`
	DeviceID    string    `json:"device_id" gorm:"index"`
	LLMProvider string    `json:"llm_provider"`
	LLMModel    string    `json:"llm_model"`
	Status      string    `json:"status" gorm:"default:created"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AgentAction struct {
	ID           string `json:"id" gorm:"primaryKey"`
	SessionID    string `json:"session_id" gorm:"index"`
	Type         string `json:"type"` // user_message | assistant_message | tool_call | tool_result | error
	Content      string `json:"content,omitempty" gorm:"type:text"`
	Result       string `json:"result,omitempty" gorm:"type:text"`
	ToolCallID   string `json:"tool_call_id,omitempty" gorm:"index"`
	ToolName     string `json:"tool_name,omitempty"`
	ToolArgsJSON string `json:"tool_args,omitempty" gorm:"type:text"`
	TimestampModel
}

// AgentMemory persists long-lived notes / facts available across sessions.
// Scope examples: "global", "session:<id>", "device:<serial>".
type AgentMemory struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	Scope     string    `json:"scope" gorm:"index"`
	Key       string    `json:"key" gorm:"index"`
	Value     string    `json:"value" gorm:"type:text"`
	Tags      string    `json:"tags"` // comma-separated
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WSMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}
