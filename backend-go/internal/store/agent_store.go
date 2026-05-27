package store

import (
	"errors"

	"github.com/mobileagent/backend-go/internal/model"
	"gorm.io/gorm"
)

type AgentStore struct {
	store *Store
}

func NewAgentStore(s *Store) *AgentStore {
	return &AgentStore{store: s}
}

// DB exposes the underlying gorm.DB for advanced queries.
func (as *AgentStore) DB() *gorm.DB {
	return as.store.DB
}

func (as *AgentStore) ListSessions() ([]model.AgentSession, error) {
	var sessions []model.AgentSession
	err := as.store.DB.Find(&sessions).Error
	return sessions, err
}

func (as *AgentStore) GetSession(id string) (*model.AgentSession, error) {
	var s model.AgentSession
	err := as.store.DB.Where("id = ?", id).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &s, err
}

func (as *AgentStore) CreateSession(s *model.AgentSession) error {
	return as.store.DB.Create(s).Error
}

func (as *AgentStore) UpdateSession(s *model.AgentSession) error {
	return as.store.DB.Save(s).Error
}

func (as *AgentStore) DeleteSession(id string) error {
	return as.store.DB.Where("id = ?", id).Delete(&model.AgentSession{}).Error
}

func (as *AgentStore) CreateAction(a *model.AgentAction) error {
	return as.store.DB.Create(a).Error
}

func (as *AgentStore) ListActions(sessionID string) ([]model.AgentAction, error) {
	var actions []model.AgentAction
	err := as.store.DB.Where("session_id = ?", sessionID).Order("created_at asc").Find(&actions).Error
	return actions, err
}

// DeleteActionsFrom deletes the action with the given ID and all subsequent actions in the session.
func (as *AgentStore) DeleteActionsFrom(sessionID, actionID string) error {
	var target model.AgentAction
	if err := as.store.DB.Where("id = ? AND session_id = ?", actionID, sessionID).First(&target).Error; err != nil {
		return err
	}
	return as.store.DB.Where("session_id = ? AND created_at >= ?", sessionID, target.CreatedAt).
		Delete(&model.AgentAction{}).Error
}

// ListPendingApprovals returns unresolved pending_approval actions for a session.
func (as *AgentStore) ListPendingApprovals(sessionID string) ([]model.AgentAction, error) {
	var actions []model.AgentAction
	err := as.store.DB.Where("session_id = ? AND type = ? AND result = ''", sessionID, "pending_approval").
		Order("created_at asc").Find(&actions).Error
	return actions, err
}

// ResolvePendingApproval marks a pending_approval as resolved.
func (as *AgentStore) ResolvePendingApproval(toolCallID string, approved bool) error {
	result := "denied"
	if approved {
		result = "approved"
	}
	return as.store.DB.Model(&model.AgentAction{}).
		Where("tool_call_id = ? AND type = ?", toolCallID, "pending_approval").
		Update("result", result).Error
}

// === Memory ===

func (as *AgentStore) SaveMemory(m *model.AgentMemory) error {
	return as.store.DB.Create(m).Error
}

func (as *AgentStore) UpdateMemory(m *model.AgentMemory) error {
	return as.store.DB.Save(m).Error
}

func (as *AgentStore) DeleteMemory(id string) error {
	return as.store.DB.Where("id = ?", id).Delete(&model.AgentMemory{}).Error
}

// SearchMemory: scopes (any of) + LIKE on key/value/tags. Empty query returns latest.
func (as *AgentStore) SearchMemory(scopes []string, query string, limit int) ([]model.AgentMemory, error) {
	if limit <= 0 {
		limit = 20
	}
	q := as.store.DB.Model(&model.AgentMemory{})
	if len(scopes) > 0 {
		q = q.Where("scope IN ?", scopes)
	}
	if query != "" {
		like := "%" + query + "%"
		q = q.Where("key LIKE ? OR value LIKE ? OR tags LIKE ?", like, like, like)
	}
	var rows []model.AgentMemory
	err := q.Order("updated_at desc").Limit(limit).Find(&rows).Error
	return rows, err
}

func (as *AgentStore) GetMemory(id string) (*model.AgentMemory, error) {
	var m model.AgentMemory
	err := as.store.DB.Where("id = ?", id).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &m, err
}
