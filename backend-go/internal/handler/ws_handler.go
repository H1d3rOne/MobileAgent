package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/model"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WSHub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan model.WSMessage
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.RWMutex
}

func NewWSHub() *WSHub {
	return &WSHub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan model.WSMessage, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
}

func (h *WSHub) Run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()
			zap.L().Info("WS client connected", zap.Int("total", len(h.clients)))
		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()
			zap.L().Info("WS client disconnected", zap.Int("total", len(h.clients)))
		case msg := <-h.broadcast:
			h.mu.RLock()
			data, err := json.Marshal(msg)
			if err != nil {
				h.mu.RUnlock()
				continue
			}
			for conn := range h.clients {
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					go func(c *websocket.Conn) {
						h.unregister <- c
					}(conn)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *WSHub) BroadcastToAll(msg model.WSMessage) {
	h.broadcast <- msg
}

func HandleWebSocket(hub *WSHub) gin.HandlerFunc {
	return func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			zap.L().Error("WS upgrade failed", zap.Error(err))
			return
		}
		hub.register <- conn

		defer func() {
			hub.unregister <- conn
		}()

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			var msg model.WSMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				continue
			}
			msg.Timestamp = time.Now().UnixMilli()

			switch msg.Type {
			case "ping":
				hub.BroadcastToAll(model.WSMessage{Type: "pong", Timestamp: time.Now().UnixMilli()})
			default:
				zap.L().Debug("WS message", zap.String("type", msg.Type))
			}
		}
	}
}
