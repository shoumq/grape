package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"grape/dto"
	"grape/model"
	"grape/service"
)

type Server struct {
	svc      *service.Service
	upgrader websocket.Upgrader
	hubMu    sync.Mutex
	chatHubs map[int64]map[*client]struct{}
	baseCtx  context.Context
}

func NewServer(svc *service.Service, baseCtx context.Context) *Server {
	return &Server{
		svc: svc,
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			return true
		}},
		chatHubs: make(map[int64]map[*client]struct{}),
		baseCtx:  baseCtx,
	}
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.Username == "" || len(req.Password) < 8 || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "invalid input")
		return
	}
	user, err := s.svc.Register(r.Context(), req.Username, req.Password, req.PublicKey)
	if err != nil {
		writeError(w, http.StatusConflict, "username taken")
		return
	}
	writeJSON(w, http.StatusCreated, toUserDTO(user))
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	token, userID, expiresAt, err := s.svc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"user_id":    userID,
		"expires_at": expiresAt,
	})
}

func (s *Server) HandleMe(w http.ResponseWriter, r *http.Request, userID int64) {
	user, err := s.svc.GetUser(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserDTO(user))
}

func (s *Server) HandleUserByID(w http.ResponseWriter, r *http.Request, _ int64) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	idStr = strings.TrimSpace(idStr)
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "missing user id")
		return
	}
	targetID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	user, err := s.svc.GetUser(r.Context(), targetID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserDTO(user))
}

func (s *Server) HandleChats(w http.ResponseWriter, r *http.Request, userID int64) {
	switch r.Method {
	case http.MethodGet:
		chats, err := s.svc.ListChats(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list failed")
			return
		}
		resp := make([]dto.ChatResponse, 0, len(chats))
		for _, chat := range chats {
			resp = append(resp, toChatDTO(chat))
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req struct {
			PeerUserID int64 `json:"peer_user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.PeerUserID == 0 || req.PeerUserID == userID {
			writeError(w, http.StatusBadRequest, "invalid peer")
			return
		}
		if _, err := s.svc.GetUser(r.Context(), req.PeerUserID); err != nil {
			writeError(w, http.StatusNotFound, "peer not found")
			return
		}
		chatID, err := s.svc.FindOrCreateChat(r.Context(), userID, req.PeerUserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "chat failed")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{"id": chatID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) HandleChatSubroutes(w http.ResponseWriter, r *http.Request, userID int64) {
	path := strings.TrimPrefix(r.URL.Path, "/api/chats/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	chatID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid chat id")
		return
	}
	member, err := s.svc.UserInChat(r.Context(), userID, chatID)
	if err != nil || !member {
		writeError(w, http.StatusForbidden, "not a member")
		return
	}
	switch parts[1] {
	case "messages":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleMessages(w, r, chatID)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request, chatID int64) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	var beforeID int64
	if v := r.URL.Query().Get("before_id"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			beforeID = parsed
		}
	}
	messages, err := s.svc.ListMessages(r.Context(), chatID, beforeID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "messages failed")
		return
	}
	resp := make([]dto.MessageDTO, 0, len(messages))
	for _, msg := range messages {
		resp = append(resp, toMessageDTO(msg))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) RequireAuth(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, userID)
	}
}

func (s *Server) authenticate(r *http.Request) (int64, error) {
	token := extractToken(r)
	if token == "" {
		return 0, errors.New("missing token")
	}
	return s.svc.Authenticate(r.Context(), token)
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return r.URL.Query().Get("token")
}

func toUserDTO(user model.User) dto.UserResponse {
	return dto.UserResponse{ID: user.ID, Username: user.Username, PublicKey: user.PublicKey}
}

func toMessageDTO(msg model.Message) dto.MessageDTO {
	return dto.MessageDTO{
		ID:         msg.ID,
		ChatID:     msg.ChatID,
		SenderID:   msg.SenderID,
		Ciphertext: msg.Ciphertext,
		Nonce:      msg.Nonce,
		CreatedAt:  msg.CreatedAt,
	}
}

func toChatDTO(chat model.ChatSummary) dto.ChatResponse {
	resp := dto.ChatResponse{
		ID:        chat.ID,
		Peer:      toUserDTO(chat.Peer),
		CreatedAt: chat.CreatedAt,
	}
	if chat.LastMessage != nil {
		msg := toMessageDTO(*chat.LastMessage)
		resp.LastMessage = &msg
	}
	return resp
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
