package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"grape/model"
	"grape/repo"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrUsernameTaken = errors.New("username taken")

type Service struct {
	repo     *repo.Repository
	tokenTTL time.Duration
}

func New(r *repo.Repository, tokenTTL time.Duration) *Service {
	return &Service{repo: r, tokenTTL: tokenTTL}
}

func (s *Service) Register(ctx context.Context, username, password, publicKey string) (model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.User{}, err
	}
	userID, err := s.repo.CreateUser(ctx, username, string(hash), publicKey)
	if err != nil {
		if errors.Is(err, repo.ErrUsernameTaken) {
			return model.User{}, ErrUsernameTaken
		}
		return model.User{}, err
	}
	return model.User{ID: userID, Username: username, PublicKey: publicKey}, nil
}

func (s *Service) Login(ctx context.Context, username, password string) (string, int64, time.Time, error) {
	userID, hash, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return "", 0, time.Time{}, ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", 0, time.Time{}, ErrUnauthorized
	}
	token, err := generateToken(32)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	expiresAt := time.Now().Add(s.tokenTTL)
	if err := s.repo.CreateSession(ctx, userID, token, expiresAt); err != nil {
		return "", 0, time.Time{}, err
	}
	return token, userID, expiresAt, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (int64, error) {
	return s.repo.GetSessionUserID(ctx, token)
}

func (s *Service) GetUser(ctx context.Context, userID int64) (model.User, error) {
	return s.repo.GetUser(ctx, userID)
}

func (s *Service) SearchUsers(ctx context.Context, username string, limit int, excludeUserID int64) ([]model.User, error) {
	return s.repo.SearchUsers(ctx, username, limit, excludeUserID)
}

func (s *Service) RandomUsers(ctx context.Context, limit int, excludeUserID int64) ([]model.User, error) {
	return s.repo.RandomUsers(ctx, limit, excludeUserID)
}

func (s *Service) UserInChat(ctx context.Context, userID, chatID int64) (bool, error) {
	return s.repo.UserInChat(ctx, userID, chatID)
}

func (s *Service) FindOrCreateChat(ctx context.Context, userID, peerID int64) (int64, error) {
	return s.repo.FindOrCreateChat(ctx, userID, peerID)
}

func (s *Service) ListChats(ctx context.Context, userID int64) ([]model.ChatSummary, error) {
	return s.repo.ListChats(ctx, userID)
}

func (s *Service) ListMessages(ctx context.Context, chatID, beforeID int64, limit int) ([]model.Message, error) {
	return s.repo.ListMessages(ctx, chatID, beforeID, limit)
}

func (s *Service) StoreMessage(ctx context.Context, chatID, userID int64, ciphertext, nonce string) (model.Message, error) {
	return s.repo.StoreMessage(ctx, chatID, userID, ciphertext, nonce)
}

func generateToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
