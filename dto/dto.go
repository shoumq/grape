package dto

import "time"

type UserResponse struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type ChatResponse struct {
	ID          int64        `json:"id"`
	Peer        UserResponse `json:"peer"`
	CreatedAt   time.Time    `json:"created_at"`
	LastMessage *MessageDTO  `json:"last_message,omitempty"`
}

type MessageDTO struct {
	ID         int64     `json:"id"`
	ChatID     int64     `json:"chat_id"`
	SenderID   int64     `json:"sender_id"`
	Ciphertext string    `json:"ciphertext"`
	Nonce      string    `json:"nonce"`
	CreatedAt  time.Time `json:"created_at"`
}
