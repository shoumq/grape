package model

import "time"

type User struct {
	ID        int64
	Username  string
	PublicKey string
}

type Message struct {
	ID         int64
	ChatID     int64
	SenderID   int64
	Ciphertext string
	Nonce      string
	CreatedAt  time.Time
}

type ChatSummary struct {
	ID          int64
	Peer        User
	CreatedAt   time.Time
	LastMessage *Message
}
