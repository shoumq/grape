package repo

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"grape/model"
)

var ErrUsernameTaken = errors.New("username taken")

type Repository struct {
	db *sql.DB
}

func New(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateUser(ctx context.Context, username, passwordHash, publicKey string) (int64, error) {
	var userID int64
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO users (username, password_hash, public_key) VALUES ($1, $2, $3) RETURNING id`,
		username, passwordHash, publicKey,
	).Scan(&userID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_username_key" {
			return 0, ErrUsernameTaken
		}
		return 0, err
	}
	return userID, err
}

func (r *Repository) GetUser(ctx context.Context, userID int64) (model.User, error) {
	var u model.User
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, public_key FROM users WHERE id = $1`,
		userID,
	).Scan(&u.ID, &u.Username, &u.PublicKey)
	return u, err
}

func (r *Repository) SearchUsers(ctx context.Context, username string, limit int, excludeUserID int64) ([]model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, public_key
		   FROM users
		  WHERE id <> $2 AND username ILIKE $1
		  ORDER BY username
		  LIMIT $3`,
		"%"+username+"%", excludeUserID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Username, &u.PublicKey); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *Repository) RandomUsers(ctx context.Context, limit int, excludeUserID int64) ([]model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, public_key
		   FROM users
		  WHERE id <> $1
		  ORDER BY random()
		  LIMIT $2`,
		excludeUserID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Username, &u.PublicKey); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *Repository) GetUserByUsername(ctx context.Context, username string) (int64, string, error) {
	var userID int64
	var hash string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE username = $1`,
		username,
	).Scan(&userID, &hash)
	return userID, hash, err
}

func (r *Repository) CreateSession(ctx context.Context, userID int64, token string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, token, expiresAt,
	)
	return err
}

func (r *Repository) GetSessionUserID(ctx context.Context, token string) (int64, error) {
	var userID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT user_id FROM sessions WHERE token = $1 AND expires_at > NOW()`,
		token,
	).Scan(&userID)
	return userID, err
}

func (r *Repository) UserInChat(ctx context.Context, userID, chatID int64) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2)`,
		chatID, userID,
	).Scan(&exists)
	return exists, err
}

func (r *Repository) FindOrCreateChat(ctx context.Context, userID, peerID int64) (int64, error) {
	var chatID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT m1.chat_id
		 FROM chat_members m1
		 JOIN chat_members m2 ON m1.chat_id = m2.chat_id
		 WHERE m1.user_id = $1 AND m2.user_id = $2
		 LIMIT 1`,
		userID, peerID,
	).Scan(&chatID)
	if err == nil {
		return chatID, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `INSERT INTO chats DEFAULT VALUES RETURNING id`).Scan(&chatID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2), ($1, $3)`,
		chatID, userID, peerID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return chatID, nil
}

func (r *Repository) ListChats(ctx context.Context, userID int64) ([]model.ChatSummary, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT c.id,
		        c.created_at,
		        u.id,
		        u.username,
		        u.public_key,
		        m.id,
		        m.sender_id,
		        m.ciphertext,
		        m.nonce,
		        m.created_at
		   FROM chats c
		   JOIN chat_members cm ON cm.chat_id = c.id
		   JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id <> $1
		   JOIN users u ON u.id = cm2.user_id
		   LEFT JOIN LATERAL (
		       SELECT id, sender_id, ciphertext, nonce, created_at
		         FROM messages
		        WHERE chat_id = c.id
		        ORDER BY id DESC
		        LIMIT 1
		   ) m ON TRUE
		  WHERE cm.user_id = $1
		  ORDER BY c.id DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chats []model.ChatSummary
	for rows.Next() {
		var chat model.ChatSummary
		var lastID sql.NullInt64
		var lastSender sql.NullInt64
		var lastCipher sql.NullString
		var lastNonce sql.NullString
		var lastCreated sql.NullTime
		if err := rows.Scan(
			&chat.ID,
			&chat.CreatedAt,
			&chat.Peer.ID,
			&chat.Peer.Username,
			&chat.Peer.PublicKey,
			&lastID,
			&lastSender,
			&lastCipher,
			&lastNonce,
			&lastCreated,
		); err != nil {
			return nil, err
		}
		if lastID.Valid {
			chat.LastMessage = &model.Message{
				ID:         lastID.Int64,
				ChatID:     chat.ID,
				SenderID:   lastSender.Int64,
				Ciphertext: lastCipher.String,
				Nonce:      lastNonce.String,
				CreatedAt:  lastCreated.Time,
			}
		}
		chats = append(chats, chat)
	}
	return chats, rows.Err()
}

func (r *Repository) ListMessages(ctx context.Context, chatID, beforeID int64, limit int) ([]model.Message, error) {
	var rows *sql.Rows
	var err error
	if beforeID > 0 {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, chat_id, sender_id, ciphertext, nonce, created_at
			   FROM messages
			  WHERE chat_id = $1 AND id < $2
			  ORDER BY id DESC
			  LIMIT $3`,
			chatID, beforeID, limit,
		)
	} else {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, chat_id, sender_id, ciphertext, nonce, created_at
			   FROM messages
			  WHERE chat_id = $1
			  ORDER BY id DESC
			  LIMIT $2`,
			chatID, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []model.Message
	for rows.Next() {
		var msg model.Message
		if err := rows.Scan(&msg.ID, &msg.ChatID, &msg.SenderID, &msg.Ciphertext, &msg.Nonce, &msg.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}
	return messages, nil
}

func (r *Repository) StoreMessage(ctx context.Context, chatID, userID int64, ciphertext, nonce string) (model.Message, error) {
	var msg model.Message
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO messages (chat_id, sender_id, ciphertext, nonce)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, chat_id, sender_id, ciphertext, nonce, created_at`,
		chatID, userID, ciphertext, nonce,
	).Scan(&msg.ID, &msg.ChatID, &msg.SenderID, &msg.Ciphertext, &msg.Nonce, &msg.CreatedAt)
	return msg, err
}
