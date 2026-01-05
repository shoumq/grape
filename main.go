package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"grape/config"
	"grape/handler"
	"grape/repo"
	"grape/service"
)

func main() {
	cfg := config.Load()
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("db ping: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	repository := repo.New(db)
	svc := service.New(repository, cfg.TokenTTL)
	srv := handler.NewServer(svc, ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", srv.HandleRegister)
	mux.HandleFunc("/api/login", srv.HandleLogin)
	mux.HandleFunc("/api/users/me", srv.RequireAuth(srv.HandleMe))
	mux.HandleFunc("/api/users/", srv.RequireAuth(srv.HandleUserByID))
	mux.HandleFunc("/api/chats", srv.RequireAuth(srv.HandleChats))
	mux.HandleFunc("/api/chats/", srv.RequireAuth(srv.HandleChatSubroutes))
	mux.HandleFunc("/ws", srv.HandleWebsocket)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler.CORS(handler.Logging(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}
