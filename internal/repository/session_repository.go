package repository

import (
	"context"
	"database/sql"
	"errors"

	"gologin/internal/model"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s *model.Session) error {
	const q = `
INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.db.ExecContext(ctx, q, s.ID, s.UserID, s.TokenHash, s.IP, s.UserAgent, s.ExpiresAt)
	return err
}

func (r *SessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	const q = `
SELECT id, user_id, token_hash, ip, user_agent, expires_at, created_at
FROM sessions
WHERE token_hash = $1 AND expires_at > now()`

	var s model.Session
	err := r.db.QueryRowContext(ctx, q, tokenHash).Scan(
		&s.ID,
		&s.UserID,
		&s.TokenHash,
		&s.IP,
		&s.UserAgent,
		&s.ExpiresAt,
		&s.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SessionRepository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID int64) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}
