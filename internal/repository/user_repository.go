package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gologin/internal/model"
)

var ErrNotFound = errors.New("record not found")

const userColumns = `id, username, email, password_hash, status, failed_attempts, locked_until, deleted_at, created_at, updated_at`

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error) {
	const q = `SELECT ` + userColumns + `
FROM users
WHERE username = $1 OR email = lower($1)
ORDER BY id
LIMIT 1`

	var u model.User
	err := r.db.QueryRowContext(ctx, q, identifier).Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.Status,
		&u.FailedAttempts,
		&u.LockedUntil,
		&u.DeletedAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id int64) (*model.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = $1`

	var u model.User
	err := r.db.QueryRowContext(ctx, q, id).Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.Status,
		&u.FailedAttempts,
		&u.LockedUntil,
		&u.DeletedAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) RegisterFailedAttempt(ctx context.Context, id int64, maxAttempts int, lockUntil time.Time) error {
	const q = `
UPDATE users
SET failed_attempts = failed_attempts + 1,
    locked_until    = CASE WHEN failed_attempts + 1 >= $2 THEN $3 ELSE locked_until END,
    updated_at      = now()
WHERE id = $1`

	_, err := r.db.ExecContext(ctx, q, id, maxAttempts, lockUntil)
	return err
}

func (r *UserRepository) ResetFailedAttempts(ctx context.Context, id int64) error {
	const q = `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, q, id)
	return err
}
