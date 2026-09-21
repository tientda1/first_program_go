package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"gologin/internal/config"
	"gologin/internal/model"
	"gologin/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountDeleted     = errors.New("account deleted")
	ErrAccountLocked      = errors.New("account locked")
)

type UserStore interface {
	FindByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	FindByID(ctx context.Context, id int64) (*model.User, error)
	RegisterFailedAttempt(ctx context.Context, id int64, maxAttempts int, lockUntil time.Time) error
	ResetFailedAttempts(ctx context.Context, id int64) error
}

type SessionStore interface {
	Create(ctx context.Context, s *model.Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	DeleteExpired(ctx context.Context) (int64, error)
	DeleteByUserID(ctx context.Context, userID int64) (int64, error)
}

type AuthService struct {
	users     UserStore
	sessions  SessionStore
	cfg       config.Config
	dummyHash []byte
}

func NewAuthService(cfg config.Config, users UserStore, sessions SessionStore) (*AuthService, error) {
	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), cfg.BcryptCost)
	if err != nil {
		return nil, err
	}
	return &AuthService{
		users:     users,
		sessions:  sessions,
		cfg:       cfg,
		dummyHash: dummy,
	}, nil
}

type LoginResult struct {
	User      model.PublicUser
	Token     string
	ExpiresAt time.Time
}

func (s *AuthService) Login(ctx context.Context, identifier, password, ip, userAgent string) (*LoginResult, error) {
	now := time.Now()

	user, err := s.users.FindByUsernameOrEmail(ctx, identifier)
	if errors.Is(err, repository.ErrNotFound) {
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if user.IsDeleted() {
		return nil, ErrAccountDeleted
	}

	if user.IsLocked(now) {
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		lockUntil := now.Add(s.cfg.LockDuration)
		if err := s.users.RegisterFailedAttempt(ctx, user.ID, s.cfg.MaxLoginAttempts, lockUntil); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}

	if err := s.users.ResetFailedAttempts(ctx, user.ID); err != nil {
		return nil, err
	}

	token, tokenHash := newToken()
	expiresAt := now.Add(s.cfg.SessionTTL)

	session := &model.Session{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		IP:        ip,
		UserAgent: userAgent,
		ExpiresAt: expiresAt,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}

	return &LoginResult{
		User:      user.Public(),
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *AuthService) Authenticate(ctx context.Context, token string) (*model.User, error) {
	if token == "" {
		return nil, ErrInvalidCredentials
	}

	session, err := s.sessions.FindByTokenHash(ctx, HashToken(token))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if user.IsDeleted() {
		return nil, ErrAccountDeleted
	}
	if user.IsLocked(time.Now()) {
		return nil, ErrAccountLocked
	}

	return user, nil
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.sessions.DeleteByTokenHash(ctx, HashToken(token))
}

func (s *AuthService) LogoutAll(ctx context.Context, userID int64) error {
	_, err := s.sessions.DeleteByUserID(ctx, userID)
	return err
}

func (s *AuthService) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	return s.sessions.DeleteExpired(ctx)
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() (token string, tokenHash string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	token = hex.EncodeToString(buf)
	return token, HashToken(token)
}
