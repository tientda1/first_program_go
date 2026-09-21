package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gologin/internal/config"
	"gologin/internal/model"
	"gologin/internal/repository"
)

type fakeUserStore struct {
	user          *model.User
	findErr       error
	registerCalls int
	lastLockUntil time.Time
	resetCalled   bool
}

func (f *fakeUserStore) FindByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.user, nil
}

func (f *fakeUserStore) FindByID(ctx context.Context, id int64) (*model.User, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.user, nil
}

func (f *fakeUserStore) RegisterFailedAttempt(ctx context.Context, id int64, maxAttempts int, lockUntil time.Time) error {
	f.registerCalls++
	f.lastLockUntil = lockUntil
	return nil
}

func (f *fakeUserStore) ResetFailedAttempts(ctx context.Context, id int64) error {
	f.resetCalled = true
	return nil
}

type fakeSessionStore struct {
	created  *model.Session
	sessions map[string]*model.Session
}

func (f *fakeSessionStore) Create(ctx context.Context, s *model.Session) error {
	f.created = s
	if f.sessions == nil {
		f.sessions = make(map[string]*model.Session)
	}
	f.sessions[s.TokenHash] = s
	return nil
}

func (f *fakeSessionStore) FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	if s, ok := f.sessions[tokenHash]; ok && s.ExpiresAt.After(time.Now()) {
		return s, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeSessionStore) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	delete(f.sessions, tokenHash)
	return nil
}

func (f *fakeSessionStore) DeleteExpired(ctx context.Context) (int64, error) { return 0, nil }

func (f *fakeSessionStore) DeleteByUserID(ctx context.Context, userID int64) (int64, error) {
	var n int64
	for k, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, k)
			n++
		}
	}
	return n, nil
}

func newTestService(t *testing.T, users *fakeUserStore, sessions *fakeSessionStore) *AuthService {
	t.Helper()

	cfg := config.Config{
		BcryptCost:       bcrypt.MinCost,
		SessionTTL:       time.Hour,
		MaxLoginAttempts: 3,
		LockDuration:     15 * time.Minute,
	}

	svc, err := NewAuthService(cfg, users, sessions)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	return svc
}

func hashPassword(t *testing.T, password string) string {
	t.Helper()

	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return string(h)
}

func TestLoginSuccess(t *testing.T) {
	users := &fakeUserStore{user: &model.User{
		ID:           1,
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: hashPassword(t, "Password123!"),
		Status:       model.StatusActive,
		CreatedAt:    time.Now(),
	}}
	sessions := &fakeSessionStore{}
	svc := newTestService(t, users, sessions)

	res, err := svc.Login(context.Background(), "alice", "Password123!", "127.0.0.1", "go-test")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if res.Token == "" {
		t.Fatal("expected a token")
	}
	if res.User.Username != "alice" || res.User.ID != 1 {
		t.Fatalf("unexpected public user: %+v", res.User)
	}
	if !users.resetCalled {
		t.Fatal("expected failed attempts to be reset")
	}
	if sessions.created == nil || sessions.created.TokenHash != HashToken(res.Token) {
		t.Fatal("expected session stored with hashed token, not raw token")
	}
	if sessions.created.TokenHash == res.Token {
		t.Fatal("raw token must not be stored in database")
	}
}

func TestLoginWrongPasswordIncrementsAndLocks(t *testing.T) {
	users := &fakeUserStore{user: &model.User{
		ID:           1,
		Username:     "alice",
		PasswordHash: hashPassword(t, "Password123!"),
		Status:       model.StatusActive,
	}}
	svc := newTestService(t, users, &fakeSessionStore{})

	_, err := svc.Login(context.Background(), "alice", "wrong-password", "127.0.0.1", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if users.registerCalls != 1 {
		t.Fatalf("expected 1 failed attempt recorded, got %d", users.registerCalls)
	}
	if !users.lastLockUntil.After(time.Now()) {
		t.Fatal("expected a lock deadline in the future")
	}
}

func TestLoginUnknownUserDoesNotRevealExistence(t *testing.T) {
	users := &fakeUserStore{findErr: repository.ErrNotFound}
	svc := newTestService(t, users, &fakeSessionStore{})

	_, err := svc.Login(context.Background(), "ghost", "whatever", "127.0.0.1", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if users.registerCalls != 0 {
		t.Fatal("must not write anything for an unknown user")
	}
}

func TestLoginDeletedAccount(t *testing.T) {
	deletedAt := time.Now()
	users := &fakeUserStore{user: &model.User{
		ID:           1,
		Username:     "alice",
		PasswordHash: hashPassword(t, "Password123!"),
		Status:       model.StatusActive,
		DeletedAt:    &deletedAt,
	}}
	svc := newTestService(t, users, &fakeSessionStore{})

	_, err := svc.Login(context.Background(), "alice", "Password123!", "127.0.0.1", "")
	if !errors.Is(err, ErrAccountDeleted) {
		t.Fatalf("expected ErrAccountDeleted, got %v", err)
	}
}

func TestLoginTemporarilyLockedAccount(t *testing.T) {
	lockedUntil := time.Now().Add(10 * time.Minute)
	users := &fakeUserStore{user: &model.User{
		ID:           1,
		Username:     "alice",
		PasswordHash: hashPassword(t, "Password123!"),
		Status:       model.StatusActive,
		LockedUntil:  &lockedUntil,
	}}
	svc := newTestService(t, users, &fakeSessionStore{})

	_, err := svc.Login(context.Background(), "alice", "Password123!", "127.0.0.1", "")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLoginDisabledAccount(t *testing.T) {
	users := &fakeUserStore{user: &model.User{
		ID:           1,
		Username:     "alice",
		PasswordHash: hashPassword(t, "Password123!"),
		Status:       model.StatusLocked,
	}}
	svc := newTestService(t, users, &fakeSessionStore{})

	_, err := svc.Login(context.Background(), "alice", "Password123!", "127.0.0.1", "")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
}

func TestAuthenticateRoundTrip(t *testing.T) {
	users := &fakeUserStore{user: &model.User{
		ID:           1,
		Username:     "alice",
		PasswordHash: hashPassword(t, "Password123!"),
		Status:       model.StatusActive,
	}}
	sessions := &fakeSessionStore{}
	svc := newTestService(t, users, sessions)

	res, err := svc.Login(context.Background(), "alice", "Password123!", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	user, err := svc.Authenticate(context.Background(), res.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.ID != 1 {
		t.Fatalf("expected user 1, got %d", user.ID)
	}

	if _, err := svc.Authenticate(context.Background(), "forged-token"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for forged token, got %v", err)
	}

	if err := svc.Logout(context.Background(), res.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), res.Token); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected token to be revoked after logout, got %v", err)
	}
}
