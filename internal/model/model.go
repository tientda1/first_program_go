package model

import "time"

const (
	StatusLocked int16 = 0
	StatusActive int16 = 1
)

type User struct {
	ID             int64
	Username       string
	Email          string
	PasswordHash   string
	Status         int16
	FailedAttempts int32
	LockedUntil    *time.Time
	DeletedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (u User) IsDeleted() bool {
	return u.DeletedAt != nil
}

func (u User) IsLocked(now time.Time) bool {
	if u.Status == StatusLocked {
		return true
	}
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

type PublicUser struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func (u User) Public() PublicUser {
	return PublicUser{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
	}
}

type Session struct {
	ID        string
	UserID    int64
	TokenHash string
	IP        string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}
