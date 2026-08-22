package users

import (
	"database/sql"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserInactive      = errors.New("user account is inactive")
)

type User struct {
	ID                string
	Sub               string
	Email             string
	EmailVerified     bool
	PasswordHash      string
	Name              string
	GivenName         string
	FamilyName        string
	Picture           string
	PreferredUsername string
	IsActive          bool
	IsPlatformAdmin   bool
	Roles             []string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

const userColumns = `id, email, email_verified, password_hash, name, given_name, family_name, picture, preferred_username, is_active, is_platform_admin, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	user := &User{}
	err := row.Scan(
		&user.ID, &user.Email, &user.EmailVerified, &user.PasswordHash,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture,
		&user.PreferredUsername, &user.IsActive, &user.IsPlatformAdmin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) GetOrgRoles(userID string) ([]string, error) {
	rows, err := r.db.Query(`
		SELECT role
		FROM org_members
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []string{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *Repository) GetByEmail(email string) (*User, error) {
	return scanUser(r.db.QueryRow(`
		SELECT `+userColumns+`
		FROM users
		WHERE email = $1
	`, email))
}

func (r *Repository) GetByID(id string) (*User, error) {
	return scanUser(r.db.QueryRow(`
		SELECT `+userColumns+`
		FROM users
		WHERE id = $1
	`, id))
}

func (r *Repository) Create(user *User) error {
	_, err := r.db.Exec(`
		INSERT INTO users (id, email, email_verified, password_hash, name, given_name, family_name, picture, preferred_username, is_active, is_platform_admin)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, user.ID, user.Email, user.EmailVerified, user.PasswordHash,
		user.Name, user.GivenName, user.FamilyName, user.Picture,
		user.PreferredUsername, user.IsActive, user.IsPlatformAdmin)
	return err
}

func (r *Repository) Update(user *User) error {
	_, err := r.db.Exec(`
		UPDATE users
		SET email = $2, email_verified = $3, name = $4, given_name = $5, family_name = $6, picture = $7, preferred_username = $8, is_active = $9, updated_at = NOW()
		WHERE id = $1
	`, user.ID, user.Email, user.EmailVerified, user.Name,
		user.GivenName, user.FamilyName, user.Picture,
		user.PreferredUsername, user.IsActive)
	return err
}

func VerifyPassword(hash, password string) bool {
	salt, secret, err := decodeArgon2Hash(hash)
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return constantTimeEqual(computed, secret)
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Refresh Tokens

func (r *Repository) CreateRefreshToken(token, clientID, userID, scope string, expiresAt time.Time) error {
	_, err := r.db.Exec(`
		INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, token, clientID, userID, scope, expiresAt)
	return err
}

func (r *Repository) GetRefreshToken(token string) (clientID, userID, scope string, err error) {
	err = r.db.QueryRow(`
		SELECT client_id, user_id, scope
		FROM refresh_tokens
		WHERE token = $1 AND revoked = FALSE AND expires_at > NOW()
	`, token).Scan(&clientID, &userID, &scope)
	if err == sql.ErrNoRows {
		return "", "", "", ErrUserNotFound
	}
	return
}

func (r *Repository) RevokeRefreshToken(token string) error {
	_, err := r.db.Exec(`
		UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1
	`, token)
	return err
}

// Password Resets

func (r *Repository) CreatePasswordReset(userID, token string, expiresAt time.Time) error {
	_, err := r.db.Exec(`
		INSERT INTO password_resets (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, userID, token, expiresAt)
	return err
}

func (r *Repository) GetPasswordReset(token string) (userID string, err error) {
	err = r.db.QueryRow(`
		SELECT user_id
		FROM password_resets
		WHERE token = $1 AND used = FALSE AND expires_at > NOW()
	`, token).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", ErrUserNotFound
	}
	return
}

func (r *Repository) MarkPasswordResetUsed(token string) error {
	_, err := r.db.Exec(`
		UPDATE password_resets SET used = TRUE WHERE token = $1
	`, token)
	return err
}

func (r *Repository) UpdatePasswordHash(userID, hash string) error {
	_, err := r.db.Exec(`
		UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1
	`, userID, hash)
	return err
}

// Admin console queries

type UserRow struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Name            string    `json:"name"`
	EmailVerified   bool      `json:"email_verified"`
	IsActive        bool      `json:"is_active"`
	IsPlatformAdmin bool      `json:"is_platform_admin"`
	CreatedAt       time.Time `json:"created_at"`
}

func (r *Repository) List(search string, limit int) ([]UserRow, error) {
	pattern := "%" + search + "%"
	rows, err := r.db.Query(`
		SELECT id, email, name, email_verified, is_active, is_platform_admin, created_at
		FROM users
		WHERE ($1 = '' OR email ILIKE $2 OR name ILIKE $2)
		ORDER BY created_at DESC
		LIMIT $3
	`, search, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []UserRow{}
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerified, &u.IsActive, &u.IsPlatformAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *Repository) SetActive(userID string, active bool) error {
	_, err := r.db.Exec(`
		UPDATE users SET is_active = $2, updated_at = NOW() WHERE id = $1
	`, userID, active)
	return err
}

func (r *Repository) CountAll() (int, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}
