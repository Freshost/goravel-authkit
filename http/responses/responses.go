// Package responses holds the request/response DTOs for the goravel-authkit HTTP
// endpoints. Swagger annotations on the controllers reference these types so the
// generated TypeScript SDK gets accurate models.
package responses

import (
	"time"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/services"
)

// ErrorResponse is the standard error envelope: {"error","message"}.
type ErrorResponse struct {
	Error   string `json:"error" example:"validation_error"`
	Message string `json:"message" example:"Email and password are required"`
}

// MessageResponse is a simple {"message"} envelope.
type MessageResponse struct {
	Message string `json:"message" example:"Password changed"`
}

// LoginRequest is the POST /auth/login body.
type LoginRequest struct {
	Email    string `json:"email" form:"email" binding:"required,email" example:"admin@example.com"`
	Password string `json:"password" form:"password" binding:"required" example:"password"`
	// Remember, when true, issues a persistent "remember me" cookie so the user
	// stays logged in across browser restarts until it expires or they log out.
	Remember bool `json:"remember" form:"remember" example:"false"`
}

// UpdateProfileRequest is the PUT /auth/me body — the user's own name and email.
type UpdateProfileRequest struct {
	Email string `json:"email" binding:"required,email" example:"admin@example.com"`
	Name  string `json:"name" example:"Admin"`
}

// ChangePasswordRequest is the PUT /auth/password body.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required" example:"password"`
	NewPassword     string `json:"newPassword" binding:"required" example:"new-password"`
}

// CreateUserRequest is the POST /users body.
type CreateUserRequest struct {
	Email    string `json:"email" binding:"required,email" example:"jane@example.com"`
	Name     string `json:"name" example:"Jane Admin"`
	Password string `json:"password" binding:"required" example:"password"`
	Role     string `json:"role" example:"admin"`
}

// UpdateUserRequest is the PUT /users/{id} body. Disabled is a pointer so an
// omitted field leaves the lock state unchanged.
type UpdateUserRequest struct {
	Email    string `json:"email" binding:"required,email" example:"jane@example.com"`
	Name     string `json:"name" example:"Jane Admin"`
	Role     string `json:"role" example:"admin"`
	Disabled *bool  `json:"disabled" example:"false"`
}

// SetPasswordRequest is the POST /users/{id}/password body.
type SetPasswordRequest struct {
	Password string `json:"password" binding:"required" example:"new-password"`
}

// TwoFactorRequiredResponse is returned by login when the user has 2FA enabled:
// the session is not established yet; the client must call the challenge endpoint.
type TwoFactorRequiredResponse struct {
	TwoFactor bool `json:"two_factor" example:"true"`
}

// TwoFactorChallengeRequest completes a 2FA login with either a TOTP code or a
// recovery code (exactly one).
type TwoFactorChallengeRequest struct {
	Code         string `json:"code" example:"123456"`
	RecoveryCode string `json:"recoveryCode" example:"ABCDE-FGHJK"`
}

// TwoFactorConfirmRequest confirms enrollment with a TOTP code.
type TwoFactorConfirmRequest struct {
	Code string `json:"code" binding:"required" example:"123456"`
}

// TwoFactorDisableRequest re-authenticates with the account password before
// disabling 2FA.
type TwoFactorDisableRequest struct {
	Password string `json:"password" binding:"required" example:"secret"`
}

// TwoFactorEnrollmentResponse is returned when enrollment starts: the secret and
// the otpauth:// URL the client renders as a QR code.
type TwoFactorEnrollmentResponse struct {
	Secret     string `json:"secret" example:"JBSWY3DPEHPK3PXP"`
	OtpauthURL string `json:"otpauthUrl" example:"otpauth://totp/App:admin@example.com?secret=...&issuer=App"`
}

// RecoveryCodesResponse carries one-time recovery codes. Plaintext codes are
// shown exactly once, at confirmation / regeneration — they are stored hashed
// and can never be re-derived afterwards.
type RecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recoveryCodes" example:"ABCDE-FGHJK"`
}

// RecoveryCodesStatusResponse reports how many unused recovery codes remain,
// without revealing the codes themselves (they are stored hashed).
type RecoveryCodesStatusResponse struct {
	Remaining int `json:"remaining" example:"6"`
}

// MetaResponse exposes the FE-relevant, non-sensitive package config so the UI
// can adapt (role-select options, feature visibility, password rules) without
// hardcoding or duplicating it. Served unauthenticated at {prefix}/meta.
type MetaResponse struct {
	// Roles are the assignable role values (from authkit.roles). Empty = any.
	Roles             []string      `json:"roles"`
	MinPasswordLength int           `json:"minPasswordLength" example:"8"`
	Features          MetaFeatures  `json:"features"`
	APITokens         *APITokenMeta `json:"apiTokens,omitempty"`
}

// APITokenMeta describes the non-sensitive token policy used by account UIs.
type APITokenMeta struct {
	AllowedScopes       []string `json:"allowedScopes"`
	DefaultLifetimeDays int      `json:"defaultLifetimeDays"`
	MaxLifetimeDays     int      `json:"maxLifetimeDays"`
	MaxPerUser          int      `json:"maxPerUser"`
}

// MetaFeatures mirrors the authkit.features toggles for the frontend.
type MetaFeatures struct {
	UserManagement bool `json:"userManagement" example:"true"`
	TwoFactor      bool `json:"twoFactor" example:"true"`
	AuditLog       bool `json:"auditLog" example:"true"`
	Sessions       bool `json:"sessions" example:"true"`
	Impersonation  bool `json:"impersonation" example:"false"`
	APITokens      bool `json:"apiTokens" example:"false"`
}

// CreateAPITokenRequest is the POST /auth/api-tokens body. The password and,
// when enabled for the user, a live TOTP code re-authenticate this sensitive
// operation. Expiration is mandatory and must be RFC3339.
type CreateAPITokenRequest struct {
	Name          string   `json:"name" binding:"required"`
	ExpiresAt     string   `json:"expiresAt" binding:"required"`
	Scopes        []string `json:"scopes"`
	Password      string   `json:"password" binding:"required"`
	TwoFactorCode string   `json:"twoFactorCode"`
}

// APITokenResponse deliberately omits the selector and validator hash.
type APITokenResponse struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	ExpiresAt  string   `json:"expiresAt"`
	LastUsedAt *string  `json:"lastUsedAt"`
	CreatedAt  string   `json:"createdAt"`
}

// IssuedAPITokenResponse contains plaintext exactly once at creation time.
type IssuedAPITokenResponse struct {
	APITokenResponse
	Token string `json:"token"`
}

func NewAPITokenResponse(token *models.APIToken) APITokenResponse {
	var lastUsedAt *string
	if token.LastUsedAt != nil {
		formatted := token.LastUsedAt.UTC().Format(time.RFC3339)
		lastUsedAt = &formatted
	}
	return APITokenResponse{
		ID: token.ID.String(), Name: token.Name, Scopes: []string(token.Scopes),
		ExpiresAt: token.ExpiresAt.UTC().Format(time.RFC3339), LastUsedAt: lastUsedAt,
		CreatedAt: token.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// UserResponse is the public view of a user (never includes the password hash).
type UserResponse struct {
	ID               string `json:"id" example:"3f2504e0-4f89-41d3-9a0c-0305e82c3301"`
	Email            string `json:"email" example:"admin@example.com"`
	Name             string `json:"name" example:"Admin"`
	Role             string `json:"role" example:"admin"`
	TwoFactorEnabled bool   `json:"twoFactorEnabled" example:"false"`
	Disabled         bool   `json:"disabled" example:"false"`
	CreatedAt        string `json:"createdAt" example:"2026-01-01T00:00:00Z"`
	// ImpersonatedBy is set only while this user is being impersonated, so the UI
	// can show a banner and an "exit impersonation" action.
	ImpersonatedBy *ImpersonatorRef `json:"impersonatedBy,omitempty"`
}

// ImpersonatorRef identifies the actor currently impersonating the user.
type ImpersonatorRef struct {
	Guard string `json:"guard"`
	ID    string `json:"id"`
	Email string `json:"email"`
}

// ImpersonateRequest is the body of POST /auth/impersonate.
type ImpersonateRequest struct {
	// Guard is the target user's guard (empty = the actor's own guard, i.e. same-guard).
	Guard string `json:"guard"`
	// UserID is the target user's id.
	UserID string `json:"userId"`
}

// NewUserResponse maps a User model to its public DTO.
func NewUserResponse(u *models.User) UserResponse {
	name := ""
	if u.Name != nil {
		name = *u.Name
	}
	createdAt := ""
	if !u.CreatedAt.IsZero() {
		createdAt = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	return UserResponse{
		ID:               u.ID.String(),
		Email:            u.Email,
		Name:             name,
		Role:             u.Role,
		TwoFactorEnabled: u.TwoFactorEnabled(),
		Disabled:         u.IsDisabled(),
		CreatedAt:        createdAt,
	}
}

// SessionResponse is the public view of one active session. The secret session
// id is never exposed; ID is the row's own id, used to address it for
// termination.
type SessionResponse struct {
	ID           string `json:"id" example:"3f2504e0-4f89-41d3-9a0c-0305e82c3301"`
	IP           string `json:"ip" example:"203.0.113.7"`
	UserAgent    string `json:"userAgent" example:"Mozilla/5.0 ..."`
	Current      bool   `json:"current" example:"true"`
	CreatedAt    string `json:"createdAt" example:"2026-01-01T00:00:00Z"`
	LastActiveAt string `json:"lastActiveAt" example:"2026-01-01T01:00:00Z"`
}

// NewSessionListResponse maps service session views to public DTOs.
func NewSessionListResponse(views []services.SessionView) []SessionResponse {
	out := make([]SessionResponse, 0, len(views))
	for _, v := range views {
		out = append(out, SessionResponse{
			ID:           v.ID.String(),
			IP:           v.IP,
			UserAgent:    v.UserAgent,
			Current:      v.IsCurrent,
			CreatedAt:    formatTime(v.CreatedAt),
			LastActiveAt: formatTime(v.LastActiveAt),
		})
	}
	return out
}

// LoginHistoryEntry is one recent successful sign-in.
type LoginHistoryEntry struct {
	// Action is "auth.login" (password) or "auth.login_remember" (remember cookie).
	Action    string `json:"action" example:"auth.login"`
	IP        string `json:"ip" example:"203.0.113.7"`
	CreatedAt string `json:"createdAt" example:"2026-01-01T00:00:00Z"`
}

// NewLoginHistoryResponse maps audit rows to login-history DTOs.
func NewLoginHistoryResponse(entries []models.AuditLog) []LoginHistoryEntry {
	out := make([]LoginHistoryEntry, 0, len(entries))
	for i := range entries {
		out = append(out, LoginHistoryEntry{
			Action:    entries[i].Action,
			IP:        entries[i].IP,
			CreatedAt: formatTime(entries[i].CreatedAt),
		})
	}
	return out
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// NewUserListResponse maps a slice of users to public DTOs.
func NewUserListResponse(users []models.User) []UserResponse {
	out := make([]UserResponse, 0, len(users))
	for i := range users {
		out = append(out, NewUserResponse(&users[i]))
	}
	return out
}
