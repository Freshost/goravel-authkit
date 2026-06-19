// Package responses holds the request/response DTOs for the goravel-auth HTTP
// endpoints. Swagger annotations on the controllers reference these types so the
// generated TypeScript SDK gets accurate models.
package responses

import (
	"time"

	"github.com/freshost/goravel-auth/models"
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

// UpdateUserRequest is the PUT /users/{id} body.
type UpdateUserRequest struct {
	Email string `json:"email" binding:"required,email" example:"jane@example.com"`
	Name  string `json:"name" example:"Jane Admin"`
	Role  string `json:"role" example:"admin"`
}

// SetPasswordRequest is the POST /users/{id}/password body.
type SetPasswordRequest struct {
	Password string `json:"password" binding:"required" example:"new-password"`
}

// UserResponse is the public view of a user (never includes the password hash).
type UserResponse struct {
	ID        string `json:"id" example:"3f2504e0-4f89-41d3-9a0c-0305e82c3301"`
	Email     string `json:"email" example:"admin@example.com"`
	Name      string `json:"name" example:"Admin"`
	Role      string `json:"role" example:"admin"`
	CreatedAt string `json:"createdAt" example:"2026-01-01T00:00:00Z"`
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
		ID:        u.ID.String(),
		Email:     u.Email,
		Name:      name,
		Role:      u.Role,
		CreatedAt: createdAt,
	}
}

// NewUserListResponse maps a slice of users to public DTOs.
func NewUserListResponse(users []models.User) []UserResponse {
	out := make([]UserResponse, 0, len(users))
	for i := range users {
		out = append(out, NewUserResponse(&users[i]))
	}
	return out
}
