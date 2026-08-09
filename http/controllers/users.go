package controllers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/services"
)

// UsersController handles admin user-management CRUD.
type UsersController struct {
	users *services.Users
	audit *services.Audit // nil when audit logging is disabled
}

// NewUsersController builds the user-management controller. Pass a nil audit to
// disable audit writes.
func NewUsersController(users *services.Users, audit *services.Audit) *UsersController {
	return &UsersController{users: users, audit: audit}
}

// Index lists all users. Handles GET {prefix}/auth/users.
func (c *UsersController) Index(ctx contractshttp.Context) contractshttp.Response {
	users, err := c.users.List(ctx.Context())
	if err != nil {
		return c.mapError(ctx, err)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserListResponse(users))
}

// Show returns a single user by id. Handles GET {prefix}/auth/users/{id}.
func (c *UsersController) Show(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	u, err := c.users.GetByID(ctx.Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(u))
}

// Store creates a user. Handles POST {prefix}/auth/users; a duplicate email is
// rejected with a conflict.
func (c *UsersController) Store(ctx contractshttp.Context) contractshttp.Response {
	var req responses.CreateUserRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}
	u, err := c.users.Create(ctx.Context(), req.Email, req.Name, req.Password, req.Role)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.create", u.ID)
	return ctx.Response().Json(http.StatusCreated, responses.NewUserResponse(u))
}

// Update changes a user's email, name, role, or disabled state. Handles
// PUT {prefix}/auth/users/{id} and refuses to let an admin disable their own
// account.
func (c *UsersController) Update(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	var req responses.UpdateUserRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}
	// Refuse to lock yourself out.
	if req.Disabled != nil && *req.Disabled && helpers.AuthUserID(ctx) == id {
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "self_disable", Message: "You cannot disable your own account",
		})
	}
	u, err := c.users.Update(ctx.Context(), id, req.Email, req.Name, req.Role, req.Disabled, helpers.AuthUserID(ctx))
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.update", u.ID)
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(u))
}

// Destroy deletes a user. Handles DELETE {prefix}/auth/users/{id} and refuses to
// let a user delete their own account.
func (c *UsersController) Destroy(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	if helpers.AuthUserID(ctx) == id {
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "self_delete", Message: "You cannot delete your own account",
		})
	}
	if err := c.users.Delete(ctx.Context(), id); err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.delete", id)
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "deleted"})
}

// SetPassword resets a user's password as an admin action. Handles
// POST {prefix}/auth/users/{id}/password.
func (c *UsersController) SetPassword(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	var req responses.SetPasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}
	u, err := c.users.SetPassword(ctx.Context(), id, req.Password)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.password_reset", u.ID)
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(u))
}

func (c *UsersController) writeAudit(ctx contractshttp.Context, action string, resourceID uuid.UUID) {
	if c.audit == nil {
		return
	}
	var actorID *uuid.UUID
	if id := helpers.AuthUserID(ctx); id != uuid.Nil {
		actorID = &id
	}
	rid := resourceID.String()
	if err := c.audit.Log(ctx.Context(), services.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &rid,
		IP:           ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}

func (c *UsersController) mapError(ctx contractshttp.Context, err error) contractshttp.Response {
	switch {
	case errors.Is(err, services.ErrNotFound):
		return ctx.Response().Json(http.StatusNotFound, responses.ErrorResponse{
			Error: "not_found", Message: "User not found",
		})
	case errors.Is(err, services.ErrValidation):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "validation_error", Message: errMessage(err),
		})
	case errors.Is(err, services.ErrAlreadyExists):
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{
			Error: "already_exists", Message: "A user with this email already exists",
		})
	case errors.Is(err, services.ErrLastAdmin):
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{
			Error: "last_admin", Message: "Cannot remove, disable, or demote the last admin user",
		})
	default:
		facades.Log().Errorf("users internal error: %v", err)
		return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
			Error: "internal_error", Message: "Internal server error",
		})
	}
}

func (c *UsersController) badRequest(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
		Error: "validation_error", Message: "Invalid request body",
	})
}
