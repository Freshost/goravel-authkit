package controllers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-auth/helpers"
	"github.com/freshost/goravel-auth/http/responses"
	"github.com/freshost/goravel-auth/services"
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

// Index godoc
//
//	@ID				listUsers
//	@Summary		List users
//	@Tags			Users
//	@Security		CookieAuth
//	@Produce		json
//	@Success		200	{array}		responses.UserResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/users [get]
func (c *UsersController) Index(ctx contractshttp.Context) contractshttp.Response {
	users, err := c.users.List(ctx.Request().Origin().Context())
	if err != nil {
		return c.mapError(ctx, err)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserListResponse(users))
}

// Show godoc
//
//	@ID				getUser
//	@Summary		Get a user
//	@Tags			Users
//	@Security		CookieAuth
//	@Produce		json
//	@Param			id	path		string	true	"User ID (UUID)"
//	@Success		200	{object}	responses.UserResponse
//	@Failure		404	{object}	responses.ErrorResponse
//	@Router			/users/{id} [get]
func (c *UsersController) Show(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	u, err := c.users.GetByID(ctx.Request().Origin().Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(u))
}

// Store godoc
//
//	@ID				createUser
//	@Summary		Create a user
//	@Tags			Users
//	@Security		CookieAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		responses.CreateUserRequest	true	"User"
//	@Success		201		{object}	responses.UserResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		409		{object}	responses.ErrorResponse
//	@Router			/users [post]
func (c *UsersController) Store(ctx contractshttp.Context) contractshttp.Response {
	var req responses.CreateUserRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}
	u, err := c.users.Create(ctx.Request().Origin().Context(), req.Email, req.Name, req.Password, req.Role)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.create", u.ID)
	return ctx.Response().Json(http.StatusCreated, responses.NewUserResponse(u))
}

// Update godoc
//
//	@ID				updateUser
//	@Summary		Update a user (email, name, role)
//	@Tags			Users
//	@Security		CookieAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"User ID (UUID)"
//	@Param			body	body		responses.UpdateUserRequest	true	"User"
//	@Success		200		{object}	responses.UserResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		404		{object}	responses.ErrorResponse
//	@Failure		409		{object}	responses.ErrorResponse
//	@Router			/users/{id} [put]
func (c *UsersController) Update(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	var req responses.UpdateUserRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}
	u, err := c.users.Update(ctx.Request().Origin().Context(), id, req.Email, req.Name, req.Role)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.update", u.ID)
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(u))
}

// Destroy godoc
//
//	@ID				deleteUser
//	@Summary		Delete a user
//	@Tags			Users
//	@Security		CookieAuth
//	@Produce		json
//	@Param			id	path		string	true	"User ID (UUID)"
//	@Success		200	{object}	responses.MessageResponse
//	@Failure		400	{object}	responses.ErrorResponse
//	@Failure		404	{object}	responses.ErrorResponse
//	@Failure		409	{object}	responses.ErrorResponse
//	@Router			/users/{id} [delete]
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
	if err := c.users.Delete(ctx.Request().Origin().Context(), id); err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, "user.delete", id)
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "deleted"})
}

// SetPassword godoc
//
//	@ID				setUserPassword
//	@Summary		Reset a user's password
//	@Tags			Users
//	@Security		CookieAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"User ID (UUID)"
//	@Param			body	body		responses.SetPasswordRequest	true	"New password"
//	@Success		200		{object}	responses.UserResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		404		{object}	responses.ErrorResponse
//	@Router			/users/{id}/password [post]
func (c *UsersController) SetPassword(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	var req responses.SetPasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}
	u, err := c.users.SetPassword(ctx.Request().Origin().Context(), id, req.Password)
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
	if err := c.audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
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
			Error: "last_admin", Message: "Cannot delete the last admin user",
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
