package controllers

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/services"
)

// APITokensController manages the current user's personal access tokens. These
// endpoints are intentionally mounted only behind session authentication.
type APITokensController struct {
	tokens           *services.APITokens
	audit            *services.Audit
	rateLimiter      *middleware.AttemptLimiter
	passwordAttempts int
}

func NewAPITokensController(tokens *services.APITokens, audit *services.Audit, rateLimiter *middleware.AttemptLimiter, passwordAttempts int) *APITokensController {
	return &APITokensController{tokens: tokens, audit: audit, rateLimiter: rateLimiter, passwordAttempts: passwordAttempts}
}

func (c *APITokensController) Index(ctx contractshttp.Context) contractshttp.Response {
	userID := helpers.AuthUserID(ctx)
	tokens, err := c.tokens.List(ctx.Context(), userID)
	if err != nil {
		return c.internal(ctx, err)
	}
	result := make([]responses.APITokenResponse, 0, len(tokens))
	for i := range tokens {
		result = append(result, responses.NewAPITokenResponse(&tokens[i]))
	}
	return ctx.Response().Json(http.StatusOK, result)
}

func (c *APITokensController) Store(ctx contractshttp.Context) contractshttp.Response {
	var req responses.CreateAPITokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return invalidAPITokenRequest(ctx, "Invalid request body")
	}
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return invalidAPITokenRequest(ctx, "expiresAt must be an RFC3339 timestamp")
	}
	userID := helpers.AuthUserID(ctx)
	if response := enforceRateLimit(ctx, c.rateLimiter, "api-token-user", userID.String(), c.passwordAttempts); response != nil {
		return response
	}
	issued, err := c.tokens.Issue(ctx.Context(), services.IssueAPITokenCommand{
		UserID: userID, Name: req.Name, ExpiresAt: expiresAt, Scopes: req.Scopes,
		Password: req.Password, TwoFactorCode: req.TwoFactorCode,
	})
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, userID, "auth.api_token_created", issued.Token.ID.String())
	return ctx.Response().Json(http.StatusCreated, responses.IssuedAPITokenResponse{
		APITokenResponse: responses.NewAPITokenResponse(issued.Token), Token: issued.Plaintext,
	})
}

func (c *APITokensController) Destroy(ctx contractshttp.Context) contractshttp.Response {
	id, errResponse := helpers.ParseUUIDParam(ctx, "id")
	if errResponse != nil {
		return *errResponse
	}
	userID := helpers.AuthUserID(ctx)
	if err := c.tokens.Revoke(ctx.Context(), userID, id); err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, userID, "auth.api_token_revoked", id.String())
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "API token revoked"})
}

func (c *APITokensController) DestroyAll(ctx contractshttp.Context) contractshttp.Response {
	userID := helpers.AuthUserID(ctx)
	if err := c.tokens.RevokeAll(ctx.Context(), userID); err != nil {
		return c.internal(ctx, err)
	}
	c.writeAudit(ctx, userID, "auth.api_tokens_revoked", userID.String())
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "API tokens revoked"})
}

func (c *APITokensController) mapError(ctx contractshttp.Context, err error) contractshttp.Response {
	switch {
	case errors.Is(err, services.ErrWrongPassword):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{Error: "wrong_password", Message: "Current password is incorrect"})
	case errors.Is(err, services.ErrInvalidCode):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{Error: "invalid_code", Message: "Invalid two-factor authentication code"})
	case errors.Is(err, services.ErrValidation):
		return invalidAPITokenRequest(ctx, errMessage(err))
	case errors.Is(err, services.ErrTokenLimit):
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{Error: "token_limit", Message: "Maximum number of active API tokens reached"})
	case errors.Is(err, services.ErrNotFound):
		return ctx.Response().Json(http.StatusNotFound, responses.ErrorResponse{Error: "not_found", Message: "API token not found"})
	case errors.Is(err, services.ErrUnauthorized):
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{Error: "unauthorized", Message: "Authentication required"})
	default:
		return c.internal(ctx, err)
	}
}

func invalidAPITokenRequest(ctx contractshttp.Context, message string) contractshttp.Response {
	return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{Error: "validation_error", Message: message})
}

func (c *APITokensController) internal(ctx contractshttp.Context, err error) contractshttp.Response {
	facades.Log().Errorf("authkit api tokens: %v", err)
	return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{Error: "internal_error", Message: "Internal server error"})
}

func (c *APITokensController) writeAudit(ctx contractshttp.Context, actorID uuid.UUID, action, resourceID string) {
	if c.audit == nil {
		return
	}
	if err := c.audit.Log(ctx.Context(), services.AuditEntry{
		ActorID: &actorID, Action: action, ResourceType: "api_token", ResourceID: &resourceID, IP: ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}
