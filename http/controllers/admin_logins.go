package controllers

import (
	"errors"
	"net/http"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/services"
)

// AdminLoginsController serves the role-gated sign-in overview.
type AdminLoginsController struct {
	logins *services.AdminLogins
}

func NewAdminLoginsController(logins *services.AdminLogins) *AdminLoginsController {
	return &AdminLoginsController{logins: logins}
}

// Index handles GET {prefix}/auth/admin/logins.
func (c *AdminLoginsController) Index(ctx contractshttp.Context) contractshttp.Response {
	page, err := c.logins.List(ctx.Context(), services.AdminLoginQuery{
		Page:    ctx.Request().QueryInt("page", 1),
		PerPage: ctx.Request().QueryInt("perPage", 20),
	})
	if err != nil {
		if errors.Is(err, services.ErrValidation) {
			return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
				Error: "validation_error", Message: err.Error(),
			})
		}
		facades.Log().Errorf("admin login history: %v", err)
		return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
			Error: "internal_error", Message: "Internal server error",
		})
	}
	return ctx.Response().Json(http.StatusOK, responses.NewAdminLoginPageResponse(page))
}
