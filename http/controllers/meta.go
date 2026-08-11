package controllers

import (
	"net/http"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/freshost/goravel-authkit/http/responses"
)

// MetaController serves the public, non-sensitive package config so the frontend
// can fetch role options and feature flags instead of hardcoding them.
type MetaController struct {
	roles             []string
	minPasswordLength int
	features          responses.MetaFeatures
	apiTokens         *responses.APITokenMeta
}

// NewMetaController builds the meta controller from the resolved route options.
func NewMetaController(roles []string, minPasswordLength int, features responses.MetaFeatures, apiTokens *responses.APITokenMeta) *MetaController {
	return &MetaController{roles: roles, minPasswordLength: minPasswordLength, features: features, apiTokens: apiTokens}
}

// Show returns the assignable roles, password rules, and feature flags so the UI
// can adapt without hardcoding them. The response is unauthenticated and
// non-sensitive. Handles GET {prefix}/auth/meta.
func (c *MetaController) Show(ctx contractshttp.Context) contractshttp.Response {
	roles := c.roles
	if roles == nil {
		roles = []string{}
	}
	return ctx.Response().Json(http.StatusOK, responses.MetaResponse{
		Roles:             roles,
		MinPasswordLength: c.minPasswordLength,
		Features:          c.features,
		APITokens:         c.apiTokens,
	})
}
