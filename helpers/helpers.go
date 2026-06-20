// Package helpers holds small HTTP utilities shared by the goravel-authkit
// controllers and middleware: route-param parsing, pagination, the
// authenticated-user context key, and the session-regeneration workaround.
package helpers

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// CtxAuthUserID is the request-context key under which the Authenticated
// middleware stores the current user id (string). Domain controllers read it
// via AuthUserID to scope queries by the current user.
const CtxAuthUserID = "auth_user_id"

// ParseUUIDParam parses a UUID route parameter. On failure it returns a pointer
// to a 400 response the controller returns directly:
//
//	id, errResp := helpers.ParseUUIDParam(ctx, "id")
//	if errResp != nil { return *errResp }
func ParseUUIDParam(ctx contractshttp.Context, name string) (uuid.UUID, *contractshttp.Response) {
	raw := ctx.Request().Route(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		var resp contractshttp.Response = ctx.Response().Json(http.StatusBadRequest, contractshttp.Json{
			"error":   "invalid_id",
			"message": "Invalid ID parameter: " + name,
		})
		return uuid.Nil, &resp
	}
	return id, nil
}

// ParsePositiveInt parses a string as a positive integer, returning fallback on
// failure. Used for pagination (page, per_page).
func ParsePositiveInt(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return fallback
	}
	return n
}

// Pagination resolves page + per_page query params with sane defaults and a
// hard cap on per_page.
func Pagination(ctx contractshttp.Context, defaultPerPage, maxPerPage int) (page, perPage int) {
	page = ParsePositiveInt(ctx.Request().Query("page", "1"), 1)
	perPage = ParsePositiveInt(ctx.Request().Query("per_page", strconv.Itoa(defaultPerPage)), defaultPerPage)
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	return page, perPage
}

// AuthUserID reads the user id injected by the Authenticated middleware under
// CtxAuthUserID. It returns uuid.Nil when absent or unparseable.
func AuthUserID(ctx contractshttp.Context) uuid.UUID {
	raw, ok := ctx.Value(CtxAuthUserID).(string)
	if !ok {
		return uuid.Nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// RegenerateAndPersistSession regenerates the session id (session-fixation
// protection) and RE-EMITS the cookie with the new id.
//
// Goravel's StartSession middleware writes the response Set-Cookie with the
// session id BEFORE the handler runs, so a plain session.Regenerate() inside the
// handler would save the auth under the NEW id while the browser keeps the OLD
// id. We therefore emit a second Set-Cookie with the new id (the later one wins).
func RegenerateAndPersistSession(ctx contractshttp.Context) error {
	session := ctx.Request().Session()
	if session == nil {
		return nil
	}
	if err := session.Regenerate(); err != nil {
		return err
	}

	config := facades.Config()
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     config.GetString("session.cookie"),
		Value:    session.GetID(),
		Path:     config.GetString("session.path", "/"),
		Domain:   config.GetString("session.domain"),
		MaxAge:   config.GetInt("session.lifetime", 120) * 60,
		Secure:   config.GetBool("session.secure", false),
		HttpOnly: config.GetBool("session.http_only", true),
		SameSite: config.GetString("session.same_site", "lax"),
	})
	return nil
}
