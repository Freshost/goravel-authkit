package controllers

import (
	"net/http"
	"strconv"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/http/responses"
)

func enforceRateLimit(ctx contractshttp.Context, limiter *middleware.AttemptLimiter, dimension, identifier string, attempts int) contractshttp.Response {
	result, err := limiter.Hit(ctx.Context(), dimension, identifier, attempts)
	if err != nil {
		facades.Log().Errorf("authkit rate limiter: %v", err)
		return ctx.Response().Json(http.StatusServiceUnavailable, responses.ErrorResponse{
			Error: "rate_limiter_unavailable", Message: "Authentication is temporarily unavailable.",
		})
	}
	if result.Allowed {
		return nil
	}

	ctx.Response().Header("Retry-After", strconv.Itoa(int((result.RetryAfter+time.Second-1)/time.Second)))
	return ctx.Response().Json(http.StatusTooManyRequests, responses.ErrorResponse{
		Error: "rate_limited", Message: "Too many attempts. Please try again later.",
	})
}
