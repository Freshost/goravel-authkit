# goravel-authkit demo (backend) — runs on :8099, consumes the package via a
# local `replace` directive. Postgres must be reachable on 127.0.0.1:5432.

EMAIL ?= admin@demo.test
PASSWORD ?= password123
NAME ?= Admin

.PHONY: help dev run setup db migrate migrate-rollback create-user smoke test tidy

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

dev: ## Run the backend with hot reload (air) — the normal way to develop
	air

run: ## Run the backend once (no hot reload)
	go run .

setup: db migrate create-user ## One-time: create DB, migrate, seed the admin user

db: ## Create the demo database (ignores "already exists")
	createdb authkit_demo 2>/dev/null || true

migrate: ## Run the package migrations
	go run . artisan migrate

migrate-rollback: ## Roll back the last migration batch
	go run . artisan migrate:rollback

create-user: ## Seed the admin (override EMAIL=/PASSWORD=/NAME=)
	go run . artisan auth:create-user --email=$(EMAIL) --password=$(PASSWORD) --name=$(NAME)

smoke: ## Smoke-test login + /me against the running backend
	curl -i -c /tmp/authkit-demo.jar -b /tmp/authkit-demo.jar -XPOST localhost:8099/api/v1/auth/login \
		-H 'origin: http://localhost:8099' \
		-H 'content-type: application/json' \
		-d '{"email":"$(EMAIL)","password":"$(PASSWORD)"}'
	@echo
	curl -s -c /tmp/authkit-demo.jar -b /tmp/authkit-demo.jar localhost:8099/api/v1/auth/me

test: ## Run Go tests (raises the login rate limit so the feature suite isn't throttled)
	AUTHKIT_RATE_LIMIT_IP_ATTEMPTS=100000 AUTHKIT_RATE_LIMIT_ACCOUNT_ATTEMPTS=100000 AUTHKIT_RATE_LIMIT_PASSWORD_ATTEMPTS=100000 go test ./...

tidy: ## Tidy go modules
	go mod tidy
