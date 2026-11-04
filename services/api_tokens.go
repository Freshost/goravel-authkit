package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
)

const (
	DefaultAPITokenLifetime    = 30 * 24 * time.Hour
	DefaultMaxAPITokenLifetime = 365 * 24 * time.Hour
	DefaultMaxAPITokensPerUser = 20
	apiTokenSelectorBytes      = 12
	apiTokenValidatorBytes     = 32
	apiTokenPrefix             = "gak_"
	apiTokenLastUsedInterval   = 5 * time.Minute
	apiTokenPruneRetention     = 30 * 24 * time.Hour
)

var apiTokenScopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$`)

type IssueAPITokenCommand struct {
	UserID        uuid.UUID
	Name          string
	ExpiresAt     time.Time
	Scopes        []string
	Password      string
	TwoFactorCode string
}

type IssuedAPIToken struct {
	Token       *models.APIToken
	Plaintext   string
	DelegatedBy *contracts.Principal
}

// APITokenDelegationGuard uses the actor guard's current users and native
// impersonation policy. A session marker alone does not confer authority.
type APITokenDelegationGuard struct {
	Users  repositories.UsersRepository
	Policy *Impersonation
}

type APITokens struct {
	repo             repositories.APITokensRepository
	users            repositories.UsersRepository
	hasher           Hasher
	twoFactor        *TwoFactor
	allowedScopes    map[string]struct{}
	maxLifetime      time.Duration
	maxPerUser       int
	now              func() time.Time
	delegationGuard  string
	delegationActors map[string]APITokenDelegationGuard
}

func NewAPITokens(repo repositories.APITokensRepository, users repositories.UsersRepository, hasher Hasher, twoFactor *TwoFactor, allowedScopes []string, maxLifetime time.Duration, maxPerUser int) *APITokens {
	if maxLifetime <= 0 {
		maxLifetime = DefaultMaxAPITokenLifetime
	}
	if maxPerUser <= 0 {
		maxPerUser = DefaultMaxAPITokensPerUser
	}
	allowed := make(map[string]struct{}, len(allowedScopes))
	for _, scope := range allowedScopes {
		allowed[strings.TrimSpace(scope)] = struct{}{}
	}
	return &APITokens{repo: repo, users: users, hasher: hasher, twoFactor: twoFactor, allowedScopes: allowed, maxLifetime: maxLifetime, maxPerUser: maxPerUser, now: func() time.Time { return time.Now().UTC() }}
}

func (s *APITokens) Issue(ctx context.Context, cmd IssueAPITokenCommand) (*IssuedAPIToken, error) {
	return s.issue(ctx, cmd, nil)
}

// AllowImpersonatedCreation is configured at boot by the host's guard options.
func (s *APITokens) AllowImpersonatedCreation(targetGuard string, actors map[string]APITokenDelegationGuard) {
	s.delegationGuard = targetGuard
	s.delegationActors = actors
}

// IssueImpersonated creates a target-owned token after revalidating the original
// actor against the current users and the native impersonation authorization.
// HTTP callers must obtain actorGuard and actorID from the server-side session.
func (s *APITokens) IssueImpersonated(ctx context.Context, actorGuard string, actorID uuid.UUID, cmd IssueAPITokenCommand) (*IssuedAPIToken, error) {
	guard, ok := s.delegationActors[actorGuard]
	if !ok || guard.Users == nil || guard.Policy == nil || s.delegationGuard == "" || actorID == uuid.Nil {
		return nil, ErrForbidden
	}
	actor, err := guard.Users.FindByID(ctx, actorID)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if actor == nil || actor.IsDisabled() {
		return nil, ErrForbidden
	}
	return s.issue(ctx, cmd, &contracts.Principal{Guard: actorGuard, UserID: actor.ID, Email: actor.Email, Role: actor.Role})
}

func (s *APITokens) issue(ctx context.Context, cmd IssueAPITokenCommand, actor *contracts.Principal) (*IssuedAPIToken, error) {
	now := s.now()
	name := strings.TrimSpace(cmd.Name)
	if name == "" || len([]rune(name)) > 100 {
		return nil, errors.Join(ErrValidation, errors.New("token name must be between 1 and 100 characters"))
	}
	expiresAt := cmd.ExpiresAt.UTC()
	if !expiresAt.After(now) || expiresAt.After(now.Add(s.maxLifetime)) {
		return nil, errors.Join(ErrValidation, errors.New("token expiration is outside the allowed lifetime"))
	}
	scopes, err := s.validateScopes(cmd.Scopes)
	if err != nil {
		return nil, err
	}

	user, err := s.users.FindByID(ctx, cmd.UserID)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if user == nil || user.IsDisabled() {
		return nil, ErrUnauthorized
	}
	if actor != nil {
		target := contracts.Principal{Guard: s.delegationGuard, UserID: user.ID, Email: user.Email, Role: user.Role}
		if err := s.delegationActors[actor.Guard].Policy.Authorize(ctx, *actor, s.delegationGuard, target); err != nil {
			return nil, err
		}
	} else {
		if user.PasswordHash == nil || !s.hasher.Check(cmd.Password, *user.PasswordHash) {
			return nil, ErrWrongPassword
		}
		if user.TwoFactorEnabled() {
			if s.twoFactor == nil || strings.TrimSpace(cmd.TwoFactorCode) == "" {
				return nil, ErrInvalidCode
			}
			ok, verifyErr := s.twoFactor.VerifyLoginCode(ctx, user.ID, cmd.TwoFactorCode)
			if verifyErr != nil {
				return nil, verifyErr
			}
			if !ok {
				return nil, ErrInvalidCode
			}
		}
	}

	count, err := s.repo.CountActiveByUser(ctx, user.ID, now)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if count >= int64(s.maxPerUser) {
		return nil, ErrTokenLimit
	}
	selector, err := randomAPITokenPart(apiTokenSelectorBytes)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	validator, err := randomAPITokenPart(apiTokenValidatorBytes)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	token := &models.APIToken{ID: uuid.New(), UserID: user.ID, Name: name, Selector: selector, ValidatorHash: hashAPITokenValidator(validator), Scopes: models.StringSlice(scopes), ExpiresAt: expiresAt, CreatedAt: now}
	if err := s.repo.Create(ctx, token); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return &IssuedAPIToken{Token: token, Plaintext: apiTokenPrefix + selector + "." + validator, DelegatedBy: actor}, nil
}

func (s *APITokens) Resolve(ctx context.Context, plaintext string) (*models.APIToken, error) {
	selector, validator, ok := splitAPIToken(plaintext)
	if !ok {
		return nil, ErrInvalidAPIToken
	}
	token, err := s.repo.FindBySelector(ctx, selector)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if token == nil || subtle.ConstantTimeCompare([]byte(hashAPITokenValidator(validator)), []byte(token.ValidatorHash)) != 1 || !token.Active(s.now()) {
		return nil, ErrInvalidAPIToken
	}
	now := s.now()
	if err := s.repo.TouchLastUsed(ctx, token.ID, now.Add(-apiTokenLastUsedInterval), now); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	token.LastUsedAt = &now
	return token, nil
}

func (s *APITokens) List(ctx context.Context, userID uuid.UUID) ([]models.APIToken, error) {
	tokens, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return tokens, nil
}

func (s *APITokens) Revoke(ctx context.Context, userID, tokenID uuid.UUID) error {
	rows, err := s.repo.Revoke(ctx, tokenID, userID, s.now())
	if err != nil {
		return errors.Join(ErrInternal, err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *APITokens) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.RevokeAllByUser(ctx, userID, s.now()); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

func (s *APITokens) Prune(ctx context.Context) error {
	if err := s.repo.DeletePrunable(ctx, s.now().Add(-apiTokenPruneRetention)); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

func (s *APITokens) validateScopes(input []string) ([]string, error) {
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, raw := range input {
		scope := strings.TrimSpace(raw)
		if !apiTokenScopePattern.MatchString(scope) {
			return nil, errors.Join(ErrValidation, errors.New("invalid api token scope"))
		}
		if _, allowed := s.allowedScopes[scope]; !allowed {
			return nil, errors.Join(ErrValidation, errors.New("api token scope is not allowed"))
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	sort.Strings(out)
	return out, nil
}

func randomAPITokenPart(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashAPITokenValidator(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func splitAPIToken(value string) (string, string, bool) {
	if !strings.HasPrefix(value, apiTokenPrefix) {
		return "", "", false
	}
	selector, validator, ok := strings.Cut(strings.TrimPrefix(value, apiTokenPrefix), ".")
	if !ok || strings.Contains(validator, ".") {
		return "", "", false
	}
	selectorBytes, selectorErr := base64.RawURLEncoding.DecodeString(selector)
	validatorBytes, validatorErr := base64.RawURLEncoding.DecodeString(validator)
	if selectorErr != nil || validatorErr != nil || len(selectorBytes) != apiTokenSelectorBytes || len(validatorBytes) != apiTokenValidatorBytes {
		return "", "", false
	}
	return selector, validator, true
}
