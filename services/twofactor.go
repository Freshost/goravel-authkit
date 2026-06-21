package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
)

// DefaultRecoveryCodeCount is the fallback number of recovery codes generated on
// confirmation when the app does not override authkit.two_factor.recovery_codes.
const DefaultRecoveryCodeCount = 8

// DefaultTwoFactorIssuer is the fallback issuer shown in the authenticator app.
const DefaultTwoFactorIssuer = "goravel-authkit"

// recoveryAlphabet excludes visually ambiguous characters (0/O, 1/I/L).
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Enrollment is returned when a user starts TOTP enrollment: the secret and the
// otpauth:// URL for rendering a QR code.
type Enrollment struct {
	Secret     string
	OtpauthURL string
}

// recoveryCode is one single-use recovery code with its consumption marker.
type recoveryCode struct {
	Code   string     `json:"code"`
	UsedAt *time.Time `json:"used_at,omitempty"`
}

// TwoFactor orchestrates TOTP enrollment, verification, and recovery codes. The
// secret and recovery codes are stored encrypted via the Crypter.
type TwoFactor struct {
	repo          repositories.UsersRepository
	crypter       Crypter
	issuer        string
	recoveryCount int
}

// NewTwoFactor builds the two-factor service. Empty issuer / non-positive
// recoveryCount fall back to the package defaults.
func NewTwoFactor(repo repositories.UsersRepository, crypter Crypter, issuer string, recoveryCount int) *TwoFactor {
	if strings.TrimSpace(issuer) == "" {
		issuer = DefaultTwoFactorIssuer
	}
	if recoveryCount <= 0 {
		recoveryCount = DefaultRecoveryCodeCount
	}
	return &TwoFactor{repo: repo, crypter: crypter, issuer: issuer, recoveryCount: recoveryCount}
}

// Enable starts enrollment: it generates a TOTP secret, stores it encrypted
// (not yet confirmed), and returns the secret + otpauth URL for the user to
// scan. Re-enrolling a confirmed user returns ErrTwoFactorAlreadyEnabled.
func (s *TwoFactor) Enable(ctx context.Context, id uuid.UUID) (*Enrollment, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if u == nil {
		return nil, ErrNotFound
	}
	if u.TwoFactorEnabled() {
		return nil, ErrTwoFactorAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.issuer, AccountName: u.Email})
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	enc, err := s.crypter.Encrypt(key.Secret())
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	// Store the pending secret; confirmed_at stays nil until Confirm.
	if err := s.repo.UpdateTwoFactor(ctx, id, &enc, nil, nil); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return &Enrollment{Secret: key.Secret(), OtpauthURL: key.URL()}, nil
}

// Confirm verifies a code against the pending secret, activates 2FA, and returns
// freshly generated recovery codes (shown to the user once).
func (s *TwoFactor) Confirm(ctx context.Context, id uuid.UUID, code string) ([]string, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if u == nil {
		return nil, ErrNotFound
	}
	if u.TwoFactorSecret == nil || *u.TwoFactorSecret == "" {
		return nil, ErrTwoFactorNotEnrolled
	}
	if u.TwoFactorEnabled() {
		return nil, ErrTwoFactorAlreadyEnabled
	}

	secret, err := s.crypter.Decrypt(*u.TwoFactorSecret)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if !totp.Validate(strings.TrimSpace(code), secret) {
		return nil, ErrInvalidCode
	}

	plain, enc, err := s.generateRecoveryCodes()
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	now := time.Now().UTC()
	if err := s.repo.UpdateTwoFactor(ctx, id, u.TwoFactorSecret, &enc, &now); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return plain, nil
}

// Verify checks a TOTP code against a confirmed user's secret.
func (s *TwoFactor) Verify(user *models.User, code string) (bool, error) {
	if user == nil || !user.TwoFactorEnabled() {
		return false, ErrTwoFactorNotEnrolled
	}
	secret, err := s.crypter.Decrypt(*user.TwoFactorSecret)
	if err != nil {
		return false, errors.Join(ErrInternal, err)
	}
	return totp.Validate(strings.TrimSpace(code), secret), nil
}

// ConsumeRecoveryCode verifies a recovery code and marks it used (single-use).
// Returns true when a matching unused code was consumed.
func (s *TwoFactor) ConsumeRecoveryCode(ctx context.Context, id uuid.UUID, code string) (bool, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return false, errors.Join(ErrInternal, err)
	}
	if u == nil || !u.TwoFactorEnabled() || u.TwoFactorRecoveryCodes == nil {
		return false, ErrTwoFactorNotEnrolled
	}
	codes, err := s.decodeRecoveryCodes(*u.TwoFactorRecoveryCodes)
	if err != nil {
		return false, errors.Join(ErrInternal, err)
	}

	code = strings.TrimSpace(code)
	matched := false
	for i := range codes {
		if codes[i].UsedAt == nil && subtle.ConstantTimeCompare([]byte(codes[i].Code), []byte(code)) == 1 {
			now := time.Now().UTC()
			codes[i].UsedAt = &now
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}

	enc, err := s.encodeRecoveryCodes(codes)
	if err != nil {
		return false, errors.Join(ErrInternal, err)
	}
	if err := s.repo.UpdateTwoFactor(ctx, id, u.TwoFactorSecret, &enc, u.TwoFactorConfirmedAt); err != nil {
		return false, errors.Join(ErrInternal, err)
	}
	return true, nil
}

// Disable clears all two-factor state for the user.
func (s *TwoFactor) Disable(ctx context.Context, id uuid.UUID) error {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return errors.Join(ErrInternal, err)
	}
	if u == nil {
		return ErrNotFound
	}
	if err := s.repo.UpdateTwoFactor(ctx, id, nil, nil, nil); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// RecoveryCodes returns the user's remaining (unused) recovery codes.
func (s *TwoFactor) RecoveryCodes(ctx context.Context, id uuid.UUID) ([]string, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if u == nil || !u.TwoFactorEnabled() || u.TwoFactorRecoveryCodes == nil {
		return nil, ErrTwoFactorNotEnrolled
	}
	codes, err := s.decodeRecoveryCodes(*u.TwoFactorRecoveryCodes)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		if c.UsedAt == nil {
			out = append(out, c.Code)
		}
	}
	return out, nil
}

// RegenerateRecoveryCodes replaces the recovery codes, invalidating the old set.
func (s *TwoFactor) RegenerateRecoveryCodes(ctx context.Context, id uuid.UUID) ([]string, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if u == nil || !u.TwoFactorEnabled() {
		return nil, ErrTwoFactorNotEnrolled
	}
	plain, enc, err := s.generateRecoveryCodes()
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if err := s.repo.UpdateTwoFactor(ctx, id, u.TwoFactorSecret, &enc, u.TwoFactorConfirmedAt); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return plain, nil
}

func (s *TwoFactor) generateRecoveryCodes() (plain []string, encrypted string, err error) {
	codes := make([]recoveryCode, 0, s.recoveryCount)
	plain = make([]string, 0, s.recoveryCount)
	for i := 0; i < s.recoveryCount; i++ {
		c, e := randomRecoveryCode()
		if e != nil {
			return nil, "", e
		}
		codes = append(codes, recoveryCode{Code: c})
		plain = append(plain, c)
	}
	encrypted, err = s.encodeRecoveryCodes(codes)
	return plain, encrypted, err
}

func (s *TwoFactor) encodeRecoveryCodes(codes []recoveryCode) (string, error) {
	b, err := json.Marshal(codes)
	if err != nil {
		return "", err
	}
	return s.crypter.Encrypt(string(b))
}

func (s *TwoFactor) decodeRecoveryCodes(enc string) ([]recoveryCode, error) {
	dec, err := s.crypter.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	var codes []recoveryCode
	if err := json.Unmarshal([]byte(dec), &codes); err != nil {
		return nil, err
	}
	return codes, nil
}

// randomRecoveryCode returns a 10-character code formatted XXXXX-XXXXX, drawn
// uniformly from recoveryAlphabet using crypto/rand (rejection sampling to avoid
// modulo bias).
func randomRecoveryCode() (string, error) {
	const n = 10
	alphabetLen := len(recoveryAlphabet)
	maxByte := 256 - (256 % alphabetLen) // largest unbiased byte value + 1
	out := make([]byte, 0, n+1)
	buf := make([]byte, 1)
	for len(out) < n+1 {
		if len(out) == 5 {
			out = append(out, '-')
			continue
		}
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= maxByte {
			continue // reject to keep the distribution uniform
		}
		out = append(out, recoveryAlphabet[int(buf[0])%alphabetLen])
	}
	return string(out), nil
}
