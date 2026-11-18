package models

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// TwoFactorCredentialStamp binds an authentication event to the enrolled
// credential. It is server-side bookkeeping, never an authentication factor.
func (u *User) TwoFactorCredentialStamp() string {
	if !u.TwoFactorEnabled() {
		return strconv.FormatInt(u.TwoFactorVersion, 10)
	}
	hash := sha256.Sum256([]byte(strconv.FormatInt(u.TwoFactorVersion, 10) + "|" + *u.TwoFactorSecret + "|" + u.TwoFactorConfirmedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(hash[:])
}

// AdvancePasswordEpoch keeps credential changes distinct at database precision.
func (u *User) AdvancePasswordEpoch(at time.Time) {
	at = at.UTC().Truncate(time.Microsecond)
	if !at.After(u.PasswordChangedAt) {
		at = u.PasswordChangedAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	}
	u.PasswordChangedAt = at
}
