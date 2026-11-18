package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// TwoFactorCredentialStamp binds an authentication event to the enrolled
// credential. It is server-side bookkeeping, never an authentication factor.
func (u *User) TwoFactorCredentialStamp() string {
	if !u.TwoFactorEnabled() {
		return ""
	}
	hash := sha256.Sum256([]byte(*u.TwoFactorSecret + "|" + u.TwoFactorConfirmedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(hash[:])
}
