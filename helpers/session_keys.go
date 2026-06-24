package helpers

// authkit stores a little bookkeeping in the session beyond the authenticated
// user id (which Goravel's session guard already scopes per guard as
// "auth_<guard>_id"). To let two authkit instances share one session cookie
// without clobbering each other, every authkit-owned key is namespaced by the
// instance's guard too. A single-instance app simply sees one stable namespace.

// PasswordChangedAtKey holds the users.password_changed_at value captured at
// login; the Authenticated middleware compares it with the DB value to log out
// every OTHER session after a password change.
func PasswordChangedAtKey(guard string) string {
	return "authkit_" + guard + "_password_changed_at"
}

// TwoFactorUserIDKey holds the id of a user who passed the password step but
// still owes a 2FA challenge. The session stays unauthenticated until it succeeds.
func TwoFactorUserIDKey(guard string) string {
	return "authkit_" + guard + "_two_factor_user_id"
}

// RememberIntentKey records, between the password step and the 2FA challenge,
// that the user asked to be remembered — so the persistent cookie is issued only
// after the challenge completes.
func RememberIntentKey(guard string) string {
	return "authkit_" + guard + "_remember_intent"
}

// SessionTrackingTokenKey holds a stable per-guard token that active-session
// tracking is keyed by (instead of Goravel's session id). The session id rotates
// on every login — including another guard's login on the same shared cookie —
// which would orphan this guard's tracking row; this token survives those
// rotations (it is a session attribute, preserved across Regenerate), so each
// guard's tracked session stays addressable.
func SessionTrackingTokenKey(guard string) string {
	return "authkit_" + guard + "_session_token"
}
