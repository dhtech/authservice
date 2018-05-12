package auth

type Attempt interface {
	// Only used for username/password auth
	Username() string
	// Used for password/OTP/U2F
	Credential() string
}
