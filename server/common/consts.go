package common

// prefix
const (
	RedisPrefixSession           = "session:"
	RedisPrefixUserSession       = "user_sessions:"
	RedisPrefixUser              = "user:"
	RedisPrefixToken             = "token:"
	RedisPrefixRateLimit         = "ratelimit:"
	RedisPrefixLoginAttempts     = "login_attempts:"
	RedisPrefixGoogleState       = "google_oauth_state:"
	RedisPrefixWeixinState       = "weixin_oauth_state:"
	RedisPrefixEmailState        = "email_state:"
	RedisPrefixEmailVerifyCode   = "email_verify_code:"
	RedisPrefixJWTKey            = "jwt_key:"
	RedisPrefixVerification      = "verification:"
	RedisPrefixVerificationToken = "verification_token:"
	RedisPrefixEmailPreregister  = "email_prereg:"
	RedisPrefixPhonePreregister  = "phone_prereg:"
)
