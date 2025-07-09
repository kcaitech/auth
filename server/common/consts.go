package common

// prefix
const (
	RedisPrefixSession           = "session:"        // + userID + sessionID -> session info
	RedisPrefixUser              = "user:"           // + userID -> user info
	RedisPrefixRateLimit         = "ratelimit:"      // + ip -> access count
	RedisPrefixLoginAttempts     = "login_attempts:" // + userID + ip -> login attempts count
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
