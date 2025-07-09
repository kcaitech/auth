package common

// prefix
const (
	RedisPrefixSession           = "auth_session:"        // + userID + sessionID -> session info
	RedisPrefixUser              = "auth_user:"           // + userID -> user info
	RedisPrefixRateLimit         = "auth_ratelimit:"      // + ip -> access count
	RedisPrefixLoginAttempts     = "auth_login_attempts:" // + userID + ip -> login attempts count
	RedisPrefixGoogleState       = "auth_google_oauth_state:"
	RedisPrefixWeixinState       = "auth_weixin_oauth_state:"
	RedisPrefixEmailState        = "auth_email_state:"
	RedisPrefixEmailVerifyCode   = "auth_email_verify_code:"
	RedisPrefixJWTKey            = "auth_jwt_key:"
	RedisPrefixVerification      = "auth_verification:"
	RedisPrefixVerificationToken = "auth_verification_token:"
	RedisPrefixEmailPreregister  = "auth_email_prereg:"
	RedisPrefixPhonePreregister  = "auth_phone_prereg:"
)
