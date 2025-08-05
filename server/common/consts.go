package common

// prefix
const (
	RedisKeySession           = "auth_session:"        // + userID + sessionID -> session info
	RedisKeyUser              = "auth_user:"           // + userID -> user info
	RedisKeyRateLimit         = "auth_ratelimit:"      // + ip -> access count
	RedisKeyLoginAttempts     = "auth_login_attempts:" // + userID + ip -> login attempts count
	RedisKeyGoogleState       = "auth_google_oauth_state:"
	RedisKeyWeixinState       = "auth_weixin_oauth_state:"
	RedisKeyEmailState        = "auth_email_state:"
	RedisKeyEmailVerifyCode   = "auth_email_verify_code:"
	RedisKeyJWTKey            = "auth_jwt_key:"
	RedisKeyVerification      = "auth_verification:"
	RedisKeyVerificationToken = "auth_verification_token:"
	RedisKeyEmailPreregister  = "auth_email_prereg:"
	RedisKeyPhonePreregister  = "auth_phone_prereg:"
	RedisKeyOauthCode         = "auth_oauth_code:"
)
