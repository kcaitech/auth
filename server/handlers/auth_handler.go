package handlers

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
	"kcaitech.com/kcauth/server/auth/storage"
	"kcaitech.com/kcauth/server/config"
	"kcaitech.com/kcauth/server/middleware"
)

// AuthHandler Authentication handler
type AuthHandler struct {
	useAccountAuth bool
	accountAuth    *auth.AccountAuth
	emailAuth      *auth.EmailAuth
	googleOAuth    *auth.GoogleOAuth
	weixinLogin    *auth.WeixinLogin
	phoneAuth      *auth.PhoneAuth
	twoFactor      *auth.TwoFactorAuth
	jwtService     *auth.JWTService
	sessionMgr     *auth.SessionManager
	redisStore     *auth.RedisStore
	storage        *storage.StorageClient
	avatarService  *auth.AvatarService
	avatarHandler  *AvatarHandler
	config         *config.Config
	logger         *log.Logger
}

// NewAuthHandler Create new authentication handler
func NewAuthHandler(
	useAccountAuth bool,
	accountAuth *auth.AccountAuth,
	emailAuth *auth.EmailAuth,
	googleOAuth *auth.GoogleOAuth,
	weixinLogin *auth.WeixinLogin,
	phoneAuth *auth.PhoneAuth,
	twoFactor *auth.TwoFactorAuth,
	jwtService *auth.JWTService,
	sessionMgr *auth.SessionManager,
	redisStore *auth.RedisStore,
	storage *storage.StorageClient,
	avatarService *auth.AvatarService,
	config *config.Config) *AuthHandler {
	return &AuthHandler{
		useAccountAuth: useAccountAuth,
		accountAuth:    accountAuth,
		emailAuth:      emailAuth,
		googleOAuth:    googleOAuth,
		weixinLogin:    weixinLogin,
		phoneAuth:      phoneAuth,
		twoFactor:      twoFactor,
		jwtService:     jwtService,
		sessionMgr:     sessionMgr,
		redisStore:     redisStore,
		storage:        storage,
		avatarService:  avatarService,
		avatarHandler:  NewAvatarHandler(accountAuth, avatarService),
		config:         config,
		logger:         log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile),
	}
}

// RegisterRoutes Register routes
func (h *AuthHandler) RegisterRoutes(authGroup *gin.RouterGroup, cfg *config.Config) {
	// Get supported login methods
	authGroup.GET("/providers", h.GetSupportedProviders)

	// Account login related routes
	if h.useAccountAuth {
		authGroup.POST("/account/register", h.Register)
		authGroup.POST("/account/login", h.Login)
		authGroup.POST("/account/password/reset", h.AuthRequired(), h.ResetPassword)
	}
	authGroup.POST("/logout", h.AuthRequired(), h.Logout)
	authGroup.POST("/token/refresh", h.RefreshToken)
	authGroup.POST("/token/validate", h.ValidateToken)

	// Email login related routes
	if h.emailAuth != nil {
		authGroup.POST("/email/login", h.EmailLogin)
		authGroup.POST("/email/register", h.EmailRegister)
		authGroup.GET("/email/verify", h.EmailVerify)
		authGroup.POST("/email/resend-verification", h.ResendEmailVerification)
		authGroup.POST("/email/password/reset", h.EmailPasswordReset)
		authGroup.POST("/email/password/reset/complete", h.CompleteEmailPasswordReset)
	}

	// Google OAuth related routes
	if h.googleOAuth != nil {
		// Get Google client ID, for frontend to use
		authGroup.GET("/google/client_id", h.GetGoogleClientID)
		authGroup.POST("/google/callback", h.GoogleCredential)
	}

	// WeChat login related routes
	if h.weixinLogin != nil {
		authGroup.GET("/weixin/url", h.WeixinLoginURL)
		// authGroup.GET("/weixin/login", h.WeixinLoginHandler)
		authGroup.GET("/weixin/callback", h.WeixinCallback)
	}

	// Phone login related routes
	if h.phoneAuth != nil {
		// Create phone handler
		phoneHandler := NewPhoneHandler(h.phoneAuth, h.sessionMgr, h.jwtService, h.config)
		// Register phone authentication routes
		phoneHandler.RegisterRoutes(authGroup)
	}

	// Two-factor authentication related routes
	if h.twoFactor != nil {
		authGroup.POST("/2fa/enable", h.AuthRequired(), h.Enable2FA)
		authGroup.POST("/2fa/disable", h.AuthRequired(), h.Disable2FA)
		authGroup.POST("/2fa/verify", h.Verify2FA)
		authGroup.POST("/2fa/recovery", h.AuthRequired(), h.GenerateRecoveryCodes)
	}

	trustedClient := middleware.TrustedClient(cfg)
	// User information related routes
	authGroup.GET("/user", h.AuthRequired(), h.GetUserInfo)
	authGroup.GET("/user/:id", h.AuthRequired(), trustedClient, h.GetUserInfoById)
	authGroup.POST("/users", h.AuthRequired(), trustedClient, h.GetUsersInfo)
	authGroup.PUT("/user", h.AuthRequired(), h.UpdateUserInfo)

	// Avatar related routes
	authGroup.POST("/avatar/upload", h.AuthRequired(), h.avatarHandler.UploadAvatar)
	authGroup.DELETE("/avatar", h.AuthRequired(), h.avatarHandler.DeleteAvatar)

	// User session information
	authGroup.GET("/sessions", h.AuthRequired(), h.GetUserSessions)
	authGroup.DELETE("/sessions/:session_id", h.AuthRequired(), h.TerminateUserSession)
	authGroup.DELETE("/sessions", h.AuthRequired(), h.TerminateAllUserSessions)
}

// GetSupportedProviders Get supported login methods
func (h *AuthHandler) GetSupportedProviders(c *gin.Context) {
	providers := []string{}

	// Add account login method
	if h.useAccountAuth {
		providers = append(providers, "account")
	}

	// Add email login method
	if h.emailAuth != nil {
		providers = append(providers, "email")
	}

	// Add Google login method
	if h.googleOAuth != nil {
		providers = append(providers, "google")
	}

	// Add WeChat login method
	if h.weixinLogin != nil {
		providers = append(providers, "weixin")
	}

	// Add phone login method
	if h.phoneAuth != nil {
		providers = append(providers, "phone")
	}

	c.JSON(200, gin.H{
		"providers": providers,
	})
}
