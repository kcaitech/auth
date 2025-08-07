/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

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
	useAccountAuth  bool
	accountAuth     *auth.AccountAuth
	emailAuth       *auth.EmailAuth
	googleOAuth     *auth.GoogleOAuth
	weixinLogin     *auth.WeixinLogin
	weixinMiniLogin *auth.WeixinMiniLogin
	phoneAuth       *auth.PhoneAuth
	jwtService      *auth.JWTService
	sessionMgr      *auth.SessionManager
	redisStore      *auth.RedisStore
	storage         *storage.StorageClient
	avatarService   *auth.AvatarService
	avatarHandler   *AvatarHandler
	config          *config.Config
	logger          *log.Logger
}

// NewAuthHandler Create new authentication handler
func NewAuthHandler(
	useAccountAuth bool,
	accountAuth *auth.AccountAuth,
	emailAuth *auth.EmailAuth,
	googleOAuth *auth.GoogleOAuth,
	weixinLogin *auth.WeixinLogin,
	weixinMiniLogin *auth.WeixinMiniLogin,
	phoneAuth *auth.PhoneAuth,
	jwtService *auth.JWTService,
	sessionMgr *auth.SessionManager,
	redisStore *auth.RedisStore,
	storage *storage.StorageClient,
	avatarService *auth.AvatarService,
	config *config.Config) *AuthHandler {
	return &AuthHandler{
		useAccountAuth:  useAccountAuth,
		accountAuth:     accountAuth,
		emailAuth:       emailAuth,
		googleOAuth:     googleOAuth,
		weixinLogin:     weixinLogin,
		weixinMiniLogin: weixinMiniLogin,
		phoneAuth:       phoneAuth,
		jwtService:      jwtService,
		sessionMgr:      sessionMgr,
		redisStore:      redisStore,
		storage:         storage,
		avatarService:   avatarService,
		avatarHandler:   NewAvatarHandler(accountAuth, avatarService),
		config:          config,
		logger:          log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile),
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

	// 已经登陆，直接回调到应用
	authGroup.GET("/login/redirect", h.AuthRequired(), h.LoginRedirect)

	trustedClient := middleware.TrustedClient(cfg)
	authGroup.GET("/login/verify", trustedClient, h.LoginVerify)

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

	if h.weixinMiniLogin != nil {
		authGroup.GET("/weixin/miniprogram", h.WeixinMiniLogin)
	}

	// Phone login related routes
	if h.phoneAuth != nil {
		// Phone pre-registration - send verification code
		authGroup.POST("/phone/preregister", h.PhonePreregister)
		// Verify phone number and complete registration
		authGroup.POST("/phone/verify-register", h.VerifyPhoneAndRegister)
		// Resend verification code
		authGroup.POST("/phone/resend-verification", h.ResendPhoneVerification)
		// Login with phone number + password
		authGroup.POST("/phone/login", h.PhoneLogin)
		// Send login verification code
		authGroup.POST("/phone/send-login-code", h.SendLoginSMS)
		// Login with phone number + verification code
		authGroup.POST("/phone/code-login", h.PhoneCodeLogin)
		// Initiate password reset - send verification code
		authGroup.POST("/phone/reset-password/init", h.PhoneInitiatePasswordReset)
		// Complete password reset
		authGroup.POST("/phone/reset-password/complete", h.PhoneCompletePasswordReset)
	}

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

	// Add WeChat Mini Program login method
	if h.weixinMiniLogin != nil {
		providers = append(providers, "weixin_mini")
	}

	// Add phone login method
	if h.phoneAuth != nil {
		providers = append(providers, "phone")
	}

	c.JSON(200, gin.H{
		"providers": providers,
	})
}
