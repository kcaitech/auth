package handlers

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
	"kcaitech.com/kcauth/server/middleware"
)

// AuthHandler 认证处理器
type AuthHandler struct {
	useAccountAuth bool
	accountAuth    auth.AccountAuth
	emailAuth      *auth.EmailAuth
	googleOAuth    *auth.GoogleOAuth
	weixinLogin    *auth.WeixinLogin
	twoFactor      *auth.TwoFactorAuth
	jwtService     *auth.JWTService
	// rateLimiter    *middleware.RateLimiter
	sessionMgr *auth.SessionManager
	redisStore *auth.RedisStore
	// emailService   *auth.EmailService
	logger *log.Logger
}

// NewAuthHandler 创建新的认证处理器
func NewAuthHandler(
	useAccountAuth bool,
	accountAuth auth.AccountAuth,
	emailAuth *auth.EmailAuth,
	googleOAuth *auth.GoogleOAuth,
	weixinLogin *auth.WeixinLogin,
	twoFactor *auth.TwoFactorAuth,
	jwtService *auth.JWTService,
	// rateLimiter *middleware.RateLimiter,
	sessionMgr *auth.SessionManager,
	redisStore *auth.RedisStore) *AuthHandler {
	return &AuthHandler{
		useAccountAuth: useAccountAuth,
		accountAuth:    accountAuth,
		emailAuth:      emailAuth,
		googleOAuth:    googleOAuth,
		weixinLogin:    weixinLogin,
		twoFactor:      twoFactor,
		jwtService:     jwtService,
		// rateLimiter:    rateLimiter,
		sessionMgr: sessionMgr,
		redisStore: redisStore,
		logger:     log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile),
	}
}

// RegisterRoutes 注册路由
func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	// 添加错误处理中间件
	r.Use(auth.ErrorHandler())

	// 添加监控中间件
	r.Use(middleware.MetricsMiddleware())

	// 添加速率限制中间件（如果启用）
	// if h.rateLimiter != nil {
	// 	r.Use(h.rateLimiter.RateLimitMiddleware())
	// }
	rateLimiter := middleware.RateLimiter{}
	r.Use(rateLimiter.RateLimitMiddleware())
	// 认证相关路由组
	authGroup := r.Group("/auth")
	{
		// 获取支持的登录方式
		authGroup.GET("/providers", h.GetSupportedProviders)

		// 账号登录相关路由
		if h.useAccountAuth {
			authGroup.POST("/register", h.Register)
			// authGroup.POST("/register/email", h.RegisterByEmail)
			authGroup.POST("/login", h.Login)
			authGroup.POST("/logout", h.AuthRequired(), h.Logout)
			authGroup.POST("/password/reset", h.ResetPassword)
			// authGroup.POST("/password/reset/complete", h.CompletePasswordReset)
			// authGroup.GET("/verify-email", h.VerifyEmail)
			// authGroup.POST("/resend-verification", h.ResendVerificationEmail)
		}
		// authGroup.POST("/refresh-session", h.RefreshSession)
		authGroup.POST("/refresh-token", h.RefreshToken)

		// 邮箱登录相关路由
		if h.emailAuth != nil {
			authGroup.POST("/email/login", h.EmailLogin)
			authGroup.POST("/email/register", h.EmailRegister)
			authGroup.GET("/email/verify", h.EmailVerify)
			authGroup.POST("/email/resend-verification", h.ResendEmailVerification)
			authGroup.POST("/email/password/reset", h.EmailPasswordReset)
			authGroup.POST("/email/password/reset/complete", h.CompleteEmailPasswordReset)
		}

		// Google OAuth相关路由
		if h.googleOAuth != nil {
			authGroup.GET("/google/login", h.GoogleLogin)
			authGroup.GET("/google/callback", h.GoogleCallback)
			authGroup.POST("/google", h.GoogleLoginPost)
		}

		// 微信登录相关路由
		if h.weixinLogin != nil {
			authGroup.GET("/weixin/url", h.WeixinLoginURL)
			authGroup.GET("/weixin/login", h.WeixinLoginHandler)
			authGroup.GET("/weixin/callback", h.WeixinCallback)
		}

		// 双因素认证相关路由
		if h.twoFactor != nil {
			authGroup.POST("/2fa/enable", h.AuthRequired(), h.Enable2FA)
			authGroup.POST("/2fa/disable", h.AuthRequired(), h.Disable2FA)
			authGroup.POST("/2fa/verify", h.Verify2FA)
			authGroup.POST("/2fa/recovery", h.AuthRequired(), h.GenerateRecoveryCodes)
		}

		// 用户信息相关路由
		authGroup.GET("/user", h.AuthRequired(), h.GetUserInfo)
		authGroup.PUT("/user", h.AuthRequired(), h.UpdateUserInfo)
	}
}

// GetSupportedProviders 获取支持的登录方式
func (h *AuthHandler) GetSupportedProviders(c *gin.Context) {
	providers := []string{}

	// 添加账号登录方式
	if h.useAccountAuth {
		providers = append(providers, "account")
	}

	// 添加邮箱登录方式
	if h.emailAuth != nil {
		providers = append(providers, "email")
	}

	// 添加Google登录方式
	if h.googleOAuth != nil {
		providers = append(providers, "google")
	}

	// 添加微信登录方式
	if h.weixinLogin != nil {
		providers = append(providers, "weixin")
	}

	c.JSON(200, gin.H{
		"providers": providers,
	})
}
