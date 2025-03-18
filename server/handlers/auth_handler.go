package handlers

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// AuthHandler 认证处理器
type AuthHandler struct {
	accountAuth *auth.AccountAuth
	googleOAuth *auth.GoogleOAuth
	weixinLogin *auth.WeixinLogin
	twoFactor   *auth.TwoFactorAuth
	jwtService  *auth.JWTService
	rateLimiter *auth.RateLimiter
	logger      *log.Logger
}

// NewAuthHandler 创建新的认证处理器
func NewAuthHandler(accountAuth *auth.AccountAuth, googleOAuth *auth.GoogleOAuth, weixinLogin *auth.WeixinLogin,
	twoFactor *auth.TwoFactorAuth, jwtService *auth.JWTService, rateLimiter *auth.RateLimiter) *AuthHandler {
	return &AuthHandler{
		accountAuth: accountAuth,
		googleOAuth: googleOAuth,
		weixinLogin: weixinLogin,
		twoFactor:   twoFactor,
		jwtService:  jwtService,
		rateLimiter: rateLimiter,
		logger:      log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile),
	}
}

// RegisterRoutes 注册路由
func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	// 添加错误处理中间件
	r.Use(auth.ErrorHandler())

	// 添加监控中间件
	r.Use(auth.MetricsMiddleware())

	// 添加速率限制中间件（如果启用）
	if h.rateLimiter != nil {
		r.Use(h.rateLimiter.RateLimitMiddleware())
	}

	// 认证相关路由组
	authGroup := r.Group("/auth")
	{
		// 账号登录相关路由
		if h.accountAuth != nil {
			authGroup.POST("/register", h.Register)
			authGroup.POST("/login", h.Login)
			authGroup.POST("/logout", h.AuthRequired(), h.Logout)
			authGroup.POST("/refresh", h.RefreshToken)
			authGroup.POST("/password/reset", h.InitiatePasswordReset)
			authGroup.POST("/password/reset/complete", h.CompletePasswordReset)
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
