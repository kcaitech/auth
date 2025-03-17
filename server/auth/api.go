package auth

import (
	"net/http"
	"time"
	"fmt"
	"log"
	"os"
	"math/rand"
	"encoding/hex"
	"strings"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/sessions"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"sync"
)

// RateLimiter 速率限制器
type RateLimiter struct {
	ips    map[string]*rate.Limiter
	mu     sync.RWMutex
	rate   rate.Limit
	burst  int
}

// NewRateLimiter 创建新的速率限制器
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		ips:   make(map[string]*rate.Limiter),
		rate:  r,
		burst: b,
	}
}

// GetLimiter 获取特定IP的限制器
func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.ips[ip] = limiter
	}

	return limiter
}

// 错误定义
var (
	ErrInvalidConfig = errors.New("invalid weixin config")
	ErrInvalidCode = errors.New("invalid code")
	ErrAPIRequest = errors.New("weixin api request failed")
	ErrInvalidSession = errors.New("invalid session")
)

// UserStatus 用户状态
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusBanned   UserStatus = "banned"
)

// UserProfile 用户档案
type UserProfile struct {
	Avatar   string `json:"avatar"`
	Gender   string `json:"gender"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
}

// Session 会话模型
type Session struct {
	ID        string    `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// WeixinLoginRequest 微信登录请求
type WeixinLoginRequest struct {
	Code  string `json:"code" binding:"required"`
	State string `json:"state" binding:"required"`
}

// RefreshTokenRequest 刷新令牌请求
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// 添加新的请求结构体
type EnableTwoFactorRequest struct {
	Code string `json:"code" binding:"required"`
}

type DisableTwoFactorRequest struct {
	Code string `json:"code" binding:"required"`
}

type VerifyTwoFactorRequest struct {
	Code string `json:"code" binding:"required"`
}

// AuthHandler 认证处理器
type AuthHandler struct {
	googleOAuth *GoogleOAuth
	accountAuth *AccountAuth
	jwtService  *JWTService
	rateLimiter *RateLimiter
	logger      *log.Logger
	weixinLogin *WeixinLogin
	twoFactor   *TwoFactorAuth
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type PasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type CompletePasswordResetRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type UpdateProfileRequest struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty" binding:"omitempty,email"`
}

func NewAuthHandler(clientID, clientSecret, redirectURL string, accountAuth *AccountAuth, redisStore *RedisStore) *AuthHandler {
	googleOAuth, err := NewGoogleOAuth(GoogleOAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Timeout:      10 * time.Second,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to initialize Google OAuth: %v", err))
	}

	// 创建微信登录实例
	weixinLogin, err := NewWeixinLogin(WeixinConfig{
		AppID:       os.Getenv("WEIXIN_APP_ID"),
		AppSecret:   os.Getenv("WEIXIN_APP_SECRET"),
		RedirectURL: os.Getenv("WEIXIN_REDIRECT_URL"),
	})
	if err != nil {
		panic(fmt.Sprintf("failed to initialize Weixin Login: %v", err))
	}

	// 创建双因素认证服务
	twoFactorConfig := NewDefaultTwoFactorConfig("YourApp")
	twoFactor := NewTwoFactorAuth(twoFactorConfig, accountAuth)

	// 创建日志记录器
	logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile)

	return &AuthHandler{
		googleOAuth:  googleOAuth,
		accountAuth:  accountAuth,
		jwtService:   NewJWTService(redisStore),
		rateLimiter:  NewRateLimiter(rate.Limit(1), 5), // 每秒1个请求，突发5个
		logger:       logger,
		weixinLogin:  weixinLogin,
		twoFactor:    twoFactor,
	}
}

// RateLimitMiddleware 速率限制中间件
func (h *AuthHandler) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := h.rateLimiter.GetLimiter(ip)
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		// 添加速率限制中间件
		auth.Use(h.RateLimitMiddleware())

		// OAuth路由
		auth.GET("/google/login", h.GoogleLogin)
		auth.GET("/google/callback", h.GoogleCallback)

		// 微信登录路由
		auth.GET("/weixin/login", h.WeixinLogin)
		auth.GET("/weixin/callback", h.WeixinCallback)
		auth.POST("/weixin/login", h.handleWeixinLogin)
		auth.POST("/token/refresh", h.handleRefreshToken)

		// 账号相关路由
		auth.POST("/register", h.handleRegister)
		auth.POST("/login", h.handleLogin)
		auth.POST("/password/reset", h.handlePasswordReset)
		auth.POST("/password/reset/complete", h.handlePasswordResetComplete)
		
		// 需要认证的路由
		authorized := auth.Group("")
		authorized.Use(h.AuthMiddleware())
		{
			authorized.PUT("/profile", h.handleUpdateProfile)
			authorized.POST("/password/change", h.handleChangePassword)
		}

		// 双因素认证路由
		twoFactor := auth.Group("/2fa")
		twoFactor.Use(h.AuthMiddleware())
		{
			twoFactor.POST("/setup", h.handleSetupTwoFactor)
			twoFactor.POST("/enable", h.handleEnableTwoFactor)
			twoFactor.POST("/disable", h.handleDisableTwoFactor)
			twoFactor.POST("/verify", h.handleVerifyTwoFactor)
			twoFactor.POST("/recovery-codes/generate", h.handleGenerateRecoveryCodes)
		}
	}
}

func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	h.logger.Printf("Initiating Google login for IP: %s", c.ClientIP())
	
	state, err := h.googleOAuth.GenerateState()
	if err != nil {
		h.logger.Printf("Failed to generate state: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// 将 state 存储在 session 中
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	if err := session.Save(); err != nil {
		h.logger.Printf("Failed to save session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	url := h.googleOAuth.GetAuthURL(state)
	h.logger.Printf("Redirecting to Google OAuth URL for IP: %s", c.ClientIP())
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	// 从 session 中获取并验证 state
	session := sessions.Default(c)
	expectedState := session.Get("oauth_state")
	session.Delete("oauth_state")
	session.Save()

	if expectedState == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session"})
		return
	}

	user, err := h.googleOAuth.HandleCallback(c.Request.Context(), code, state, expectedState.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 检查用户是否已存在
	dbUser, err := h.accountAuth.GetUserByEmail(user.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if dbUser == nil {
		// 创建新用户
		dbUser = &User{
			Email:     user.Email,
			Username:  user.Name,
			Provider:  "google",
			SocialID:  user.ID,
			Status:    UserStatusActive,
		}
		if err := h.accountAuth.CreateUser(dbUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	}

	// 生成会话ID
	sessionID := generateSessionID()

	// 生成 JWT token
	token, err := h.jwtService.GenerateJWT(int64(dbUser.ID), dbUser.Email, sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  dbUser,
	})
}

func (h *AuthHandler) handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.accountAuth.Register(req.Username, req.Password, req.Email); err != nil {
		statusCode := http.StatusInternalServerError
		if appErr, ok := err.(*AppError); ok {
			switch appErr.Code {
			case ErrCodeUsernameTaken, ErrCodeEmailTaken, ErrCodeInvalidUsername,
				ErrCodeInvalidEmail, ErrCodeWeakPassword:
				statusCode = http.StatusBadRequest
			}
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})
}

func (h *AuthHandler) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Printf("Invalid login request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	user, err := h.accountAuth.Login(req.Username, req.Password)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if appErr, ok := err.(*AppError); ok {
			switch appErr.Code {
			case ErrCodeUserNotFound, ErrCodeInvalidPassword, ErrCodeTooManyAttempts:
				statusCode = http.StatusUnauthorized
			}
		}
		h.logger.Printf("Login failed for user %s: %v", req.Username, err)
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	// 生成会话ID
	sessionID := generateSessionID()
	
	// 生成 JWT token
	token, err := h.jwtService.GenerateJWT(int64(user.ID), user.Email, sessionID)
	if err != nil {
		h.logger.Printf("Failed to generate token for user %s: %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	h.logger.Printf("User %s logged in successfully", user.Username)
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": user,
	})
}

// 生成会话ID
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *AuthHandler) handlePasswordReset(c *gin.Context) {
	var req PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	token, err := h.accountAuth.InitiatePasswordReset(req.Email)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if appErr, ok := err.(*AppError); ok {
			switch appErr.Code {
			case ErrCodeUserNotFound:
				statusCode = http.StatusNotFound
			}
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	// TODO: 发送重置密码邮件
	c.JSON(http.StatusOK, gin.H{
		"message": "password reset email sent",
		"reset_token": token, // 注意：实际生产环境中不应该直接返回token
	})
}

func (h *AuthHandler) handlePasswordResetComplete(c *gin.Context) {
	var req CompletePasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.accountAuth.CompletePasswordReset(req.Token, req.NewPassword); err != nil {
		statusCode := http.StatusInternalServerError
		if appErr, ok := err.(*AppError); ok {
			switch appErr.Code {
			case ErrCodeInvalidToken, ErrCodeTokenExpired, ErrCodeWeakPassword:
				statusCode = http.StatusBadRequest
			}
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successful"})
}

func (h *AuthHandler) handleUpdateProfile(c *gin.Context) {
	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// 从上下文获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	updates := make(map[string]interface{})
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.Email != "" {
		updates["email"] = req.Email
	}

	if err := h.accountAuth.UpdateProfile(userID.(uint), updates); err != nil {
		statusCode := http.StatusInternalServerError
		if appErr, ok := err.(*AppError); ok {
			switch appErr.Code {
			case ErrCodeUserNotFound:
				statusCode = http.StatusNotFound
			case ErrCodeUsernameTaken, ErrCodeEmailTaken,
				ErrCodeInvalidUsername, ErrCodeInvalidEmail:
				statusCode = http.StatusBadRequest
			}
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "profile updated successfully"})
}

func (h *AuthHandler) handleChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// 从上下文获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.accountAuth.ChangePassword(userID.(uint), req.OldPassword, req.NewPassword); err != nil {
		statusCode := http.StatusInternalServerError
		if appErr, ok := err.(*AppError); ok {
			switch appErr.Code {
			case ErrCodeUserNotFound:
				statusCode = http.StatusNotFound
			case ErrCodeInvalidPassword, ErrCodeWeakPassword:
				statusCode = http.StatusBadRequest
			}
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
}

// AuthMiddleware JWT认证中间件
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// 从 Authorization 头中提取 token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		// 验证 token
		claims, err := h.jwtService.ValidateJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("session_id", claims.SessionID)

		c.Next()
	}
}

// WeixinLogin 处理微信登录请求
func (h *AuthHandler) WeixinLogin(c *gin.Context) {
	h.logger.Printf("Initiating Weixin login for IP: %s", c.ClientIP())
	
	// 生成随机state
	state := make([]byte, 16)
	if _, err := rand.Read(state); err != nil {
		h.logger.Printf("Failed to generate state: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}
	stateStr := hex.EncodeToString(state)

	// 将state存储在session中
	session := sessions.Default(c)
	session.Set("weixin_oauth_state", stateStr)
	if err := session.Save(); err != nil {
		h.logger.Printf("Failed to save session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	// 获取授权URL并重定向
	url := h.weixinLogin.GetAuthURL(stateStr)
	h.logger.Printf("Redirecting to Weixin OAuth URL for IP: %s", c.ClientIP())
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// WeixinCallback 处理微信回调
func (h *AuthHandler) WeixinCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	// 验证state
	session := sessions.Default(c)
	expectedState := session.Get("weixin_oauth_state")
	session.Delete("weixin_oauth_state")
	session.Save()

	if expectedState == nil || state != expectedState.(string) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
		return
	}

	// 处理回调，获取访问令牌
	loginResp, err := h.weixinLogin.HandleCallback(code)
	if err != nil {
		h.logger.Printf("Failed to handle Weixin callback: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to handle callback"})
		return
	}

	// 获取用户信息
	userInfo, err := h.weixinLogin.GetUserInfo(loginResp.AccessToken, loginResp.OpenID)
	if err != nil {
		h.logger.Printf("Failed to get Weixin user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// 检查用户是否已存在
	dbUser, err := h.accountAuth.GetUserByWeixinID(userInfo.UnionID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if dbUser == nil {
		// 将性别数字转换为字符串
		var gender string
		switch userInfo.Sex {
		case 1:
			gender = "male"
		case 2:
			gender = "female"
		default:
			gender = "unknown"
		}

		// 创建新用户
		dbUser = &User{
			Username:  userInfo.Nickname,
			Provider:  "weixin",
			SocialID:  userInfo.UnionID,
			Status:    UserStatusActive,
			Profile: UserProfile{
				Avatar:   userInfo.HeadImgURL,
				Gender:   gender,
				Country:  userInfo.Country,
				Province: userInfo.Province,
				City:     userInfo.City,
			},
		}
		if err := h.accountAuth.CreateUser(dbUser); err != nil {
			h.logger.Printf("Failed to create user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	}

	// 生成会话ID
	sessionID := generateSessionID()

	// 生成JWT令牌
	token, err := h.jwtService.GenerateJWT(int64(dbUser.ID), dbUser.Email, sessionID)
	if err != nil {
		h.logger.Printf("Failed to generate token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	h.logger.Printf("Weixin user %s logged in successfully", dbUser.Username)
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  dbUser,
	})
}

// handleWeixinLogin 处理微信小程序/APP登录
func (h *AuthHandler) handleWeixinLogin(c *gin.Context) {
	var req WeixinLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// 处理回调，获取访问令牌
	loginResp, err := h.weixinLogin.HandleCallback(req.Code)
	if err != nil {
		h.logger.Printf("Failed to handle Weixin login: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to handle login"})
		return
	}

	// 获取用户信息
	userInfo, err := h.weixinLogin.GetUserInfo(loginResp.AccessToken, loginResp.OpenID)
	if err != nil {
		h.logger.Printf("Failed to get Weixin user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// 处理用户登录
	token, user, err := h.handleWeixinUser(userInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": user,
		"refresh_token": loginResp.RefreshToken,
	})
}

// handleWeixinUser 处理微信用户登录
func (h *AuthHandler) handleWeixinUser(userInfo *WeixinUserInfo) (string, *User, error) {
	// 检查用户是否已存在
	dbUser, err := h.accountAuth.GetUserByWeixinID(userInfo.UnionID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil, fmt.Errorf("database error: %v", err)
	}

	if dbUser == nil {
		// 将性别数字转换为字符串
		var gender string
		switch userInfo.Sex {
		case 1:
			gender = "male"
		case 2:
			gender = "female"
		default:
			gender = "unknown"
		}

		// 创建新用户
		dbUser = &User{
			Username:  userInfo.Nickname,
			Provider:  "weixin",
			SocialID:  userInfo.UnionID,
			Status:    UserStatusActive,
			Profile: UserProfile{
				Avatar:   userInfo.HeadImgURL,
				Gender:   gender,
				Country:  userInfo.Country,
				Province: userInfo.Province,
				City:     userInfo.City,
			},
		}
		if err := h.accountAuth.CreateUser(dbUser); err != nil {
			return "", nil, fmt.Errorf("failed to create user: %v", err)
		}
	}

	// 更新最后登录时间
	now := time.Now()
	dbUser.LastLogin = &now
	if err := h.accountAuth.UpdateUser(dbUser); err != nil {
		h.logger.Printf("Failed to update last login time: %v", err)
	}

	// 生成会话ID和JWT令牌
	sessionID := generateSessionID()
	token, err := h.jwtService.GenerateJWT(int64(dbUser.ID), dbUser.Email, sessionID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token: %v", err)
	}

	return token, dbUser, nil
}

// handleRefreshToken 处理令牌刷新
func (h *AuthHandler) handleRefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// 刷新访问令牌
	loginResp, err := h.weixinLogin.RefreshToken(req.RefreshToken)
	if err != nil {
		h.logger.Printf("Failed to refresh token: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to refresh token"})
		return
	}

	// 获取用户信息
	userInfo, err := h.weixinLogin.GetUserInfo(loginResp.AccessToken, loginResp.OpenID)
	if err != nil {
		h.logger.Printf("Failed to get user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// 处理用户登录
	token, user, err := h.handleWeixinUser(userInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": user,
		"refresh_token": loginResp.RefreshToken,
	})
}

// handleSetupTwoFactor 处理双因素认证设置
func (h *AuthHandler) handleSetupTwoFactor(c *gin.Context) {
	userID := c.GetUint("user_id")

	// 生成新的TOTP密钥
	key, err := h.twoFactor.GenerateSecret(userID)
	if err != nil {
		h.logger.Printf("Failed to generate 2FA secret: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate 2FA secret"})
		return
	}

	// 保存临时密钥
	if err := h.accountAuth.EnableTwoFactor(userID, key.Secret()); err != nil {
		h.logger.Printf("Failed to save temporary 2FA secret: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save 2FA secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret": key.Secret(),
		"qr_code": key.URL(),
	})
}

// handleEnableTwoFactor 处理启用双因素认证
func (h *AuthHandler) handleEnableTwoFactor(c *gin.Context) {
	var req EnableTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetUint("user_id")
	if err := h.twoFactor.EnableTwoFactor(userID, req.Code); err != nil {
		h.logger.Printf("Failed to enable 2FA: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA enabled successfully"})
}

// handleDisableTwoFactor 处理禁用双因素认证
func (h *AuthHandler) handleDisableTwoFactor(c *gin.Context) {
	var req DisableTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetUint("user_id")
	if err := h.twoFactor.DisableTwoFactor(userID, req.Code); err != nil {
		h.logger.Printf("Failed to disable 2FA: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA disabled successfully"})
}

// handleVerifyTwoFactor 处理验证双因素认证
func (h *AuthHandler) handleVerifyTwoFactor(c *gin.Context) {
	var req VerifyTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetUint("user_id")
	if err := h.twoFactor.VerifyTwoFactor(userID, req.Code); err != nil {
		h.logger.Printf("Failed to verify 2FA code: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA verification successful"})
}

// handleGenerateRecoveryCodes 处理生成新的恢复码
func (h *AuthHandler) handleGenerateRecoveryCodes(c *gin.Context) {
	var req VerifyTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID := c.GetUint("user_id")
	codes, err := h.twoFactor.GenerateRecoveryCodes(userID, req.Code)
	if err != nil {
		h.logger.Printf("Failed to generate recovery codes: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Recovery codes generated successfully",
		"codes": codes,
	})
}