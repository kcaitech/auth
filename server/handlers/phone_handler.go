package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// PhoneRegisterRequest 手机注册请求
type PhoneRegisterRequest struct {
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Nickname string `json:"nickname"`
}

// PhoneLoginRequest 手机密码登录请求
type PhoneLoginRequest struct {
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// PhoneCodeLoginRequest 手机验证码登录请求
type PhoneCodeLoginRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// SendVerificationCodeRequest 发送验证码请求
type SendVerificationCodeRequest struct {
	Phone string `json:"phone" binding:"required"`
}

// VerifyPhoneRequest 验证手机号请求
type VerifyPhoneRequest struct {
	Code string `json:"code" binding:"required"`
}

// PhoneResetPasswordRequest 手机重置密码请求
type PhoneResetPasswordRequest struct {
	Phone       string `json:"phone" binding:"required"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// PhoneHandler 手机认证处理器
type PhoneHandler struct {
	phoneAuth     *auth.PhoneAuth
	sessionMgr    *auth.SessionManager
	jwtService    *auth.JWTService
	verifyCodeTTL int
}

// NewPhoneHandler 创建手机认证处理器
func NewPhoneHandler(
	phoneAuth *auth.PhoneAuth,
	sessionMgr *auth.SessionManager,
	jwtService *auth.JWTService,
) *PhoneHandler {
	return &PhoneHandler{
		phoneAuth:     phoneAuth,
		sessionMgr:    sessionMgr,
		jwtService:    jwtService,
		verifyCodeTTL: 300, // 默认5分钟
	}
}

// RegisterRoutes 注册路由
func (h *PhoneHandler) RegisterRoutes(router *gin.RouterGroup) {
	phoneGroup := router.Group("/phone")
	{
		// 手机预注册 - 发送验证码
		phoneGroup.POST("/preregister", h.PhonePreregister)
		// 验证手机号并完成注册
		phoneGroup.POST("/verify-register", h.VerifyPhoneAndRegister)
		// 重新发送验证码
		phoneGroup.POST("/resend-verification", h.ResendPhoneVerification)
		// 使用手机号+密码登录
		phoneGroup.POST("/login", h.PhoneLogin)
		// 发送登录验证码
		phoneGroup.POST("/send-login-code", h.SendLoginSMS)
		// 使用手机号+验证码登录
		phoneGroup.POST("/code-login", h.PhoneCodeLogin)
		// 发起密码重置 - 发送验证码
		phoneGroup.POST("/reset-password/init", h.InitiatePasswordReset)
		// 完成密码重置
		phoneGroup.POST("/reset-password/complete", h.CompletePasswordReset)
	}
}

// Login 处理手机密码登录请求
func (h *PhoneHandler) Login(c *gin.Context) {
	var req PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 尝试登录
	user, err := h.phoneAuth.PhoneLogin(req.Phone, req.Password)
	if err != nil {
		// 根据错误类型返回相应的状态码和消息
		status := http.StatusUnauthorized
		message := "手机号或密码错误"

		if appErr, ok := err.(*auth.AppError); ok {
			if appErr.Code == auth.ErrCodeEmailNotVerified {
				message = "手机号未验证，请先验证手机号"
			}
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// 创建会话和JWT令牌
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	token, err := h.jwtService.GenerateJWT(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	// 登录成功，返回用户信息和令牌
	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   token,
		"user": gin.H{
			"user_id":  user.UserID,
			"nickname": user.Profile.Nickname,
			"avatar":   user.Profile.Avatar,
		},
	})
}

// PhoneCodeLogin 手机号+验证码登录
func (h *PhoneHandler) PhoneCodeLogin(c *gin.Context) {
	var req PhoneCodeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 尝试验证码登录
	user, err := h.phoneAuth.PhoneCodeLogin(req.Phone, req.Code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "手机号或验证码错误"})
		return
	}

	// 创建会话和JWT令牌
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	token, err := h.jwtService.GenerateJWT(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	// 登录成功，返回用户信息和令牌
	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   token,
		"user": gin.H{
			"user_id":  user.UserID,
			"nickname": user.Profile.Nickname,
			"avatar":   user.Profile.Avatar,
		},
	})
}

// SendVerificationCode 处理发送验证码请求
func (h *PhoneHandler) SendVerificationCode(c *gin.Context) {
	var req SendVerificationCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 验证手机号格式
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 发送验证码
	// 这里可以根据不同场景发送不同类型的验证码
	// 例如：登录验证码、注册验证码等
	code, err := h.phoneAuth.SendLoginSMS(req.Phone)
	if err != nil {
		// 如果用户不存在，返回特定的错误
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "该手机号未注册"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "发送验证码失败"})
		return
	}

	// 在开发环境中返回验证码，方便测试
	// 生产环境应该移除这个
	devInfo := gin.H{}
	if gin.Mode() == gin.DebugMode {
		devInfo["code"] = code
	}

	// 发送成功
	c.JSON(http.StatusOK, gin.H{
		"message":     "验证码已发送",
		"expires_in":  h.verifyCodeTTL,
		"development": devInfo,
	})
}

// VerifyPhone 处理验证手机号请求
func (h *PhoneHandler) VerifyPhone(c *gin.Context) {
	var req VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 验证手机号
	if err := h.phoneAuth.VerifyPhone(req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码无效或已过期"})
		return
	}

	// 验证成功
	c.JSON(http.StatusOK, gin.H{"message": "手机号验证成功"})
}

// InitiatePasswordReset 发起密码重置
func (h *PhoneHandler) InitiatePasswordReset(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 验证手机号格式
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 发起密码重置
	code, err := h.phoneAuth.InitiatePasswordReset(req.Phone)
	if err != nil {
		// 如果用户不存在，返回特定的错误
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "手机号不存在"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "发送重置验证码失败"})
		return
	}

	// 在开发环境中返回验证码，方便测试
	devInfo := gin.H{}
	if gin.Mode() == gin.DebugMode {
		devInfo["code"] = code
	}

	// 发送成功
	c.JSON(http.StatusOK, gin.H{
		"message":     "重置密码验证码已发送",
		"expires_in":  h.verifyCodeTTL,
		"development": devInfo,
	})
}

// ResetPassword 处理重置密码请求
func (h *PhoneHandler) ResetPassword(c *gin.Context) {
	var req PhoneResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 完成密码重置
	if err := h.phoneAuth.CompletePasswordReset(req.Code, req.Phone, req.NewPassword); err != nil {
		var status int
		var message string

		switch appErr := err.(type) {
		case *auth.AppError:
			switch appErr.Code {
			case auth.ErrCodeInvalidToken:
				status = http.StatusBadRequest
				message = "验证码无效或已过期"
			case auth.ErrCodeWeakPassword:
				status = http.StatusBadRequest
				message = "密码太弱，请使用更强的密码"
			default:
				status = http.StatusInternalServerError
				message = "重置密码失败，请稍后再试"
			}
		default:
			status = http.StatusInternalServerError
			message = "重置密码失败，请稍后再试"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// 重置成功
	c.JSON(http.StatusOK, gin.H{"message": "密码重置成功"})
}

// PhonePreregister 手机预注册 - 发送验证码
func (h *PhoneHandler) PhonePreregister(c *gin.Context) {
	var req struct {
		Phone    string `json:"phone" binding:"required"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 预注册手机用户，发送验证码
	code, err := h.phoneAuth.PhonePreregister(req.Phone, req.Password, req.Nickname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "验证码已发送，请查收并输入验证码完成注册",
		"phone":   req.Phone,
		"code":    code, // 在生产环境中应该移除这个字段，这里仅用于测试
	})
}

// ResendPhoneVerification 重新发送手机验证码
func (h *PhoneHandler) ResendPhoneVerification(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 重新发送验证码
	code, err := h.phoneAuth.ResendPhoneVerification(req.Phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "验证码已重新发送，请查收",
		"code":    code, // 在生产环境中应该移除这个字段，这里仅用于测试
	})
}

// VerifyPhoneAndRegister 验证手机号并完成注册
func (h *PhoneHandler) VerifyPhoneAndRegister(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
		Code  string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 验证手机号并完成注册
	user, err := h.phoneAuth.VerifyPhoneAndRegister(req.Phone, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 创建会话
	clientIP := c.ClientIP()
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"message":     "手机号验证成功，注册完成",
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}

// PhoneLogin 手机号+密码登录
func (h *PhoneHandler) PhoneLogin(c *gin.Context) {
	var req PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 尝试登录
	user, err := h.phoneAuth.PhoneLogin(req.Phone, req.Password)
	if err != nil {
		// 根据错误类型返回相应的状态码和消息
		status := http.StatusUnauthorized
		message := "手机号或密码错误"

		if appErr, ok := err.(*auth.AppError); ok {
			if appErr.Code == auth.ErrCodeEmailNotVerified {
				message = "手机号未验证，请先验证手机号"
			}
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// 创建会话和JWT令牌
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	token, err := h.jwtService.GenerateJWT(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	// 登录成功，返回用户信息和令牌
	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   token,
		"user": gin.H{
			"user_id":  user.UserID,
			"nickname": user.Profile.Nickname,
			"avatar":   user.Profile.Avatar,
		},
	})
}

// SendLoginSMS 发送登录验证码
func (h *PhoneHandler) SendLoginSMS(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 验证手机号格式
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 发送登录验证码
	code, err := h.phoneAuth.SendLoginSMS(req.Phone)
	if err != nil {
		// 如果用户不存在，返回特定的错误
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "该手机号未注册"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "发送登录验证码失败"})
		return
	}

	// 在开发环境中返回验证码，方便测试
	devInfo := gin.H{}
	if gin.Mode() == gin.DebugMode {
		devInfo["code"] = code
	}

	// 发送成功
	c.JSON(http.StatusOK, gin.H{
		"message":     "登录验证码已发送",
		"expires_in":  h.verifyCodeTTL,
		"development": devInfo,
	})
}

// CompletePasswordReset 完成密码重置
func (h *PhoneHandler) CompletePasswordReset(c *gin.Context) {
	var req PhoneResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 完成密码重置
	if err := h.phoneAuth.CompletePasswordReset(req.Code, req.Phone, req.NewPassword); err != nil {
		var status int
		var message string

		switch appErr := err.(type) {
		case *auth.AppError:
			switch appErr.Code {
			case auth.ErrCodeInvalidToken:
				status = http.StatusBadRequest
				message = "验证码无效或已过期"
			case auth.ErrCodeWeakPassword:
				status = http.StatusBadRequest
				message = "密码太弱，请使用更强的密码"
			default:
				status = http.StatusInternalServerError
				message = "重置密码失败，请稍后再试"
			}
		default:
			status = http.StatusInternalServerError
			message = "重置密码失败，请稍后再试"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// 重置成功
	c.JSON(http.StatusOK, gin.H{"message": "密码重置成功"})
}
