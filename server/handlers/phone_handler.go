package handlers

import (
	"net/http"

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
func (h *PhoneHandler) RegisterRoutes(rg *gin.RouterGroup) {
	phone := rg.Group("/phone")
	{
		phone.POST("/register", h.Register)                         // 手机号注册
		phone.POST("/login", h.Login)                               // 密码登录
		phone.POST("/code-login", h.CodeLogin)                      // 验证码登录
		phone.POST("/send-code", h.SendVerificationCode)            // 发送验证码
		phone.POST("/verify", h.VerifyPhone)                        // 验证手机号
		phone.POST("/reset-password-init", h.InitiatePasswordReset) // 发起密码重置
		phone.POST("/reset-password", h.ResetPassword)              // 重置密码
	}
}

// Register 处理手机注册请求
func (h *PhoneHandler) Register(c *gin.Context) {
	var req PhoneRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 验证手机号格式
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 注册用户
	user, err := h.phoneAuth.RegisterPhoneUser(req.Phone, req.Password, req.Nickname)
	if err != nil {
		// 根据错误类型返回相应的状态码和消息
		var status int
		var message string

		switch err.(type) {
		case *auth.AppError:
			appErr := err.(*auth.AppError)
			switch appErr.Code {
			case auth.ErrCodePhoneTaken:
				status = http.StatusConflict
				message = "该手机号已被注册"
			case auth.ErrCodeWeakPassword:
				status = http.StatusBadRequest
				message = "密码太弱，请使用更强的密码"
			case auth.ErrCodeInvalidPhoneFormat:
				status = http.StatusBadRequest
				message = "无效的手机号格式"
			default:
				status = http.StatusInternalServerError
				message = "注册失败，请稍后再试"
			}
		default:
			status = http.StatusInternalServerError
			message = "注册失败，请稍后再试"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// 注册成功，返回用户信息（不包含敏感字段）
	c.JSON(http.StatusCreated, gin.H{
		"message": "注册成功，请验证手机号",
		"user_id": user.UserID,
	})
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
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration)
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

// CodeLogin 处理手机验证码登录请求
func (h *PhoneHandler) CodeLogin(c *gin.Context) {
	var req PhoneCodeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式无效"})
		return
	}

	// 尝试验证码登录
	user, err := h.phoneAuth.PhoneCodeLogin(req.Phone, req.Code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "验证码无效或已过期"})
		return
	}

	// 创建会话和JWT令牌
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration)
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

// InitiatePasswordReset 处理发起密码重置请求
func (h *PhoneHandler) InitiatePasswordReset(c *gin.Context) {
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

	// 发起密码重置
	code, err := h.phoneAuth.InitiatePasswordReset(req.Phone)
	if err != nil {
		// 如果用户不存在，返回特定的错误
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "该手机号未注册"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "发起密码重置失败"})
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

		switch err.(type) {
		case *auth.AppError:
			appErr := err.(*auth.AppError)
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
