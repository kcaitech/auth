package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// EmailLogin 邮箱登录
func (h *AuthHandler) EmailLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 检查登录尝试次数限制
	clientIP := c.ClientIP()
	if err := h.accountAuth.CheckLoginAttempts(req.Email, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// 使用邮箱登录
	user, err := h.emailAuth.EmailLogin(req.Email, req.Password)
	if err != nil {
		// 记录失败的登录尝试
		h.accountAuth.RecordLoginAttempt(req.Email, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// 记录成功的登录尝试
	h.accountAuth.RecordLoginAttempt(req.Email, clientIP, true)

	// 创建会话
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
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}

// EmailRegister 邮箱预注册
func (h *AuthHandler) EmailRegister(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 预注册邮箱用户，只发送验证邮件，不创建用户
	_, err := h.emailAuth.EmailPreregister(req.Email, req.Password, req.Nickname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "验证邮件已发送，请查收并点击验证链接完成注册",
		"email":   req.Email,
	})
}

// EmailVerify 邮箱验证并完成注册
func (h *AuthHandler) EmailVerify(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少验证令牌"})
		return
	}

	// 验证邮箱并完成注册
	user, err := h.emailAuth.VerifyEmail(token)
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
		"message":     "邮箱验证成功，注册完成",
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}

// ResendEmailVerification 重新发送邮箱验证邮件
func (h *AuthHandler) ResendEmailVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		// Password string `json:"password" binding:"required"`
		// Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	_, err := h.emailAuth.ResentEmailVerification(req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "验证邮件已重新发送，请查收"})
}

// EmailPasswordReset 邮箱密码重置
func (h *AuthHandler) EmailPasswordReset(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 发起密码重置
	_, err := h.emailAuth.InitiatePasswordReset(req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "密码重置邮件已发送，请查收",
	})
}

// CompleteEmailPasswordReset 完成邮箱密码重置
func (h *AuthHandler) CompleteEmailPasswordReset(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 完成密码重置
	if err := h.emailAuth.CompletePasswordReset(req.Token, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "密码重置成功"})
}
