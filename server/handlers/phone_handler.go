/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
	"kcaitech.com/kcauth/server/config"
)

// PhoneRegisterRequest Phone registration request
type PhoneRegisterRequest struct {
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Nickname string `json:"nickname"`
}

// PhoneLoginRequest Phone password login request
type PhoneLoginRequest struct {
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// PhoneCodeLoginRequest Phone verification code login request
type PhoneCodeLoginRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// SendVerificationCodeRequest Send verification code request
type SendVerificationCodeRequest struct {
	Phone string `json:"phone" binding:"required"`
}

// VerifyPhoneRequest Verify phone number request
type VerifyPhoneRequest struct {
	Code string `json:"code" binding:"required"`
}

// PhoneResetPasswordRequest Phone reset password request
type PhoneResetPasswordRequest struct {
	Phone       string `json:"phone" binding:"required"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// PhoneHandler Phone authentication handler
type PhoneHandler struct {
	phoneAuth     *auth.PhoneAuth
	sessionMgr    *auth.SessionManager
	jwtService    *auth.JWTService
	verifyCodeTTL int
	config        *config.Config
	avatarService *auth.AvatarService
}

// NewPhoneHandler Create phone authentication handler
func NewPhoneHandler(
	phoneAuth *auth.PhoneAuth,
	sessionMgr *auth.SessionManager,
	jwtService *auth.JWTService,
	avatarService *auth.AvatarService,
	config *config.Config,
) *PhoneHandler {
	return &PhoneHandler{
		phoneAuth:     phoneAuth,
		sessionMgr:    sessionMgr,
		jwtService:    jwtService,
		verifyCodeTTL: 300, // Default 5 minutes
		config:        config,
	}
}

// RegisterRoutes Register routes
func (h *PhoneHandler) RegisterRoutes(router *gin.RouterGroup) {
	phoneGroup := router.Group("/phone")
	{
		// Phone pre-registration - send verification code
		phoneGroup.POST("/preregister", h.PhonePreregister)
		// Verify phone number and complete registration
		phoneGroup.POST("/verify-register", h.VerifyPhoneAndRegister)
		// Resend verification code
		phoneGroup.POST("/resend-verification", h.ResendPhoneVerification)
		// Login with phone number + password
		phoneGroup.POST("/login", h.PhoneLogin)
		// Send login verification code
		phoneGroup.POST("/send-login-code", h.SendLoginSMS)
		// Login with phone number + verification code
		phoneGroup.POST("/code-login", h.PhoneCodeLogin)
		// Initiate password reset - send verification code
		phoneGroup.POST("/reset-password/init", h.InitiatePasswordReset)
		// Complete password reset
		phoneGroup.POST("/reset-password/complete", h.CompletePasswordReset)
	}
}

// Login Handle phone password login request
func (h *PhoneHandler) Login(c *gin.Context) {
	var req PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Try to login
	user, err := h.phoneAuth.PhoneLogin(req.Phone, req.Password)
	if err != nil {
		// Return appropriate status code and message based on error type
		status := http.StatusUnauthorized
		message := "Invalid phone number or password"

		if appErr, ok := err.(*auth.AppError); ok {
			if appErr.Code == auth.ErrCodeEmailNotVerified {
				message = "Phone number not verified, please verify first"
			}
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// Create session and JWT token
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	token, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.SetCookie("refreshToken", token.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	// Login successful, return user information and token
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token.AccessToken,
		"user": gin.H{
			"user_id":  user.UserID,
			"nickname": user.Nickname,
			"avatar":   user.Avatar,
		},
	})
}

// PhoneCodeLogin Phone number + verification code login
func (h *PhoneHandler) PhoneCodeLogin(c *gin.Context) {
	var req PhoneCodeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Try verification code login
	user, err := h.phoneAuth.PhoneCodeLogin(req.Phone, req.Code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid phone number or verification code"})
		return
	}

	// Create session and JWT token
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	token, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.SetCookie("refreshToken", token.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	// Login successful, return user information and token
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token.AccessToken,
		"user": gin.H{
			"user_id":  user.UserID,
			"nickname": user.Nickname,
			"avatar":   user.Avatar,
		},
	})
}

// SendVerificationCode Handle send verification code request
func (h *PhoneHandler) SendVerificationCode(c *gin.Context) {
	var req SendVerificationCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send verification code
	// Different types of verification codes can be sent for different scenarios
	// For example: login verification code, registration verification code, etc.
	code, err := h.phoneAuth.SendLoginSMS(req.Phone)
	if err != nil {
		// Return specific error if user doesn't exist
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "This phone number is not registered"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification code"})
		return
	}

	// Return verification code in development environment for testing
	// Should be removed in production
	devInfo := gin.H{}
	if gin.Mode() == gin.DebugMode {
		devInfo["code"] = code
	}

	// Send successful
	c.JSON(http.StatusOK, gin.H{
		"message":     "Verification code has been sent",
		"expires_in":  h.verifyCodeTTL,
		"development": devInfo,
	})
}

// VerifyPhone Handle verify phone number request
func (h *PhoneHandler) VerifyPhone(c *gin.Context) {
	var req VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Verify phone number
	if err := h.phoneAuth.VerifyPhone(req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired verification code"})
		return
	}

	// Verification successful
	c.JSON(http.StatusOK, gin.H{"message": "Phone number verification successful"})
}

// InitiatePasswordReset Initiate password reset
func (h *PhoneHandler) InitiatePasswordReset(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Initiate password reset
	code, err := h.phoneAuth.InitiatePasswordReset(req.Phone)
	if err != nil {
		// Return specific error if user doesn't exist
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Phone number does not exist"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send reset verification code"})
		return
	}

	// Return verification code in development environment for testing
	devInfo := gin.H{}
	if gin.Mode() == gin.DebugMode {
		devInfo["code"] = code
	}

	// Send successful
	c.JSON(http.StatusOK, gin.H{
		"message":     "Password reset verification code has been sent",
		"expires_in":  h.verifyCodeTTL,
		"development": devInfo,
	})
}

// ResetPassword Handle reset password request
func (h *PhoneHandler) ResetPassword(c *gin.Context) {
	var req PhoneResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Complete password reset
	if err := h.phoneAuth.CompletePasswordReset(req.Code, req.Phone, req.NewPassword); err != nil {
		var status int
		var message string

		switch appErr := err.(type) {
		case *auth.AppError:
			switch appErr.Code {
			case auth.ErrCodeInvalidToken:
				status = http.StatusBadRequest
				message = "Invalid or expired verification code"
			case auth.ErrCodeWeakPassword:
				status = http.StatusBadRequest
				message = "Password too weak, please use a stronger password"
			default:
				status = http.StatusInternalServerError
				message = "Failed to reset password, please try again later"
			}
		default:
			status = http.StatusInternalServerError
			message = "Failed to reset password, please try again later"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// Reset successful
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

// PhonePreregister Phone pre-registration - send verification code
func (h *PhoneHandler) PhonePreregister(c *gin.Context) {
	var req struct {
		Phone    string `json:"phone" binding:"required"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Pre-register phone user, send verification code
	code, err := h.phoneAuth.PhonePreregister(req.Phone, req.Password, req.Nickname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification code has been sent, please check and enter the code to complete registration",
		"phone":   req.Phone,
		"code":    code, // In production, this field should be removed, it's only for testing
	})
}

// ResendPhoneVerification Resend phone verification code
func (h *PhoneHandler) ResendPhoneVerification(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Resend verification code
	code, err := h.phoneAuth.ResendPhoneVerification(req.Phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification code has been resent, please check",
		"code":    code, // In production, this field should be removed, it's only for testing
	})
}

// VerifyPhoneAndRegister Verify phone number and complete registration
func (h *PhoneHandler) VerifyPhoneAndRegister(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
		Code  string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Verify phone number and complete registration
	user, err := h.phoneAuth.VerifyPhoneAndRegister(req.Phone, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create session
	clientIP := c.ClientIP()
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
	}
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"message":     "Phone verification successful, registration complete",
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
}

// PhoneLogin Phone number + password login
func (h *PhoneHandler) PhoneLogin(c *gin.Context) {
	var req PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Try to login
	user, err := h.phoneAuth.PhoneLogin(req.Phone, req.Password)
	if err != nil {
		// Return appropriate status code and message based on error type
		status := http.StatusUnauthorized
		message := "Invalid phone number or password"

		if appErr, ok := err.(*auth.AppError); ok {
			if appErr.Code == auth.ErrCodeEmailNotVerified {
				message = "Phone number not verified, please verify first"
			}
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// Create session and JWT token
	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.GetHeader("User-Agent"), auth.TokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	token, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
	}
	c.SetCookie("refreshToken", token.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	// Login successful, return user information and token
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token.AccessToken,
		"user": gin.H{
			"user_id":  user.UserID,
			"nickname": user.Nickname,
			"avatar":   user.Avatar,
		},
	})
}

// SendLoginSMS Send login verification code
func (h *PhoneHandler) SendLoginSMS(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send login verification code
	code, err := h.phoneAuth.SendLoginSMS(req.Phone)
	if err != nil {
		// Return specific error if user doesn't exist
		if appErr, ok := err.(*auth.AppError); ok && appErr.Code == auth.ErrCodeUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "This phone number is not registered"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send login verification code"})
		return
	}

	// Return verification code in development environment for testing
	devInfo := gin.H{}
	if gin.Mode() == gin.DebugMode {
		devInfo["code"] = code
	}

	// Send successful
	c.JSON(http.StatusOK, gin.H{
		"message":     "Login verification code has been sent",
		"expires_in":  h.verifyCodeTTL,
		"development": devInfo,
	})
}

// CompletePasswordReset Complete password reset
func (h *PhoneHandler) CompletePasswordReset(c *gin.Context) {
	var req PhoneResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Complete password reset
	if err := h.phoneAuth.CompletePasswordReset(req.Code, req.Phone, req.NewPassword); err != nil {
		var status int
		var message string

		switch appErr := err.(type) {
		case *auth.AppError:
			switch appErr.Code {
			case auth.ErrCodeInvalidToken:
				status = http.StatusBadRequest
				message = "Invalid or expired verification code"
			case auth.ErrCodeWeakPassword:
				status = http.StatusBadRequest
				message = "Password too weak, please use a stronger password"
			default:
				status = http.StatusInternalServerError
				message = "Failed to reset password, please try again later"
			}
		default:
			status = http.StatusInternalServerError
			message = "Failed to reset password, please try again later"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}

	// Reset successful
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}
