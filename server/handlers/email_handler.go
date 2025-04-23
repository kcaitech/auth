package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// EmailLogin Email login
func (h *AuthHandler) EmailLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Check login attempt limits
	clientIP := c.ClientIP()
	if err := h.accountAuth.CheckLoginAttempts(req.Email, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Use email to login
	user, err := h.emailAuth.EmailLogin(req.Email, req.Password)
	if err != nil {
		// Record failed login attempt
		h.accountAuth.RecordLoginAttempt(req.Email, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Record successful login attempt
	h.accountAuth.RecordLoginAttempt(req.Email, clientIP, true)

	// Create session
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

	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
}

// EmailRegister Email pre-registration
func (h *AuthHandler) EmailRegister(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
		Title    string `json:"title" binding:"required"`
		Content  string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Pre-register email user, only send verification email, don't create user
	_, err := h.emailAuth.EmailPreregister(req.Email, req.Password, req.Nickname, req.Title, req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification email has been sent, please check and click the verification link to complete registration",
		"email":   req.Email,
	})
}

// EmailVerify Email verification and complete registration
func (h *AuthHandler) EmailVerify(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing verification token"})
		return
	}
	log.Println("email verify token:", token)
	// Verify email and complete registration
	user, err := h.emailAuth.VerifyEmail(token)
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

	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"message":     "Email verification successful, registration complete",
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
}

// ResendEmailVerification Resend email verification
func (h *AuthHandler) ResendEmailVerification(c *gin.Context) {
	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Title   string `json:"title" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	_, err := h.emailAuth.ResentEmailVerification(req.Email, req.Title, req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email has been resent, please check"})
}

// EmailPasswordReset Email password reset
func (h *AuthHandler) EmailPasswordReset(c *gin.Context) {
	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Title   string `json:"title" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Initiate password reset
	_, err := h.emailAuth.InitiatePasswordReset(req.Email, req.Title, req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset email has been sent, please check",
	})
}

// CompleteEmailPasswordReset Complete email password reset
func (h *AuthHandler) CompleteEmailPasswordReset(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Complete password reset
	if err := h.emailAuth.CompletePasswordReset(req.Token, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}
