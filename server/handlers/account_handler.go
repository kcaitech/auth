package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// User registration type constants
type UserType string

const (
	UserTypeRegular UserType = "regular" // Regular account
	UserTypeEmail   UserType = "email"   // Email account
)

// Register Regular username/password registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		// Email    string `json:"email"`
		// Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Create user
	user := &auth.User{
		UserID:   req.Username,
		Password: req.Password,
		Status:   auth.UserStatusActive,
		// Profile:  auth.UserProfile{
		// Nickname: req.Nickname,
		// },
	}

	if err := h.accountAuth.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Directly return login information
	// Check login attempt limits
	clientIP := c.ClientIP()
	// if err := h.accountAuth.CheckLoginAttempts(req.Username, clientIP); err != nil {
	// 	c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	// 	return
	// }

	// user, err := h.accountAuth.Login(req.Username, req.Password)
	// if err != nil {
	// 	// Record failed login attempt
	// 	h.accountAuth.RecordLoginAttempt(req.Username, clientIP, false)
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	// 	return
	// }

	// Record successful login attempt
	// h.accountAuth.RecordLoginAttempt(req.Username, clientIP, true)

	// Create JWT token
	// token, err := h.jwtService.GenerateJWT(user.UserID, "", "")

	// Or create session
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
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}

// Login Regular login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"` // Username or email
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Check login attempt limits
	clientIP := c.ClientIP()
	if err := h.accountAuth.CheckLoginAttempts(req.Username, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	user, err := h.accountAuth.Login(req.Username, req.Password)
	if err != nil {
		// Record failed login attempt
		h.accountAuth.RecordLoginAttempt(req.Username, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Record successful login attempt
	h.accountAuth.RecordLoginAttempt(req.Username, clientIP, true)

	// Create JWT token
	// token, err := h.jwtService.GenerateJWT(user.UserID, "", "")

	// Or create session
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

// Logout Logout handling
func (h *AuthHandler) Logout(c *gin.Context) {

	// Get session ID
	sessionID, ok := c.Get("session_id")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID not found"})
		return
	}

	// Get user information from context
	userID, ok := c.Get("user_id")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID not found"})
		return
	}

	// Revoke refresh token
	if err := h.jwtService.RevokeJWTByID(userID.(string), sessionID.(string)); err != nil {
		h.logger.Printf("Failed to revoke refresh token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke refresh token"})
		return
	}

	// Clear client cookie
	c.SetCookie("refreshToken", "", -1, "/", "", true, true)

	// Delete session
	if err := h.sessionMgr.DeleteSession(userID.(string), sessionID.(string)); err != nil {
		// Even if session deletion fails, continue trying to revoke token
		h.logger.Printf("Failed to delete session: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// RefreshSession Refresh session
// func (h *AuthHandler) RefreshSession(c *gin.Context) {
// 	sessionID := c.GetHeader("Session-ID")
// 	if sessionID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID not provided"})
// 		return
// 	}

// 	// Refresh session, extend validity to 7 days
// 	if err := h.sessionMgr.RefreshSession(sessionID, auth.RefreshTokenExpiration); err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to refresh session"})
// 		return
// 	}

// 	// Get refreshed session
// 	session, err := h.sessionMgr.GetSession(sessionID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get session"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"session_id":  session.ID,
// 		"expire_time": session.ExpiresAt,
// 	})
// }

// ResetPassword Reset password
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6,max=32"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	if err := h.accountAuth.ChangePassword(userID.(string), req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})

}

// GetUserInfo Get user information
func (h *AuthHandler) GetUserInfo(c *gin.Context) {
	// Get user ID from Session or JWT
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	// Convert userID to string
	userIDStr := ""
	switch v := userID.(type) {
	case string:
		userIDStr = v
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case int:
		userIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
		return
	}

	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// UpdateUserInfo Update user information
func (h *AuthHandler) UpdateUserInfo(c *gin.Context) {
	var req struct {
		UserID   string           `json:"user_id"`
		Nickname string           `json:"nickname"`
		Profile  auth.UserProfile `json:"profile"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Get user ID from Session or JWT
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	// Convert userID to string
	userIDStr := ""
	switch v := userID.(type) {
	case string:
		userIDStr = v
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case int:
		userIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
		return
	}

	// Get existing user information
	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Prepare update data
	updates := make(map[string]interface{})

	// Update user information
	if req.UserID != "" && req.UserID != user.UserID {
		updates["user_id"] = req.UserID
	}

	// Update user profile
	if req.Nickname != "" {
		if user.Profile.Nickname != req.Nickname {
			updates["profile.nickname"] = req.Nickname
		}
	}

	// Update other profile fields
	if req.Profile.Avatar != "" && user.Profile.Avatar != req.Profile.Avatar {
		updates["profile.avatar"] = req.Profile.Avatar
	}
	// if req.Profile.Bio != "" && user.Profile.Bio != req.Profile.Bio {
	// 	updates["profile.bio"] = req.Profile.Bio
	// }
	if req.Profile.Location != "" && user.Profile.Location != req.Profile.Location {
		updates["profile.location"] = req.Profile.Location
	}
	// if req.Profile.Website != "" && user.Profile.Website != req.Profile.Website {
	// 	updates["profile.website"] = req.Profile.Website
	// }
	if req.Profile.Birthday != "" && user.Profile.Birthday != req.Profile.Birthday {
		updates["profile.birthday"] = req.Profile.Birthday
	}
	if req.Profile.Gender != "" && user.Profile.Gender != req.Profile.Gender {
		updates["profile.gender"] = req.Profile.Gender
	}
	// if req.Profile.Phone != "" && user.Profile.Phone != req.Profile.Phone {
	// 	updates["profile.phone"] = req.Profile.Phone
	// }

	// If there are fields to update
	if len(updates) > 0 {
		if err := h.accountAuth.UpdateProfile(userIDStr, updates); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User information updated"})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "No information to update"})
	}
}

// ValidateToken Validate JWT token
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not provided"})
		return
	}

	var err error
	if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token := authHeader[7:]
		var claims *auth.CustomClaims
		// Validate JWT
		claims, err = h.jwtService.ValidateJWT(token)
		if err == nil && claims != nil {
			c.JSON(http.StatusOK, gin.H{"user_id": claims.UserID})
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
}

// AuthRequired Verify if user is logged in
func (h *AuthHandler) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from request header
		// sessionID := c.GetHeader("Session-ID")
		// if sessionID != "" {
		// 	// Validate session
		// 	session, err := h.sessionMgr.GetSession(sessionID)
		// 	if err == nil && session != nil {
		// 		// Session valid, set user ID and continue
		// 		c.Set("user_id", session.UserID)
		// 		c.Next()
		// 		return
		// 	}
		// }

		var err error
		// No valid session, try to validate JWT
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token := authHeader[7:]
			var claims *auth.CustomClaims
			// Validate JWT
			claims, err = h.jwtService.ValidateJWT(token)
			if err == nil && claims != nil {
				// JWT valid, set user ID
				// Note: claims.Subject should contain user ID
				c.Set("user_id", claims.UserID)
				c.Set("session_id", claims.SessionID)
				c.Next()
				return
			} else {
				// JWT invalid, deny access
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
				return
			}
		} else {
			// Not authenticated, deny access
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no Authorization header"})
			c.Abort()
			return
		}

		// Not authenticated, deny access
		// c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed, please log in"})
		// c.Abort()
	}
}

// RefreshToken JWT refresh token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Get refreshtoken from Cookie
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token not provided"})
		return
	}

	// var req struct {
	// 	Token string `json:"token" binding:"required"`
	// }

	// if err := c.ShouldBindJSON(&req); err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
	// 	return
	// }

	claims, err := h.jwtService.ValidateJWT(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
		return
	}

	// Refresh session
	if err := h.sessionMgr.RefreshSession(claims.UserID, claims.SessionID, auth.RefreshTokenExpiration); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh session"})
		return
	}
	// Refresh JWT token
	tokenPair, err := h.jwtService.RefreshJWT(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Automatically update refreshToken
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		// "user_id":     user.UserID,
		"token": tokenPair.AccessToken,
		// "profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}
