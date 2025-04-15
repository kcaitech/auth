package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// GoogleLoginPost Handle Google token sent directly from frontend
func (h *AuthHandler) GoogleLoginPost(c *gin.Context) {
	if h.googleOAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google login is not enabled"})
		return
	}

	// Parse request
	var req struct {
		Token string `json:"token" binding:"required"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Verify token (simplified handling here, should actually verify through Google API)
	// In a complete implementation, should call Google TokenInfo API to verify the token

	// Create new user or find existing user
	user, err := h.handleGoogleUser(req.Token, req.Email, req.Name, "")
	if err != nil {
		h.logger.Printf("Failed to process Google login: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process login"})
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
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}

// GoogleLogout Google logout
// func (h *AuthHandler) GoogleLogout(c *gin.Context) {
// 	// Get session ID
// 	sessionID := c.GetHeader("Session-ID")
// 	if sessionID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID not provided"})
// 		return
// 	}

// 	// Delete session
// 	if err := h.sessionMgr.DeleteSession(sessionID); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
// }

// GoogleLogin Handle Google login
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	if h.googleOAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google login is not enabled"})
		return
	}

	state, err := h.googleOAuth.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// Generate unique client identifier
	clientID := c.ClientIP() + "-" + c.Request.UserAgent()
	stateKey := "google_oauth_state:" + clientID

	// Store state in Redis with a reasonable expiration time (e.g., 15 minutes)
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Set cookie to store client identifier for subsequent callback
	c.SetCookie("google_client_id", clientID, int(time.Minute*15/time.Second), "/", "", false, true)

	// Redirect to Google login page
	c.Redirect(http.StatusTemporaryRedirect, h.googleOAuth.GetAuthURL(state))
}

// GoogleCallback Handle Google callback
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	if h.googleOAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google login is not enabled"})
		return
	}

	// Verify state
	actualState := c.Query("state")
	if actualState == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Get client identifier from cookie
	clientID, err := c.Cookie("google_client_id")
	if err != nil {
		h.logger.Printf("Failed to get client_id cookie: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request, please login again"})
		return
	}

	// Get expected state from Redis
	stateKey := "google_oauth_state:" + clientID
	var expectedState string
	if err := h.redisStore.Get(stateKey, &expectedState); err != nil {
		h.logger.Printf("Failed to get OAuth state from Redis: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session expired, please login again"})
		return
	}

	// Verify state value
	if expectedState != actualState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Clear state from Redis and cookie
	if err := h.redisStore.Delete(stateKey); err != nil {
		h.logger.Printf("Failed to clear OAuth state from Redis: %v", err)
		// Don't interrupt the flow, continue processing
	}
	c.SetCookie("google_client_id", "", -1, "/", "", false, true)

	// Handle callback
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code not provided"})
		return
	}

	// Use authorization code to get user information
	googleUser, err := h.googleOAuth.HandleCallback(c.Request.Context(), code, actualState, expectedState)
	if err != nil {
		h.logger.Printf("Google callback processing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Google login processing failed"})
		return
	}

	// Create new user or find existing user
	user, err := h.handleGoogleUser(googleUser.ID, googleUser.Email, googleUser.Name, googleUser.Picture)
	if err != nil {
		h.logger.Printf("Failed to find or create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user information"})
		return
	}

	// Create session
	clientIP := c.ClientIP()
	session1, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session1.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Return user and session information, or redirect to frontend application
	if redirectURL := c.Query("redirect"); redirectURL != "" {
		// Redirect to frontend with token parameter
		redirectWithToken := redirectURL + "?token=" + tokenPair.AccessToken
		c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
		c.Redirect(http.StatusTemporaryRedirect, redirectWithToken)
		return
	}

	// Directly return JSON response
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}

// handleGoogleUser Process Google user, find or create user
func (h *AuthHandler) handleGoogleUser(googleID, email, name, pictureURL string) (*auth.User, error) {
	if h.googleOAuth == nil {
		return nil, fmt.Errorf("google OAuth is not enabled")
	}

	// Create a GoogleUserInfo object
	googleUserInfo := &auth.GoogleUserInfo{
		ID:    googleID,
		Email: email,
		// VerifiedEmail: true, // Assume email is verified
		Name:    name,
		Picture: pictureURL,
	}

	// Find existing user
	user, err := h.googleOAuth.GetUserByGoogleID(googleID, email)
	if err != nil {
		// If the error is not "user not found", return directly
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			return nil, err
		}
	}

	// If user does not exist, create new user
	if user == nil {
		user, err = h.googleOAuth.CreateUserFromGoogle(googleUserInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to create Google user: %w", err)
		}
	} else {
		// Update user information
		if err := h.googleOAuth.UpdateGoogleUserInfo(user.UserID, googleUserInfo); err != nil {
			h.logger.Printf("Failed to update Google user information: %v", err)
			// Does not affect login flow, just log the error
		}
	}

	return user, nil
}

func (h *AuthHandler) GoogleCredential(c *gin.Context) {
	// 解析请求体
	var req struct {
		Credential string `json:"credential" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// 验证 Google ID token
	// 使用 Google 的 TokenInfo API 验证 token
	resp, err := http.Get(fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", req.Credential))
	if err != nil {
		h.logger.Printf("Failed to verify Google token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify Google token"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.logger.Printf("Invalid Google token status: %d", resp.StatusCode)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Google token"})
		return
	}

	var tokenInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Audience      string `json:"aud"`
		ExpiresAt     string `json:"exp"`
		IssuedAt      string `json:"iat"`
		Issuer        string `json:"iss"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		h.logger.Printf("Failed to decode token info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode token info"})
		return
	}

	// 验证 token 的受众（audience）是否匹配
	if tokenInfo.Audience != h.googleOAuth.GetClientID() {
		h.logger.Printf("Token audience mismatch: %s != %s", tokenInfo.Audience, h.googleOAuth.GetClientID())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token audience"})
		return
	}

	// 验证 token 的颁发者（issuer）是否匹配
	if tokenInfo.Issuer != "https://accounts.google.com" && tokenInfo.Issuer != "accounts.google.com" {
		h.logger.Printf("Invalid token issuer: %s", tokenInfo.Issuer)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token issuer"})
		return
	}

	// 验证 token 是否过期
	exp, err := strconv.ParseInt(tokenInfo.ExpiresAt, 10, 64)
	if err != nil {
		h.logger.Printf("Invalid token expiration time: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token expiration time"})
		return
	}

	if time.Now().Unix() > exp {
		h.logger.Printf("Token expired")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
		return
	}

	// 创建 Google 用户信息
	googleUser := &auth.GoogleUserInfo{
		ID:      tokenInfo.Sub,
		Email:   tokenInfo.Email,
		Name:    tokenInfo.Name,
		Picture: tokenInfo.Picture,
	}

	// 创建或查找用户
	user, err := h.handleGoogleUser(googleUser.ID, googleUser.Email, googleUser.Name, googleUser.Picture)
	if err != nil {
		h.logger.Printf("Failed to process Google user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user information"})
		return
	}

	// 创建会话
	clientIP := c.ClientIP()
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// 生成token对
	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// 设置cookie
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)

	// 返回用户信息和token
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
	})
}
