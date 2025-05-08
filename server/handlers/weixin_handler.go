package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"kcaitech.com/kcauth/server/auth"
)

// WeixinLoginURL Get WeChat login URL
func (h *AuthHandler) WeixinLoginURL(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Generate random state
	state := uuid.New().String()

	// Generate unique client identifier
	clientID := c.ClientIP() + "-" + c.Request.UserAgent()
	stateKey := "weixin_oauth_state:" + clientID

	// Store state in Redis with a reasonable expiration time (e.g., 15 minutes)
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Set cookie to store client identifier for subsequent callback
	c.SetCookie("weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", false, true)

	// Get login URL
	authURL := h.weixinLogin.GetAuthURL(state)

	// Return URL
	c.JSON(http.StatusOK, gin.H{
		"url": authURL,
	})
}

// WeixinLoginHandler Handle WeChat login
func (h *AuthHandler) WeixinLoginHandler(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Generate random state
	state := uuid.New().String()

	// Generate unique client identifier
	clientID := c.ClientIP() + "-" + c.Request.UserAgent()
	stateKey := "weixin_oauth_state:" + clientID

	// Store state in Redis with a reasonable expiration time (e.g., 15 minutes)
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Set cookie to store client identifier for subsequent callback
	c.SetCookie("weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", false, true)

	// Redirect to WeChat login page
	c.Redirect(http.StatusTemporaryRedirect, h.weixinLogin.GetAuthURL(state))
}

// WeixinCallback Handle WeChat callback
func (h *AuthHandler) WeixinCallback(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Verify state
	actualState := c.Query("state")
	if actualState == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Get client identifier from cookie
	clientID, err := c.Cookie("weixin_client_id")
	if err != nil {
		h.logger.Printf("Failed to get weixin_client_id cookie: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request, please login again"})
		return
	}

	// Get expected state from Redis
	stateKey := "weixin_oauth_state:" + clientID
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
	c.SetCookie("weixin_client_id", "", -1, "/", "", false, true)

	// Handle callback
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code not provided"})
		return
	}

	// Use WeChat login service to directly handle login or registration
	user, _, err := h.weixinLogin.RegisterOrLoginWithWeixin(code)
	if err != nil {
		h.logger.Printf("WeChat login processing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "WeChat login processing failed"})
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
	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
	}
	// Directly return JSON response
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
		// "weixin":      loginResp, // Keep WeChat login response information
	})
}
