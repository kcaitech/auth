package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"log"
	"net/http"
	"sort"
	"strings"
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
	user, loginResp, err := h.weixinLogin.RegisterOrLoginWithWeixin(code)
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

	// Directly return JSON response
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
		"weixin":      loginResp, // Keep WeChat login response information
	})
}

// WeixinLoginPost WeChat login POST request
func (h *AuthHandler) WeixinLoginPost(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Parse request
	var req struct {
		Code  string `json:"code" binding:"required"`
		State string `json:"state"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Use WeChat login service to directly handle login or registration
	user, loginResp, err := h.weixinLogin.RegisterOrLoginWithWeixin(req.Code)
	if err != nil {
		h.logger.Printf("WeChat login processing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "WeChat login processing failed"})
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
		"weixin":      loginResp, // Keep WeChat login response information
	})
}

// WeixinLogin WeChat login
func (h *AuthHandler) WeixinLogin(c *gin.Context) {
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

// 验证微信签名
func checkSignature(token, signature, timestamp, nonce string) bool {
	// 1. 将token、timestamp、nonce三个参数进行字典序排序
	strs := []string{token, timestamp, nonce}
	sort.Strings(strs)

	// 2. 将三个参数字符串拼接成一个字符串
	str := strings.Join(strs, "")

	// 3. 进行sha1加密
	h := sha1.New()
	h.Write([]byte(str))
	sha1Hash := hex.EncodeToString(h.Sum(nil))

	// 4. 开发者获得加密后的字符串可与signature对比
	return sha1Hash == signature
}

func (h *AuthHandler) WeixinDomainVerify(c *gin.Context) {
	signature := c.Query("signature")
	timestamp := c.Query("timestamp")
	nonce := c.Query("nonce")
	echostr := c.Query("echostr")

	// 替换为你在微信公众平台设置的Token
	token := h.weixinLogin.Config.DomainVerifyToken

	// 验证签名
	if checkSignature(token, signature, timestamp, nonce) {
		// 验证成功，返回echostr
		c.Writer.WriteHeader(http.StatusOK)
		c.Writer.Write([]byte(echostr))
		log.Println("微信验证成功")
	} else {
		// 验证失败
		c.Writer.WriteHeader(http.StatusForbidden)
		// c.Writer.Write([]byte("验证失败"))
		log.Println("微信验证失败")
	}
}
