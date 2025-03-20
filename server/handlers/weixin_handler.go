package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"kcaitech.com/kcauth/server/auth"
)

// WeixinLoginURL 获取微信登录URL
func (h *AuthHandler) WeixinLoginURL(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "微信登录未启用"})
		return
	}

	// 生成随机状态
	state := uuid.New().String()

	// 生成唯一的客户端标识
	clientID := c.ClientIP() + "-" + c.Request.UserAgent()
	stateKey := "weixin_oauth_state:" + clientID

	// 将state存储到Redis中，设置合理的过期时间（如15分钟）
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("保存OAuth状态到Redis失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部服务器错误"})
		return
	}

	// 设置cookie存储客户端标识，用于后续回调时获取对应的state
	c.SetCookie("weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", false, true)

	// 获取登录URL
	authURL := h.weixinLogin.GetAuthURL(state)

	// 返回URL
	c.JSON(http.StatusOK, gin.H{
		"url": authURL,
	})
}

// WeixinLoginHandler 处理微信登录
func (h *AuthHandler) WeixinLoginHandler(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "微信登录未启用"})
		return
	}

	// 生成随机状态
	state := uuid.New().String()

	// 生成唯一的客户端标识
	clientID := c.ClientIP() + "-" + c.Request.UserAgent()
	stateKey := "weixin_oauth_state:" + clientID

	// 将state存储到Redis中，设置合理的过期时间（如15分钟）
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("保存OAuth状态到Redis失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部服务器错误"})
		return
	}

	// 设置cookie存储客户端标识，用于后续回调时获取对应的state
	c.SetCookie("weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", false, true)

	// 重定向到微信登录页面
	c.Redirect(http.StatusTemporaryRedirect, h.weixinLogin.GetAuthURL(state))
}

// WeixinCallback 处理微信回调
func (h *AuthHandler) WeixinCallback(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "微信登录未启用"})
		return
	}

	// 验证state
	actualState := c.Query("state")
	if actualState == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的状态参数"})
		return
	}

	// 从cookie获取客户端标识
	clientID, err := c.Cookie("weixin_client_id")
	if err != nil {
		h.logger.Printf("获取weixin_client_id cookie失败: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求，请重新登录"})
		return
	}

	// 从Redis获取预期状态
	stateKey := "weixin_oauth_state:" + clientID
	var expectedState string
	if err := h.redisStore.Get(stateKey, &expectedState); err != nil {
		h.logger.Printf("从Redis获取OAuth状态失败: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "会话已过期，请重新登录"})
		return
	}

	// 验证状态值
	if expectedState != actualState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的状态参数"})
		return
	}

	// 清除Redis中的状态和cookie
	if err := h.redisStore.Delete(stateKey); err != nil {
		h.logger.Printf("清除Redis中的OAuth状态失败: %v", err)
		// 不中断流程，继续处理
	}
	c.SetCookie("weixin_client_id", "", -1, "/", "", false, true)

	// 处理回调
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供授权码"})
		return
	}

	// 使用微信登录服务直接处理登录或注册
	user, loginResp, err := h.weixinLogin.RegisterOrLoginWithWeixin(code)
	if err != nil {
		h.logger.Printf("微信登录处理失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "微信登录处理失败"})
		return
	}

	// 创建会话
	clientIP := c.ClientIP()
	session1, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session1.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	// 返回用户和会话信息，或重定向到前端应用
	if redirectURL := c.Query("redirect"); redirectURL != "" {
		// 重定向到前端，带上token参数
		redirectWithToken := redirectURL + "?token=" + tokenPair.AccessToken
		c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
		c.Redirect(http.StatusTemporaryRedirect, redirectWithToken)
		return
	}

	// 直接返回JSON响应
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"profile":     user.Profile,
		"expire_time": auth.TokenExpiration,
		"weixin":      loginResp, // 保留微信登录响应信息
	})
}

// WeixinLoginPost 微信登录POST请求
func (h *AuthHandler) WeixinLoginPost(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "微信登录未启用"})
		return
	}

	// 解析请求
	var req struct {
		Code  string `json:"code" binding:"required"`
		State string `json:"state"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 使用微信登录服务直接处理登录或注册
	user, loginResp, err := h.weixinLogin.RegisterOrLoginWithWeixin(req.Code)
	if err != nil {
		h.logger.Printf("微信登录处理失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "微信登录处理失败"})
		return
	}

	// 创建会话
	clientIP := c.ClientIP()
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration)
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
		"weixin":      loginResp, // 保留微信登录响应信息
	})
}

// WeixinLogin 微信登录
func (h *AuthHandler) WeixinLogin(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "微信登录未启用"})
		return
	}

	// 生成随机状态
	state := uuid.New().String()

	// 生成唯一的客户端标识
	clientID := c.ClientIP() + "-" + c.Request.UserAgent()
	stateKey := "weixin_oauth_state:" + clientID

	// 将state存储到Redis中，设置合理的过期时间（如15分钟）
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("保存OAuth状态到Redis失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部服务器错误"})
		return
	}

	// 设置cookie存储客户端标识，用于后续回调时获取对应的state
	c.SetCookie("weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", false, true)

	// 重定向到微信登录页面
	c.Redirect(http.StatusTemporaryRedirect, h.weixinLogin.GetAuthURL(state))
}
