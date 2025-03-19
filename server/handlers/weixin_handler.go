package handlers

import (
	"net/http"

	"github.com/gin-contrib/sessions" // todo 不对的。不一定回调回当前服务实例中。需要存到redis中。
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

	// 存储state到session
	session := sessions.Default(c)
	session.Set("weixin_oauth_state", state)
	session.Save()

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

	// 存储state到session
	session := sessions.Default(c)
	session.Set("weixin_oauth_state", state)
	session.Save()

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
	session := sessions.Default(c)
	expectedState := session.Get("weixin_oauth_state")
	actualState := c.Query("state")
	if expectedState == nil || expectedState.(string) != actualState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的状态参数"})
		return
	}

	// 清除session中的state
	session.Delete("weixin_oauth_state")
	session.Save()

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

	// 存储state到session
	session := sessions.Default(c)
	session.Set("weixin_oauth_state", state)
	session.Save()

	// 重定向到微信登录页面
	c.Redirect(http.StatusTemporaryRedirect, h.weixinLogin.GetAuthURL(state))
}
