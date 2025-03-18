package handlers

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"kcaitech.com/kcauth/server/auth"
)

// GoogleLogin 处理Google登录
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	if h.googleOAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google登录未启用"})
		return
	}

	state, err := h.googleOAuth.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成状态失败"})
		return
	}

	// 存储state到session
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	session.Save()

	// 重定向到Google登录页面
	c.Redirect(http.StatusTemporaryRedirect, h.googleOAuth.GetAuthURL(state))
}

// GoogleCallback 处理Google回调
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	if h.googleOAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google登录未启用"})
		return
	}

	// 验证state
	session := sessions.Default(c)
	expectedState := session.Get("oauth_state")
	actualState := c.Query("state")
	if expectedState == nil || expectedState.(string) != actualState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的状态参数"})
		return
	}

	// 清除session中的state
	session.Delete("oauth_state")
	session.Save()

	// 处理回调
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供授权码"})
		return
	}

	// 使用授权码获取用户信息
	googleUser, err := h.googleOAuth.HandleCallback(c.Request.Context(), code, actualState, expectedState.(string))
	if err != nil {
		h.logger.Printf("Google回调处理失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Google登录处理失败"})
		return
	}

	// 查找或创建用户
	user, err := h.accountAuth.FindOrCreateUserByOAuth(c.Request.Context(), "google", googleUser.ID,
		googleUser.Email, googleUser.Name, googleUser.Picture)
	if err != nil {
		h.logger.Printf("查找或创建用户失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "处理用户信息失败"})
		return
	}

	// 创建JWT令牌
	token, err := h.jwtService.GenerateToken(user.ID, user.Username, auth.RoleUser)
	if err != nil {
		h.logger.Printf("生成JWT令牌失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成登录凭证失败"})
		return
	}

	// 返回用户和令牌，或重定向到前端应用
	if c.Query("redirect") != "" {
		// 重定向到前端，带上token参数
		redirectURL := c.Query("redirect") + "?token=" + token
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	// 直接返回JSON响应
	c.JSON(http.StatusOK, gin.H{
		"user":  user,
		"token": token,
	})
}

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
	state := session.Get("weixin_oauth_state")
	if state != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的状态"})
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

	// TODO: 实现微信回调处理逻辑
}

// GoogleLoginPost 处理前端直接发送的 Google 令牌
func (h *AuthHandler) GoogleLoginPost(c *gin.Context) {
	if h.googleOAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Google登录未启用"})
		return
	}

	// 解析请求
	var req struct {
		Token string `json:"token" binding:"required"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 验证令牌 (这里简化处理，实际应该通过 Google API 验证令牌)
	// 在完整实现中，应该调用 Google TokenInfo API 验证令牌

	// 查找或创建用户
	user, err := h.accountAuth.FindOrCreateUserByOAuth(
		c.Request.Context(),
		"google",
		req.Token, // 将令牌作为 socialID 使用
		req.Email,
		req.Name,
		"", // 没有头像URL
	)
	if err != nil {
		h.logger.Printf("处理 Google 登录失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "处理登录失败"})
		return
	}

	// 创建 JWT 令牌
	token, err := h.jwtService.GenerateToken(user.ID, user.Username, auth.RoleUser)
	if err != nil {
		h.logger.Printf("生成 JWT 令牌失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成登录凭证失败"})
		return
	}

	// 返回用户和令牌
	c.JSON(http.StatusOK, gin.H{
		"user":  user,
		"token": token,
	})
}
