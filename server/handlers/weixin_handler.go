package handlers

import (
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	userAgent := c.Request.UserAgent()
	appSession, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, userAgent, time.Hour*24*7) // 7天过期
	if err != nil {
		h.logger.Printf("创建会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	// 返回用户和会话信息，或重定向到前端应用
	if redirectURL := c.Query("redirect"); redirectURL != "" {
		// 重定向到前端，带上会话ID参数
		redirectWithSession := redirectURL + "?session_id=" + appSession.ID
		c.Redirect(http.StatusTemporaryRedirect, redirectWithSession)
		return
	}

	// 直接返回JSON响应
	c.JSON(http.StatusOK, gin.H{
		"user":       user,
		"session_id": appSession.ID,
		"expires_at": appSession.ExpiresAt,
		"weixin":     loginResp, // 返回微信登录响应信息
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
	userAgent := c.Request.UserAgent()
	appSession, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, userAgent, time.Hour*24*7) // 7天过期
	if err != nil {
		h.logger.Printf("创建会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	// 返回用户和会话信息
	c.JSON(http.StatusOK, gin.H{
		"user":       user,
		"session_id": appSession.ID,
		"expires_at": appSession.ExpiresAt,
		"weixin":     loginResp, // 返回微信登录响应信息
	})
}

// WeixinLogout 微信登出
func (h *AuthHandler) WeixinLogout(c *gin.Context) {
	// 获取会话ID
	sessionID := c.GetHeader("Session-ID")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供会话ID"})
		return
	}

	// 删除会话
	if err := h.sessionMgr.DeleteSession(sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
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
