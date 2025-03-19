package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions" // todo 不对的。不一定回调回当前服务实例中。需要存到redis中。
	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

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

	// 创建新用户或查找已有用户
	user, err := h.handleGoogleUser(req.Token, req.Email, req.Name, "")
	if err != nil {
		h.logger.Printf("处理 Google 登录失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "处理登录失败"})
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
	})
}

// GoogleLogout 谷歌登出
// func (h *AuthHandler) GoogleLogout(c *gin.Context) {
// 	// 获取会话ID
// 	sessionID := c.GetHeader("Session-ID")
// 	if sessionID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供会话ID"})
// 		return
// 	}

// 	// 删除会话
// 	if err := h.sessionMgr.DeleteSession(sessionID); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
// }

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

	// 创建新用户或查找已有用户
	user, err := h.handleGoogleUser(googleUser.ID, googleUser.Email, googleUser.Name, googleUser.Picture)
	if err != nil {
		h.logger.Printf("查找或创建用户失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "处理用户信息失败"})
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
	})
}

// handleGoogleUser 处理谷歌用户，查找或创建用户
func (h *AuthHandler) handleGoogleUser(googleID, email, name, pictureURL string) (*auth.User, error) {
	if h.googleOAuth == nil {
		return nil, fmt.Errorf("Google OAuth 未启用")
	}

	// 创建一个GoogleUserInfo对象
	googleUserInfo := &auth.GoogleUserInfo{
		ID:            googleID,
		Email:         email,
		VerifiedEmail: true, // 假设邮箱已验证
		Name:          name,
		Picture:       pictureURL,
	}

	// 查找现有用户
	user, err := h.googleOAuth.GetUserByGoogleID(googleID)
	if err != nil {
		// 如果是非"用户不存在"错误，则直接返回
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			return nil, err
		}
	}

	// 如果用户不存在，则创建新用户
	if user == nil {
		user, err = h.googleOAuth.CreateUserFromGoogle(googleUserInfo)
		if err != nil {
			return nil, fmt.Errorf("创建Google用户失败: %w", err)
		}
	} else {
		// 更新用户信息
		if err := h.googleOAuth.UpdateGoogleUserInfo(user.UserID, googleUserInfo); err != nil {
			h.logger.Printf("更新Google用户信息失败: %v", err)
			// 不影响登录流程，只记录日志
		}
	}

	return user, nil
}
