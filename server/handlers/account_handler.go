package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// 用户注册类型常量
type UserType string

const (
	UserTypeRegular UserType = "regular" // 普通账号
	UserTypeEmail   UserType = "email"   // 邮箱账号
)

// Register 普通账号密码注册
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		// Email    string `json:"email"`
		// Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 创建用户
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

	c.JSON(http.StatusOK, gin.H{"message": "注册成功"})
}

// Login 普通登录
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		UsernameOrEmail string `json:"username" binding:"required"` // 用户名或邮箱
		Password        string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 检查登录尝试次数限制
	clientIP := c.ClientIP()
	if err := h.accountAuth.CheckLoginAttempts(req.UsernameOrEmail, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	user, err := h.accountAuth.Login(req.UsernameOrEmail, req.Password)
	if err != nil {
		// 记录失败的登录尝试
		h.accountAuth.RecordLoginAttempt(req.UsernameOrEmail, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// 记录成功的登录尝试
	h.accountAuth.RecordLoginAttempt(req.UsernameOrEmail, clientIP, true)

	// 创建JWT令牌
	// token, err := h.jwtService.GenerateJWT(user.UserID, "", "")

	// 或者创建会话
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), time.Hour*24*7)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"session_id":  session.ID,
		"profile":     user.Profile,
		"expire_time": session.ExpiresAt,
	})
}

// Logout 登出处理
func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID := c.GetHeader("Session-ID")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供会话ID"})
		return
	}

	if err := h.sessionMgr.DeleteSession(sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
}

// RefreshSession 刷新会话
func (h *AuthHandler) RefreshSession(c *gin.Context) {
	sessionID := c.GetHeader("Session-ID")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供会话ID"})
		return
	}

	// 刷新会话，延长有效期为7天
	if err := h.sessionMgr.RefreshSession(sessionID, time.Hour*24*7); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "刷新会话失败"})
		return
	}

	// 获取刷新后的会话
	session, err := h.sessionMgr.GetSession(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id":  session.ID,
		"expire_time": session.ExpiresAt,
	})
}

// ResetPassword 重置密码
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 这里需要实现完成密码重置的逻辑
	// if h.emailAuth != nil {
	//     if err := h.emailAuth.CompletePasswordReset(req.Token, req.Password); err != nil {
	//         c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//         return
	//     }
	//     c.JSON(http.StatusOK, gin.H{"message": "密码重置成功"})
	//     return
	// }

	c.JSON(http.StatusNotImplemented, gin.H{"error": "密码重置功能尚未实现"})
}

// GetUserInfo 获取用户信息
func (h *AuthHandler) GetUserInfo(c *gin.Context) {
	// 从Session或者JWT中获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}

	// 将userID转换为字符串
	userIDStr := ""
	switch v := userID.(type) {
	case string:
		userIDStr = v
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case int:
		userIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无效的用户ID类型"})
		return
	}

	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// UpdateUserInfo 更新用户信息
func (h *AuthHandler) UpdateUserInfo(c *gin.Context) {
	var req struct {
		UserID   string           `json:"user_id"`
		Nickname string           `json:"nickname"`
		Profile  auth.UserProfile `json:"profile"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 从Session或者JWT中获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}

	// 将userID转换为字符串
	userIDStr := ""
	switch v := userID.(type) {
	case string:
		userIDStr = v
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case int:
		userIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无效的用户ID类型"})
		return
	}

	// 获取现有用户信息
	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 准备更新数据
	updates := make(map[string]interface{})

	// 更新用户信息
	if req.UserID != "" && req.UserID != user.UserID {
		updates["user_id"] = req.UserID
	}

	// 更新用户资料
	if req.Nickname != "" {
		if user.Profile.Nickname != req.Nickname {
			updates["profile.nickname"] = req.Nickname
		}
	}

	// 更新其他资料字段
	if req.Profile.Avatar != "" && user.Profile.Avatar != req.Profile.Avatar {
		updates["profile.avatar"] = req.Profile.Avatar
	}
	if req.Profile.Bio != "" && user.Profile.Bio != req.Profile.Bio {
		updates["profile.bio"] = req.Profile.Bio
	}
	if req.Profile.Location != "" && user.Profile.Location != req.Profile.Location {
		updates["profile.location"] = req.Profile.Location
	}
	if req.Profile.Website != "" && user.Profile.Website != req.Profile.Website {
		updates["profile.website"] = req.Profile.Website
	}
	if req.Profile.Birthday != "" && user.Profile.Birthday != req.Profile.Birthday {
		updates["profile.birthday"] = req.Profile.Birthday
	}
	if req.Profile.Gender != "" && user.Profile.Gender != req.Profile.Gender {
		updates["profile.gender"] = req.Profile.Gender
	}
	if req.Profile.Phone != "" && user.Profile.Phone != req.Profile.Phone {
		updates["profile.phone"] = req.Profile.Phone
	}

	// 如果有需要更新的字段
	if len(updates) > 0 {
		if err := h.accountAuth.UpdateProfile(userIDStr, updates); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "用户信息已更新"})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "没有需要更新的信息"})
	}
}

// AuthRequired 验证用户是否已登录
func (h *AuthHandler) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头中获取会话ID
		sessionID := c.GetHeader("Session-ID")
		if sessionID != "" {
			// 验证会话
			session, err := h.sessionMgr.GetSession(sessionID)
			if err == nil && session != nil {
				// 会话有效，设置用户ID并继续
				c.Set("user_id", session.UserID)
				c.Next()
				return
			}
		}

		// 没有有效会话，尝试验证JWT
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token := authHeader[7:]

			// 验证JWT
			claims, err := h.jwtService.ValidateJWT(token)
			if err == nil && claims != nil {
				// JWT有效，设置用户ID
				// 注意：claims.Subject 应包含用户ID
				c.Set("user_id", claims.Subject)
				c.Next()
				return
			}
		}

		// 未认证，拒绝访问
		c.JSON(http.StatusUnauthorized, gin.H{"error": "认证失败，请登录"})
		c.Abort()
	}
}

// RefreshToken JWT刷新令牌
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 刷新JWT令牌
	tokenPair, err := h.jwtService.RefreshJWT(req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
	})
}
