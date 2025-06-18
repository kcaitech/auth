/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// WeixinMiniLogin 处理微信小程序登录
func (h *AuthHandler) WeixinMiniLogin(c *gin.Context) {
	if h.weixinMiniLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat mini program login is not enabled"})
		return
	}

	// 获取前端传来的 code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code parameter"})
		return
	}

	// 调用微信小程序登录服务
	user, _, err := h.weixinMiniLogin.MiniProgramLogin(code)
	if err != nil {
		h.logger.Printf("WeChat mini program login failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "WeChat mini program login failed"})
		return
	}

	// 创建会话
	clientIP := c.ClientIP()
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.RefreshTokenExpiration+time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// 生成 token 对
	tokenPair, err := h.jwtService.GenerateTokenPair(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// 转换头像 URL
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
	}

	// 设置 cookie
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)

	// 返回用户信息和 token
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
}

// WeixinMiniUpdateProfile 更新小程序用户的个人信息
func (h *AuthHandler) WeixinMiniUpdateProfile(c *gin.Context) {
	if h.weixinMiniLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat mini program login is not enabled"})
		return
	}

	// 从token中获取用户ID（需要中间件验证）
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		return
	}

	// 解析请求参数
	var req struct {
		Nickname  string `json:"nickname"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 验证至少提供一个要更新的字段
	if req.Nickname == "" && req.AvatarURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one field (nickname or avatar_url) must be provided"})
		return
	}

	// 更新用户信息
	err := h.weixinMiniLogin.UpdateUserProfile(userIDStr, req.Nickname, req.AvatarURL)
	if err != nil {
		h.logger.Printf("Failed to update user profile for user %s: %v", userIDStr, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
	})
}
