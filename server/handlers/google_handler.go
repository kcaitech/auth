/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"kcaitech.com/kcauth/server/auth"
)

// handleGoogleUser Process Google user, find or create user
func (h *AuthHandler) handleGoogleUser(googleID, email, name, pictureURL string) (*auth.User, error) {
	if h.googleOAuth == nil {
		return nil, fmt.Errorf("google OAuth is not enabled")
	}

	// Create a GoogleUserInfo object
	googleUserInfo := &auth.GoogleUserInfo{
		ID:      googleID,
		Email:   email,
		Name:    name,
		Picture: pictureURL,
	}

	// Find existing user
	user, err := h.googleOAuth.GetUserByGoogleID(googleID, email)
	if err != nil {
		// If user not found, create new user
		if errors.Is(err, gorm.ErrRecordNotFound) {
			user, err = h.googleOAuth.CreateUserFromGoogle(googleUserInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to create Google user: %w", err)
			}
		} else {
			return nil, err
		}
	} else {
		// Update user information
		// if err := h.googleOAuth.UpdateGoogleUserInfo(user.UserID, googleUserInfo); err != nil {
		// 	h.logger.Printf("Failed to update Google user information: %v", err)
		// 	// Does not affect login flow, just log the error
		// }
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
	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
	}
	// 设置cookie
	c.SetCookie("refreshToken", tokenPair.RefreshToken, int(auth.RefreshTokenExpiration.Seconds()), "/", "", true, true)

	// 返回用户信息和token
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       tokenPair.AccessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
}

func (h *AuthHandler) GetGoogleClientID(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"client_id": h.googleOAuth.GetClientID()})
}
