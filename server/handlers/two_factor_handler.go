package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Enable2FA 启用双因素认证
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "双因素认证未启用"})
		return
	}

	// 从上下文中获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到用户ID"})
		return
	}

	// 将userID转换为字符串
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户ID格式错误"})
		return
	}

	// 获取用户信息用于账户名称
	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("获取用户信息失败: %v", err)})
		return
	}

	// 使用用户昵称或ID作为账户名
	accountName := user.Profile.Nickname
	if accountName == "" {
		accountName = userIDStr
	}

	// 生成双因素认证密钥
	key, err := h.twoFactor.GenerateSecret(userIDStr, accountName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":  key.Secret(),
		"qr_code": key.URL(),
	})
}

// Disable2FA 禁用双因素认证
func (h *AuthHandler) Disable2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "双因素认证未启用"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 从上下文中获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到用户ID"})
		return
	}

	// 将userID转换为字符串
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户ID格式错误"})
		return
	}

	if err := h.twoFactor.DisableTwoFactor(userIDStr, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "双因素认证已禁用"})
}

// Verify2FA 验证双因素认证码
func (h *AuthHandler) Verify2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "双因素认证未启用"})
		return
	}

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	if err := h.twoFactor.VerifyTwoFactor(req.UserID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "验证成功"})
}

// GenerateRecoveryCodes 生成恢复码
func (h *AuthHandler) GenerateRecoveryCodes(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "双因素认证未启用"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 从上下文中获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到用户ID"})
		return
	}

	// 将userID转换为字符串
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户ID格式错误"})
		return
	}

	codes, err := h.twoFactor.GenerateRecoveryCodes(userIDStr, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
}
