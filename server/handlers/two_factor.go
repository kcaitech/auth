package handlers

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

// Enable2FA 启用双因素认证
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "双因素认证未启用"})
		return
	}

	userID := c.GetUint("user_id")
	key, err := h.twoFactor.GenerateSecret(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret": key.Secret(),
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

	userID := c.GetUint("user_id")
	if err := h.twoFactor.DisableTwoFactor(userID, req.Code); err != nil {
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
		UserID uint   `json:"user_id" binding:"required"`
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

	userID := c.GetUint("user_id")
	codes, err := h.twoFactor.GenerateRecoveryCodes(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
} 