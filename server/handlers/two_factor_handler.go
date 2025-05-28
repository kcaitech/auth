/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Enable2FA Enable two-factor authentication
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Two-factor authentication is not enabled"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID not found"})
		return
	}

	// Convert userID to string
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID format error"})
		return
	}

	// Get user information for account name
	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get user information: %v", err)})
		return
	}

	// Use user nickname or ID as account name
	accountName := user.Nickname
	if accountName == "" {
		accountName = userIDStr
	}

	// Generate two-factor authentication key
	tfaData, err := h.twoFactor.GenerateSecret(userIDStr, accountName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get QR code URL
	qrCodeURL, err := h.twoFactor.GetQRCodeURL(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":  tfaData.TempSecret,
		"qr_code": qrCodeURL,
	})
}

// Disable2FA Disable two-factor authentication
func (h *AuthHandler) Disable2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Two-factor authentication is not enabled"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID not found"})
		return
	}

	// Convert userID to string
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID format error"})
		return
	}

	if err := h.twoFactor.DisableTwoFactor(userIDStr, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Two-factor authentication has been disabled"})
}

// Verify2FA Verify two-factor authentication code
func (h *AuthHandler) Verify2FA(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Two-factor authentication is not enabled"})
		return
	}

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	if err := h.twoFactor.VerifyTwoFactor(req.UserID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification successful"})
}

// GenerateRecoveryCodes Generate recovery codes
func (h *AuthHandler) GenerateRecoveryCodes(c *gin.Context) {
	if h.twoFactor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Two-factor authentication is not enabled"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID not found"})
		return
	}

	// Convert userID to string
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID format error"})
		return
	}

	codes, err := h.twoFactor.GenerateRecoveryCodes(userIDStr, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
}
