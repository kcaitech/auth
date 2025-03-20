package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

func (h *AuthHandler) GetUserSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	sessions, err := h.sessionMgr.GetUserSessions(userID)
	if err != nil {
		h.logger.Printf("获取用户会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询会话失败"})
		return
	}

	// 确保sessions不是null
	if sessions == nil {
		sessions = []*auth.Session{}
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
	})
}

func (h *AuthHandler) TerminateUserSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "会话ID不能为空"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	// 参数验证
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "会话ID不能为空"})
		return
	}

	// 创建会话管理器
	sessionManager := h.sessionMgr

	// 从Redis中删除会话
	if err := sessionManager.DeleteSession(userID, sessionID); err != nil {
		h.logger.Printf("终止会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "终止会话失败"})
		return
	}

	// 撤销JWT会话
	if err := h.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
		h.logger.Printf("撤销JWT会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销JWT会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "会话已成功终止"})
}

func (h *AuthHandler) TerminateAllUserSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	sessionManager := h.sessionMgr

	// 终止所有普通会话
	deletedCount, err := sessionManager.DeleteUserSessions(userID)
	if err != nil {
		h.logger.Printf("终止用户会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "终止普通会话失败"})
		return
	}

	// 撤销JWT会话
	for _, sessionID := range deletedCount {
		if err := h.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
			h.logger.Printf("撤销JWT会话失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销JWT会话失败"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "用户所有会话已成功终止",
		"user_id":       userID,
		"deleted_count": len(deletedCount),
	})
}
