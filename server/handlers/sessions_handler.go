package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

func (h *AuthHandler) GetUserSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	sessions, err := h.sessionMgr.GetUserSessions(userID)
	if err != nil {
		h.logger.Printf("Failed to get user sessions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query sessions"})
		return
	}

	// Ensure sessions is not null
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID cannot be empty"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parameter validation
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID cannot be empty"})
		return
	}

	// Create session manager
	sessionManager := h.sessionMgr

	// Delete session from Redis
	if err := sessionManager.DeleteSession(userID, sessionID); err != nil {
		h.logger.Printf("Failed to terminate session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate session"})
		return
	}

	// Revoke JWT session
	if err := h.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
		h.logger.Printf("Failed to revoke JWT session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke JWT session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session successfully terminated"})
}

func (h *AuthHandler) TerminateAllUserSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	sessionManager := h.sessionMgr

	// Terminate all regular sessions
	deletedCount, err := sessionManager.DeleteUserSessions(userID)
	if err != nil {
		h.logger.Printf("Failed to terminate user sessions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate regular sessions"})
		return
	}

	// Revoke JWT sessions
	for _, sessionID := range deletedCount {
		if err := h.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
			h.logger.Printf("Failed to revoke JWT session: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke JWT session"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "All user sessions successfully terminated",
		"user_id":       userID,
		"deleted_count": len(deletedCount),
	})
}
