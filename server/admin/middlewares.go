package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Logger middleware
func (s *AdminServer) loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		s.logger.Printf("[ADMIN] %s | %3d | %13v | %15s | %s",
			method, statusCode, latency, clientIP, path)
	}
}

// CORS middleware
func (s *AdminServer) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			// Use actual Origin from request instead of wildcard
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			// Allow requests with credentials
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// IP restriction middleware
func (s *AdminServer) ipRestrictionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(s.config.AllowedIPs) > 0 {
			clientIP := c.ClientIP()
			allowed := false

			for _, ip := range s.config.AllowedIPs {
				// 检查是否是通配符
				if ip == "*" {
					allowed = true
					break
				}

				// 检查是否是CIDR格式
				if strings.Contains(ip, "/") {
					_, ipnet, err := net.ParseCIDR(ip)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "无效的CIDR格式"})
						c.Abort()
						return
					}
					if ipnet.Contains(net.ParseIP(clientIP)) {
						allowed = true
						break
					}
				} else {
					// 普通IP地址匹配
					if ip == clientIP {
						allowed = true
						break
					}
				}
			}

			if !allowed {
				s.logger.Printf("Access request from %s denied", clientIP)
				c.JSON(http.StatusForbidden, gin.H{"error": "IP address not in allowed list"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// Authentication middleware
func (s *AdminServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		// Check if user information exists in session
		username := session.Get(sessionUserKey)
		if username == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			c.Abort()
			return
		}

		// Get role information
		rolesJSON := session.Get(sessionRoleKey)
		if rolesJSON == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session is corrupted"})
			c.Abort()
			return
		}

		var roles []string
		if err := json.Unmarshal([]byte(rolesJSON.(string)), &roles); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse session"})
			c.Abort()
			return
		}

		// Set user information and roles to context
		c.Set("username", username)
		c.Set("roles", roles)

		c.Next()
	}
}
