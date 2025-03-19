package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

// AuthRequired 认证中间件
func AuthRequired(jwtService *auth.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			c.Abort()
			return
		}

		// 验证JWT令牌
		claims, err := jwtService.ValidateJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证令牌"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("user_id", claims.UserID)
		// c.Set("email", claims.Email)
		c.Next()
	}
}
