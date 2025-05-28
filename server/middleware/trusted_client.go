/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package middleware

import (
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/config"
)

// TrustedClient 可信第三方客户端中间件
func TrustedClient(_config *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 验证请求是否来自受信任的第三方
		clientID := c.GetHeader("X-Client-ID")
		clientSecret := c.GetHeader("X-Client-Secret")
		clientIP := c.ClientIP()

		// 验证客户端
		var trustedClient *config.TrustedClient
		for _, client := range _config.TrustedClients {
			// 使用 bcrypt 比较密钥
			err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret))
			if client.ClientID == clientID && err == nil {
				trustedClient = &client
				break
			}
		}

		if trustedClient == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权的客户端"})
			c.Abort()
			return
		}

		// 验证IP地址
		ipAllowed := false
		for _, allowedIP := range trustedClient.AllowedIPs {
			// 检查是否是通配符
			if allowedIP == "*" {
				ipAllowed = true
				break
			}

			// 检查是否是CIDR格式
			if strings.Contains(allowedIP, "/") {
				_, ipnet, err := net.ParseCIDR(allowedIP)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "无效的CIDR格式"})
					c.Abort()
					return
				}
				if ipnet.Contains(net.ParseIP(clientIP)) {
					ipAllowed = true
					break
				}
			} else {
				// 普通IP地址匹配
				if allowedIP == clientIP {
					ipAllowed = true
					break
				}
			}
		}

		if !ipAllowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "IP地址未授权"})
			c.Abort()
			return
		}

		// 由功能去验证
		// 验证权限范围
		// hasReadScope := false
		// for _, scope := range trustedClient.Scopes {
		// 	if scope == "read:users" {
		// 		hasReadScope = true
		// 		break
		// 	}
		// }
		// if !hasReadScope {
		// 	c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
		// 	c.Abort()
		// 	return
		// }

		// 将验证通过的客户端信息存储到上下文中
		c.Set("trusted_client", trustedClient)
		c.Next()
	}
}
