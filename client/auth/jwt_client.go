package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWTClient JWT客户端
type JWTClient struct {
	AuthServerURL string           // 认证服务URL
	HTTPClient    *http.Client     // HTTP客户端
	Timeout       time.Duration    // 请求超时时间
	tokenCache    map[string]int64 // 令牌缓存，用于减少对认证服务的请求
	cacheMutex    sync.RWMutex     // 缓存锁
	cacheExpiry   time.Duration    // 缓存过期时间
}

// NewJWTClient 创建新的JWT客户端
func NewJWTClient(authServerURL string) *JWTClient {
	return &JWTClient{
		AuthServerURL: authServerURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Timeout:     10 * time.Second,
		tokenCache:  make(map[string]int64),
		cacheExpiry: 15 * time.Minute, // 默认缓存15分钟
	}
}

// tokenNotExpired 判断令牌是否过期
func tokenIsValid(accessToken string) bool {
	// 将jwt token 解码
	token, _ := jwt.ParseWithClaims(accessToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
		// 获取当前时间的NumericDate
		now := time.Now()
		// 检查令牌是否过期
		return claims.ExpiresAt.Time.Before(now)
	}

	return false
}

// ValidateToken 验证令牌
func (c *JWTClient) ValidateToken(accessToken string) (bool, error) {
	// 创建请求
	req, err := http.NewRequest("GET", c.AuthServerURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	// 令牌无效
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil
	}

	// 其他错误
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return false, fmt.Errorf("验证令牌失败: %d", resp.StatusCode)
	}
	return false, errors.New(errResp.Error)
}

// AuthRequired 验证JWT令牌的中间件
func (c *JWTClient) AuthRequired() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 从请求头获取令牌
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "未提供授权令牌"})
			ctx.Abort()
			return
		}

		// 检查令牌格式
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "授权格式无效"})
			ctx.Abort()
			return
		}

		tokenString := parts[1]

		// 检查令牌缓存
		if c.isTokenCached(tokenString) {
			// 令牌有效，继续处理请求
			ctx.Next()
			return
		}

		// 验证令牌
		valid, err := c.ValidateToken(tokenString)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "验证令牌失败: " + err.Error()})
			ctx.Abort()
			return
		}

		if !valid {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "无效的令牌"})
			ctx.Abort()
			return
		}

		// 缓存有效的令牌
		c.cacheToken(tokenString)

		// 继续处理请求
		ctx.Next()
	}
}

// OptionalAuth 可选的JWT验证中间件
func (c *JWTClient) OptionalAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			ctx.Next()
			return
		}

		tokenString := parts[1]

		// 检查令牌缓存
		if c.isTokenCached(tokenString) {
			ctx.Set("authenticated", true)
			ctx.Next()
			return
		}

		// 验证令牌
		valid, _ := c.ValidateToken(tokenString)
		if valid {
			// 缓存有效的令牌
			c.cacheToken(tokenString)
			// 设置认证标志
			ctx.Set("authenticated", true)
		}

		ctx.Next()
	}
}

// isTokenCached 检查令牌是否在缓存中
func (c *JWTClient) isTokenCached(token string) bool {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	expiry, exists := c.tokenCache[token]
	if !exists {
		return false
	}

	// 检查缓存是否过期
	if time.Now().Unix() > expiry || !tokenIsValid(token) {
		delete(c.tokenCache, token)
		return false
	}

	return true
}

// cacheToken 缓存令牌
func (c *JWTClient) cacheToken(token string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// 设置缓存过期时间
	expiry := time.Now().Add(c.cacheExpiry).Unix()
	c.tokenCache[token] = expiry
}
