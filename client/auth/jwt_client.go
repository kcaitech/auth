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

// 需要与服务端定义的 Claims 结构一致
// Define JWT Claims structure
type CustomClaims struct {
	UserID string `json:"user_id"`
	// Email     string `json:"email"`
	SessionID string `json:"session_id"`
	// KeyID     string `json:"kid"`        // For key rotation
	// TokenType string `json:"token_type"` // Identifies whether it's an access token or refresh token
	jwt.RegisteredClaims
}

type UserProfile struct {
	Nickname string `json:"nickname" gorm:"size:50"`  // Nickname
	Avatar   string `json:"avatar" gorm:"size:255"`   // Avatar URL
	Location string `json:"location" gorm:"size:100"` // Location
	Birthday string `json:"birthday" gorm:"size:10"`  // Birthday
	Gender   string `json:"gender" gorm:"size:10"`    // Gender
	Language string `json:"language" gorm:"size:20"`  // Preferred Language
	Timezone string `json:"timezone" gorm:"size:50"`  // Timezone
}

// UserInfo 用户信息结构
type UserInfo struct {
	UserID string `json:"user_id" gorm:"primarykey"` // Login identifier, for normal accounts this is the login account, for email accounts it's automatically generated
	// Password      string      `json:"-" gorm:"not null"`
	Status        string      `json:"status" gorm:"not null;default:'active'"`
	Profile       UserProfile `json:"profile" gorm:"embedded"`
	LastLogin     *time.Time  `json:"last_login"`
	LoginAttempts int         `json:"login_attempts" gorm:"default:0"`
	LastAttempt   *time.Time  `json:"last_attempt"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
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

func getJWTClaims(accessToken string) (*CustomClaims, error) {
	token, _ := jwt.ParseWithClaims(accessToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok {
		now := time.Now()
		if claims.ExpiresAt.Time.After(now) {
			return claims, nil
		}
		return nil, errors.New("token expired")
	}

	return nil, errors.New("invalid token claims")
}

// remoteValidateToken 验证令牌
func (c *JWTClient) remoteValidateToken(accessToken string) (bool, error) {
	// 创建请求
	req, err := http.NewRequest("POST", c.AuthServerURL+"/authapi/token/validate", nil)
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

		claims, err := c.ValidateToken(tokenString)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "无效的令牌"})
			ctx.Abort()
			return
		}
		ctx.Set("user_id", claims.UserID)
		ctx.Set("session_id", claims.SessionID)
		ctx.Set("authenticated", true)
		ctx.Set("access_token", tokenString)
		ctx.Next()
	}
}

// 验证令牌
func (c *JWTClient) ValidateToken(tokenString string) (*CustomClaims, error) {

	claims, err := c.getTokenCached(tokenString)
	if err == nil {
		return claims, nil
	}
	valid, err := c.remoteValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid token")
	}
	claims, err = getJWTClaims(tokenString)
	if err != nil {
		return nil, err
	}
	c.cacheToken(tokenString)
	return claims, nil
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

		claims, err := c.ValidateToken(tokenString)
		if err != nil {
			ctx.Next()
			return
		}
		ctx.Set("user_id", claims.UserID)
		ctx.Set("session_id", claims.SessionID)
		ctx.Set("authenticated", true)
		ctx.Set("access_token", tokenString)
		ctx.Next()
	}
}

// getTokenCached 检查令牌是否在缓存中
func (c *JWTClient) getTokenCached(token string) (*CustomClaims, error) {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	expiry, exists := c.tokenCache[token]
	if !exists {
		return nil, errors.New("token not cached")
	}

	// 检查缓存是否过期
	if time.Now().Unix() > expiry {
		delete(c.tokenCache, token)
		return nil, errors.New("token expired")
	}

	return getJWTClaims(token)
}

// cacheToken 缓存令牌
func (c *JWTClient) cacheToken(token string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// 设置缓存过期时间
	expiry := time.Now().Add(c.cacheExpiry).Unix()
	c.tokenCache[token] = expiry
}

// GetUserInfo 获取用户信息
func (c *JWTClient) GetUserInfo(accessToken string) (*UserInfo, error) {
	// 创建请求
	req, err := http.NewRequest("GET", c.AuthServerURL+"/authapi/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New("invalid token")
		}
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("获取用户信息失败: %d", resp.StatusCode)
		}
		return nil, errors.New(errResp.Error)
	}

	// 解析响应
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("解析用户信息失败: %v", err)
	}

	return &userInfo, nil
}
