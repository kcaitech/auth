package auth

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// JWTMiddleware JWT中间件
type JWTMiddleware struct {
	client         *JWTClient       // JWT客户端
	tokenCache     map[string]int64 // 令牌缓存，用于减少对认证服务的请求
	cacheMutex     sync.RWMutex     // 缓存锁
	cacheExpiry    time.Duration    // 缓存过期时间
	tokenRefresher *TokenRefresher  // 令牌刷新器
}

// TokenRefresher 令牌刷新器
type TokenRefresher struct {
	client       *JWTClient          // JWT客户端
	refreshMutex sync.Mutex          // 刷新锁
	tokenStore   TokenStore          // 令牌存储
	refreshHook  func(*TokenResponse) // 刷新回调
}

// TokenStore 令牌存储接口
type TokenStore interface {
	GetRefreshToken() string
	SetTokens(accessToken, refreshToken string, expiresIn int)
}

// MemoryTokenStore 内存令牌存储
type MemoryTokenStore struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	mutex        sync.RWMutex
}

// NewMemoryTokenStore 创建内存令牌存储
func NewMemoryTokenStore(accessToken, refreshToken string, expiresIn int) *MemoryTokenStore {
	return &MemoryTokenStore{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
}

// GetRefreshToken 获取刷新令牌
func (s *MemoryTokenStore) GetRefreshToken() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.RefreshToken
}

// SetTokens 设置令牌
func (s *MemoryTokenStore) SetTokens(accessToken, refreshToken string, expiresIn int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.AccessToken = accessToken
	s.RefreshToken = refreshToken
	s.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
}

// NewJWTMiddleware 创建JWT中间件
func NewJWTMiddleware(client *JWTClient) *JWTMiddleware {
	return &JWTMiddleware{
		client:      client,
		tokenCache:  make(map[string]int64),
		cacheExpiry: 5 * time.Minute, // 默认缓存5分钟
	}
}

// SetTokenRefresher 设置令牌刷新器
func (m *JWTMiddleware) SetTokenRefresher(tokenStore TokenStore, refreshHook func(*TokenResponse)) {
	m.tokenRefresher = &TokenRefresher{
		client:     m.client,
		tokenStore: tokenStore,
		refreshHook: refreshHook,
	}
}

// AuthRequired 验证JWT令牌的中间件
func (m *JWTMiddleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取令牌
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供授权令牌"})
			c.Abort()
			return
		}

		// 检查令牌格式
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "授权格式无效"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 检查令牌缓存
		if m.isTokenCached(tokenString) {
			// 令牌有效，继续处理请求
			c.Next()
			return
		}

		// 验证令牌
		valid, err := m.client.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "验证令牌失败: " + err.Error()})
			c.Abort()
			return
		}

		if !valid {
			// 如果令牌无效，尝试刷新令牌
			if m.tokenRefresher != nil {
				newToken, err := m.tokenRefresher.RefreshIfNeeded()
				if err != nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "令牌无效且无法刷新: " + err.Error()})
					c.Abort()
					return
				}

				// 使用新令牌
				c.Header("X-New-Token", newToken)
				// 继续处理请求
				c.Next()
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的令牌"})
			c.Abort()
			return
		}

		// 缓存有效的令牌
		m.cacheToken(tokenString)

		// 继续处理请求
		c.Next()
	}
}

// OptionalAuth 可选的JWT验证中间件
func (m *JWTMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.Next()
			return
		}

		tokenString := parts[1]

		// 检查令牌缓存
		if m.isTokenCached(tokenString) {
			// 令牌有效，设置认证标志
			c.Set("authenticated", true)
			c.Next()
			return
		}

		// 验证令牌
		valid, _ := m.client.ValidateToken(tokenString)
		if valid {
			// 缓存有效的令牌
			m.cacheToken(tokenString)
			// 设置认证标志
			c.Set("authenticated", true)
		}

		c.Next()
	}
}

// isTokenCached 检查令牌是否在缓存中
func (m *JWTMiddleware) isTokenCached(token string) bool {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()

	expiry, exists := m.tokenCache[token]
	if !exists {
		return false
	}

	// 检查缓存是否过期
	if time.Now().Unix() > expiry {
		delete(m.tokenCache, token)
		return false
	}

	return true
}

// cacheToken 缓存令牌
func (m *JWTMiddleware) cacheToken(token string) {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()

	// 设置缓存过期时间
	expiry := time.Now().Add(m.cacheExpiry).Unix()
	m.tokenCache[token] = expiry
}

// RefreshIfNeeded 如果需要，刷新令牌
func (r *TokenRefresher) RefreshIfNeeded() (string, error) {
	r.refreshMutex.Lock()
	defer r.refreshMutex.Unlock()

	// 获取刷新令牌
	refreshToken := r.tokenStore.GetRefreshToken()
	if refreshToken == "" {
		return "", errors.New("没有可用的刷新令牌")
	}

	// 刷新令牌
	tokenResp, err := r.client.RefreshToken(refreshToken)
	if err != nil {
		return "", err
	}

	// 存储新令牌
	r.tokenStore.SetTokens(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)

	// 调用刷新回调
	if r.refreshHook != nil {
		r.refreshHook(tokenResp)
	}

	return tokenResp.AccessToken, nil
} 