package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"encoding/json"
	"bytes"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
)

func setupTestRouter() (*gin.Engine, *AuthHandler) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// 设置Redis存储
	store, _ := redis.NewStore(10, "tcp", "localhost:6379", "", []byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	// 创建认证处理器
	accountAuth := NewAccountAuth(nil) // 使用空数据库
	handler := NewAuthHandler(
		"test-client-id",
		"test-client-secret",
		"http://localhost:8080/callback",
		accountAuth,
	)

	return r, handler
}

func TestGoogleLogin(t *testing.T) {
	r, handler := setupTestRouter()
	r.GET("/auth/google/login", handler.GoogleLogin)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth/google/login", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "accounts.google.com")
}

func TestRateLimit(t *testing.T) {
	r, handler := setupTestRouter()
	r.GET("/test", handler.RateLimitMiddleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		r.ServeHTTP(w, req)

		if i < 5 {
			assert.Equal(t, http.StatusOK, w.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, w.Code)
		}
	}
}

func TestJWTAuth(t *testing.T) {
	r, handler := setupTestRouter()
	r.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// 测试无token访问
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// 生成有效token
	token, _ := GenerateJWT(123, "test@example.com")
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// 测试无效token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin(t *testing.T) {
	r, handler := setupTestRouter()
	r.POST("/auth/login", handler.handleLogin)

	// 测试有效登录
	loginReq := LoginRequest{
		Username: "testuser",
		Password: "TestPass123",
	}
	body, _ := json.Marshal(loginReq)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// 由于没有实际的数据库，这里应该返回错误
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// 测试无效请求
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/auth/login", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRedisStore(t *testing.T) {
	store, err := NewRedisStore("localhost:6379", "", 0)
	if err != nil {
		t.Skip("Redis not available")
		return
	}
	defer store.Close()

	// 测试用户缓存
	user := &User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	err = store.CacheUser(user)
	assert.NoError(t, err)

	cached, err := store.GetCachedUser(1)
	assert.NoError(t, err)
	assert.Equal(t, user.Username, cached.Username)

	// 测试速率限制
	ip := "192.168.1.1"
	count, err := store.IncrRateLimit(ip, time.Minute)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)

	count, err = store.GetRateLimit(ip)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestSessionHandling(t *testing.T) {
	r, handler := setupTestRouter()
	r.GET("/auth/google/login", handler.GoogleLogin)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth/google/login", nil)
	r.ServeHTTP(w, req)

	// 检查session cookie是否设置
	assert.Contains(t, w.Header().Get("Set-Cookie"), "mysession")
} 