package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"context"

	"github.com/go-redis/redis/v8"
)

// RedisStore Redis存储服务
type RedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisStore 创建新的Redis存储服务
func NewRedisStore(addr, password string, db int) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisStore{
		client: client,
		ctx:    ctx,
	}, nil
}

// IncrRateLimit 增加限流计数并返回当前值
func (rs *RedisStore) IncrRateLimit(key string, window time.Duration) (int, error) {
	pipe := rs.client.Pipeline()
	incr := pipe.Incr(rs.ctx, key)
	pipe.Expire(rs.ctx, key, window)
	_, err := pipe.Exec(rs.ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}

// StoreRateLimit 存储速率限制信息
func (rs *RedisStore) StoreRateLimit(ip string, count int, window time.Duration) error {
	key := fmt.Sprintf("ratelimit:%s", ip)
	return rs.client.Set(rs.ctx, key, count, window).Err()
}

// GetRateLimit 获取速率限制信息
func (rs *RedisStore) GetRateLimit(ip string) (int, error) {
	key := fmt.Sprintf("ratelimit:%s", ip)
	count, err := rs.client.Get(rs.ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// DeleteRateLimit 删除速率限制信息
func (rs *RedisStore) DeleteRateLimit(ip string) error {
	key := fmt.Sprintf("ratelimit:%s", ip)
	return rs.client.Del(rs.ctx, key).Err()
}

// Close 关闭Redis连接
func (rs *RedisStore) Close() error {
	return rs.client.Close()
}

// RateLimiterConfig 限流器配置
type RateLimiterConfig struct {
	// 时间窗口内允许的最大请求数
	MaxRequests int
	// 时间窗口大小
	Window time.Duration
	// 是否启用IP限流
	EnableIPRateLimit bool
	// 是否启用用户ID限流
	EnableUserRateLimit bool
	// 是否启用全局限流
	EnableGlobalRateLimit bool
	// 全局限流阈值
	GlobalMaxRequests int
	// 全局限流窗口
	GlobalWindow time.Duration
}

// DefaultRateLimiterConfig 默认限流配置
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		MaxRequests:           100,
		Window:                time.Minute,
		EnableIPRateLimit:     true,
		EnableUserRateLimit:   true,
		EnableGlobalRateLimit: false,
		GlobalMaxRequests:     1000,
		GlobalWindow:          time.Minute,
	}
}

// RateLimiter 速率限制器
type RateLimiter struct {
	store  *RedisStore
	config RateLimiterConfig
}

// NewRateLimiter 创建新的速率限制器
func NewRateLimiter(store *RedisStore, config RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		store:  store,
		config: config,
	}
}

// RateLimitMiddleware 速率限制中间件
func (rl *RateLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查是否需要限流
		if !rl.shouldRateLimit(c) {
			c.Next()
			return
		}

		// 获取客户端标识符
		identifier := rl.getClientIdentifier(c)
		if identifier == "" {
			c.Next()
			return
		}

		// 检查是否超过限制
		limited, count, err := rl.isLimited(identifier)
		if err != nil {
			// 如果出错，记录错误但允许请求通过
			c.Next()
			return
		}

		// 设置RateLimit相关的HTTP头
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", rl.config.MaxRequests))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", rl.config.MaxRequests-count))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(rl.config.Window).Unix()))

		if limited {
			// 记录限流事件
			RecordRateLimit(identifier)

			// 返回429状态码
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": rl.config.Window.Seconds(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 检查是否应该对当前请求进行限流
func (rl *RateLimiter) shouldRateLimit(c *gin.Context) bool {
	// 跳过对静态资源的限流
	if strings.HasPrefix(c.Request.URL.Path, "/static") {
		return false
	}

	// 跳过对健康检查的限流
	if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/metrics" {
		return false
	}

	return true
}

// 获取客户端标识符（IP或用户ID）
func (rl *RateLimiter) getClientIdentifier(c *gin.Context) string {
	// 如果启用了用户ID限流，并且用户已登录，使用用户ID
	if rl.config.EnableUserRateLimit {
		if userID, exists := c.Get("user_id"); exists {
			return fmt.Sprintf("user:%v", userID)
		}
	}

	// 如果启用了IP限流，使用客户端IP
	if rl.config.EnableIPRateLimit {
		clientIP := c.ClientIP()
		if clientIP != "" {
			return fmt.Sprintf("ip:%s", clientIP)
		}
	}

	return ""
}

// 检查是否超过限制
func (rl *RateLimiter) isLimited(identifier string) (bool, int, error) {
	// 增加计数并获取当前值
	count, err := rl.store.IncrRateLimit(identifier, rl.config.Window)
	if err != nil {
		return false, 0, err
	}

	// 检查是否超过限制
	if count > rl.config.MaxRequests {
		return true, count, nil
	}

	// 如果启用了全局限流，还需要检查全局限制
	if rl.config.EnableGlobalRateLimit {
		globalCount, err := rl.store.IncrRateLimit("global", rl.config.GlobalWindow)
		if err != nil {
			return false, count, err
		}

		if globalCount > rl.config.GlobalMaxRequests {
			return true, count, nil
		}
	}

	return false, count, nil
}
