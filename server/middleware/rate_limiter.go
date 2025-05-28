/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

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

// RedisStore Redis storage service
type RedisStore struct {
	Client *redis.Client
	Ctx    context.Context
}

// NewRedisStore Create a new Redis storage service
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
		Client: client,
		Ctx:    ctx,
	}, nil
}

// IncrRateLimit Increment rate limit counter and return current value
func (rs *RedisStore) IncrRateLimit(key string, window time.Duration) (int, error) {
	// 使用 Redis 的 INCR 命令增加计数
	count, err := rs.Client.Incr(rs.Ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// 如果是第一次设置或者没有设置过期时间，则设置过期时间
	if count == 1 || rs.Client.TTL(rs.Ctx, key).Val() == -1 {
		rs.Client.Expire(rs.Ctx, key, window)
	}

	return int(count), nil
}

// StoreRateLimit Store rate limit information
func (rs *RedisStore) StoreRateLimit(ip string, count int, window time.Duration) error {
	key := fmt.Sprintf("ratelimit:%s", ip)
	return rs.Client.Set(rs.Ctx, key, count, window).Err()
}

// GetRateLimit Get rate limit information
func (rs *RedisStore) GetRateLimit(ip string) (int, error) {
	key := fmt.Sprintf("ratelimit:%s", ip)
	count, err := rs.Client.Get(rs.Ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// DeleteRateLimit Delete rate limit information
func (rs *RedisStore) DeleteRateLimit(ip string) error {
	key := fmt.Sprintf("ratelimit:%s", ip)
	return rs.Client.Del(rs.Ctx, key).Err()
}

// Close Close Redis connection
func (rs *RedisStore) Close() error {
	return rs.Client.Close()
}

// RateLimiterConfig Rate limiter configuration
type RateLimiterConfig struct {
	// Maximum number of requests allowed within the time window
	MaxRequests int
	// Time window size
	Window time.Duration
	// Whether to enable IP-based rate limiting
	EnableIPRateLimit bool
	// Whether to enable user ID-based rate limiting
	EnableUserRateLimit bool
	// Whether to enable global rate limiting
	EnableGlobalRateLimit bool
	// Global rate limit threshold
	GlobalMaxRequests int
	// Global rate limit window
	GlobalWindow time.Duration
}

// DefaultRateLimiterConfig Default rate limiter configuration
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		MaxRequests:           100,
		Window:                time.Minute,
		EnableIPRateLimit:     true,
		EnableUserRateLimit:   true,
		EnableGlobalRateLimit: false,
		GlobalMaxRequests:     10000,
		GlobalWindow:          time.Minute,
	}
}

// RateLimiter Rate limiter
type RateLimiter struct {
	store  *RedisStore
	config RateLimiterConfig
}

// NewRateLimiter Create a new rate limiter
func NewRateLimiter(store *RedisStore, config RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		store:  store,
		config: config,
	}
}

// RateLimitMiddleware Rate limiting middleware
func (rl *RateLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if rate limiting should be applied
		if !rl.shouldRateLimit(c) {
			c.Next()
			return
		}

		// Get client identifier
		identifier := rl.getClientIdentifier(c)
		if identifier == "" {
			c.Next()
			return
		}

		// Check if limit is exceeded
		limited, count, err := rl.isLimited(identifier)
		if err != nil {
			// If there's an error, log it but allow the request to proceed
			c.Next()
			return
		}

		// Set RateLimit related HTTP headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", rl.config.MaxRequests))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", rl.config.MaxRequests-count))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(rl.config.Window).Unix()))

		if limited {
			// Record rate limit event
			RecordRateLimit(identifier)

			// Return 429 status code
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

// Check if rate limiting should be applied to the current request
func (rl *RateLimiter) shouldRateLimit(c *gin.Context) bool {
	// Skip rate limiting for static resources
	if strings.HasPrefix(c.Request.URL.Path, "/static") {
		return false
	}

	// Skip rate limiting for health checks
	if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/metrics" {
		return false
	}

	return true
}

// Get client identifier (IP or user ID)
func (rl *RateLimiter) getClientIdentifier(c *gin.Context) string {
	// If user ID rate limiting is enabled and user is logged in, use user ID
	if rl.config.EnableUserRateLimit {
		if userID, exists := c.Get("user_id"); exists {
			return fmt.Sprintf("user:%v", userID)
		}
	}

	// If IP rate limiting is enabled, use client IP
	if rl.config.EnableIPRateLimit {
		clientIP := c.ClientIP()
		if clientIP != "" {
			return fmt.Sprintf("ip:%s", clientIP)
		}
	}

	return ""
}

// Check if limit is exceeded
func (rl *RateLimiter) isLimited(identifier string) (bool, int, error) {
	// Increment counter and get current value
	count, err := rl.store.IncrRateLimit(identifier, rl.config.Window)
	if err != nil {
		return false, 0, err
	}

	// Check if limit is exceeded
	if count > rl.config.MaxRequests {
		return true, count, nil
	}

	// If global rate limiting is enabled, also check global limit
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
