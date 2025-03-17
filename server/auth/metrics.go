package auth

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/gin-gonic/gin"
)

var (
	// 登录相关指标
	loginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_login_attempts_total",
		Help: "Total number of login attempts",
	}, []string{"provider", "status"})

	loginDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_login_duration_seconds",
		Help:    "Login request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"provider"})

	// API响应时间
	apiDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_api_duration_seconds",
		Help:    "API request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint", "method", "status"})

	// 速率限制指标
	rateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_rate_limit_hits_total",
		Help: "Total number of rate limit hits",
	}, []string{"ip"})

	// 活跃用户数
	activeUsers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "auth_active_users",
		Help: "Number of currently active users",
	})

	// 缓存指标
	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_cache_hits_total",
		Help: "Total number of cache hits",
	}, []string{"type"})

	cacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_cache_misses_total",
		Help: "Total number of cache misses",
	}, []string{"type"})
)

// MetricsMiddleware 监控中间件
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		timer := prometheus.NewTimer(apiDuration.WithLabelValues(
			c.FullPath(),
			c.Request.Method,
			"200",
		))
		defer timer.ObserveDuration()

		c.Next()

		status := c.Writer.Status()
		apiDuration.WithLabelValues(
			c.FullPath(),
			c.Request.Method,
			string(status),
		).Observe(timer.ObserveDuration().Seconds())
	}
}

// RecordLogin 记录登录尝试
func RecordLogin(provider string, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	loginAttempts.WithLabelValues(provider, status).Inc()
}

// RecordRateLimit 记录速率限制命中
func RecordRateLimit(ip string) {
	rateLimitHits.WithLabelValues(ip).Inc()
}

// RecordCacheHit 记录缓存命中
func RecordCacheHit(cacheType string) {
	cacheHits.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss 记录缓存未命中
func RecordCacheMiss(cacheType string) {
	cacheMisses.WithLabelValues(cacheType).Inc()
}

// UpdateActiveUsers 更新活跃用户数
func UpdateActiveUsers(count float64) {
	activeUsers.Set(count)
} 