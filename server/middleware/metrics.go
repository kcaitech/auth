package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Login related metrics
	loginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_login_attempts_total",
		Help: "Total number of login attempts",
	}, []string{"provider", "status"})

	loginDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_login_duration_seconds",
		Help:    "Login request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"provider"})

	// API response time
	apiDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_api_duration_seconds",
		Help:    "API request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint", "method", "status"})

	// Rate limiting metrics
	rateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_rate_limit_hits_total",
		Help: "Total number of rate limit hits",
	}, []string{"ip"})

	// Active users count
	activeUsers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "auth_active_users",
		Help: "Number of currently active users",
	})

	// Cache metrics
	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_cache_hits_total",
		Help: "Total number of cache hits",
	}, []string{"type"})

	cacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_cache_misses_total",
		Help: "Total number of cache misses",
	}, []string{"type"})
)

// MetricsMiddleware Monitoring middleware
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
			fmt.Sprintf("%d", status),
		).Observe(timer.ObserveDuration().Seconds())
	}
}

// RecordLogin Record login attempt
func RecordLogin(provider string, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	loginAttempts.WithLabelValues(provider, status).Inc()
}

// RecordRateLimit Record rate limit hit
func RecordRateLimit(ip string) {
	rateLimitHits.WithLabelValues(ip).Inc()
}

// RecordCacheHit Record cache hit
func RecordCacheHit(cacheType string) {
	cacheHits.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss Record cache miss
func RecordCacheMiss(cacheType string) {
	cacheMisses.WithLabelValues(cacheType).Inc()
}

// UpdateActiveUsers Update active users count
func UpdateActiveUsers(count float64) {
	activeUsers.Set(count)
}

// RecordLoginDuration Record login duration
func RecordLoginDuration(provider string, duration float64) {
	loginDuration.WithLabelValues(provider).Observe(duration)
}
