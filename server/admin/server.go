/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package admin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"kcaitech.com/kcauth/server/auth"
	"kcaitech.com/kcauth/server/config"
)

const (
	sessionUserKey = "admin_user"
	sessionRoleKey = "admin_roles"
)

const ADMIN_ROUTER_PATH = config.ADMIN_ROUTER_PATH

// AdminServer Admin server
type AdminServer struct {
	config     *config.AdminConfig
	db         *gorm.DB
	router     *gin.Engine
	server     *http.Server
	logger     *log.Logger
	redis      *auth.RedisStore
	sessionMgr *auth.SessionManager
	jwtService *auth.JWTService
}

// NewAdminServer Create admin server
func NewAdminServer(cfg *config.Config, db *gorm.DB, logger *log.Logger, webFilePath string, port int) *AdminServer {
	if !cfg.Admin.Enabled {
		return nil
	}

	// If no admin account is configured, disable admin interface
	if len(cfg.Admin.Accounts) == 0 {
		logger.Println("Warning: Admin interface is configured to be enabled, but no admin account is configured, admin interface will be disabled")
		return nil
	}

	// Initialize RedisStore
	redisAddr := cfg.Redis.GetRedisAddr()
	redisStore, err := auth.NewRedisStore(redisAddr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		logger.Printf("Warning: Failed to initialize Redis connection: %v", err)
		logger.Println("Some features may not work properly, such as JWT session management")
	}

	// Initialize session manager
	sessionManager := auth.NewSessionManager(nil)
	if redisStore != nil {
		// Create session Redis storage
		sessionRedisStore := auth.NewSessionRedisStore(redisStore.GetClient())
		sessionManager = auth.NewSessionManager(sessionRedisStore)

		// Initialize session manager
		if err := sessionManager.Init(); err != nil {
			logger.Printf("Warning: Failed to initialize session manager: %v", err)
		} else {
			logger.Println("Session manager initialized successfully")
		}
	}

	// Initialize JWT service
	jwtService := auth.NewJWTService(redisStore, auth.JWTConfig{
		Issuer: cfg.Auth.JWT.Issuer,
	})

	// Create admin server
	server := &AdminServer{
		config:     &cfg.Admin,
		db:         db,
		logger:     logger,
		redis:      redisStore,
		sessionMgr: sessionManager,
		jwtService: jwtService,
	}

	// Set Gin mode
	if gin.Mode() == gin.DebugMode {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(server.loggerMiddleware())
	router.Use(server.corsMiddleware())

	// Initialize session storage
	store := cookie.NewStore([]byte(cfg.Admin.SecretKey))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   cfg.Admin.SessionTTL * 60, // Convert to seconds
		HttpOnly: true,
		Secure:   cfg.Admin.RequireTLS,
	})
	router.Use(sessions.Sessions("kcauth_admin_session", store))

	// Add IP restriction middleware
	router.Use(server.ipRestrictionMiddleware())

	// Register routes
	server.registerRoutes(router, webFilePath)
	server.router = router

	// Create HTTP server
	server.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}

	return server
}

// Start Start admin server
func (s *AdminServer) Start() error {
	s.logger.Printf("Admin server started on :%s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Shutdown Shutdown admin server
func (s *AdminServer) Shutdown(ctx context.Context) error {
	// Close Redis connection
	if s.redis != nil {
		if err := s.redis.Close(); err != nil {
			s.logger.Printf("Failed to close Redis connection: %v", err)
		}
	}
	return s.server.Shutdown(ctx)
}

// Register routes
func (s *AdminServer) registerRoutes(r *gin.Engine, webFilePath string) {
	// Public routes
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes group (requires authentication)
	admin := r.Group(ADMIN_ROUTER_PATH)
	// Login route
	admin.POST("/login", s.handleLogin)

	admin.Use(s.authMiddleware())
	{
		// User statistics
		admin.GET("/stats", s.handleGetStats)

		// User list
		admin.GET("/users", s.handleGetUsers)

		// User activity
		admin.GET("/activity", s.handleGetActivity)

		// User session information
		admin.GET("/user/:id/sessions", s.handleGetUserSessions)
		admin.DELETE("/user/:id/sessions/:session_id", s.handleTerminateUserSession)
		admin.DELETE("/user/:id/sessions", s.handleTerminateAllUserSessions)

		// Logout
		admin.POST("/logout", s.handleLogout)
	}

	// 添加静态文件服务
	r.Use(static.Serve("/", static.LocalFile(webFilePath, false))) // 前端工程

	// All other routes redirect to admin UI entry point
	r.NoRoute(func(c *gin.Context) {
		// If it's an API request, return 404 error
		if c.Request.URL.Path == ADMIN_ROUTER_PATH || strings.HasPrefix(c.Request.URL.Path, ADMIN_ROUTER_PATH+"/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth endpoint not found"})
			return
		}
		// 设置缓存时间为15分钟
		c.Header("Cache-Control", "public, max-age=900")
		// Otherwise, return admin UI entry point
		c.File(webFilePath + "/index.html")
	})
}
