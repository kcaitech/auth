package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"kcaitech.com/kcauth/server/auth"
	"kcaitech.com/kcauth/server/config"
)

const (
	sessionUserKey = "admin_user"
	sessionRoleKey = "admin_roles"
)

// AdminServer Admin server
type AdminServer struct {
	config     *config.AdminConfig
	db         *gorm.DB
	router     *gin.Engine
	server     *http.Server
	sessions   map[string]*AdminSession
	sessionMu  sync.Mutex
	logger     *log.Logger
	redis      *auth.RedisStore
	sessionMgr *auth.SessionManager
	jwtService *auth.JWTService
}

// AdminSession Administrator session
type AdminSession struct {
	Username     string
	Roles        []string
	IP           string
	UserAgent    string
	LastActivity time.Time
	ExpiresAt    time.Time
}

// NewAdminServer Create admin server
func NewAdminServer(cfg *config.Config, db *gorm.DB, logger *log.Logger) *AdminServer {
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
		sessions:   make(map[string]*AdminSession),
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
	router.Use(sessions.Sessions("admin_session", store))

	// Add IP restriction middleware
	router.Use(server.ipRestrictionMiddleware())

	// Register routes
	server.registerRoutes(router)
	server.router = router

	// Get timeout configuration
	readTimeout, err := cfg.Server.GetReadTimeout()
	if err != nil {
		logger.Printf("Warning: Failed to parse read timeout configuration: %v, using default value 15 seconds", err)
		readTimeout = 15 * time.Second
	}

	writeTimeout, err := cfg.Server.GetWriteTimeout()
	if err != nil {
		logger.Printf("Warning: Failed to parse write timeout configuration: %v, using default value 15 seconds", err)
		writeTimeout = 15 * time.Second
	}

	// Create HTTP server
	server.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Admin.Port),
		Handler:      router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	return server
}

// Start Start admin server
func (s *AdminServer) Start() error {
	s.logger.Printf("Admin server started on :%d", s.config.Port)
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
func (s *AdminServer) registerRoutes(r *gin.Engine) {
	// Public routes
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes group (requires authentication)
	admin := r.Group("/authadmin")
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

	// Static file routes
	// r.Static("/assets", "./admin/assets")

	// 添加静态文件服务
	// r.Static("/", "./admin-web/")
	r.Use(static.Serve("/", static.LocalFile("./admin-web/", false))) // 前端工程

	// All other routes redirect to admin UI entry point
	r.NoRoute(func(c *gin.Context) {
		// If it's an API request, return 404 error
		if strings.HasPrefix(c.Request.URL.Path, "/auth/") || strings.HasPrefix(c.Request.URL.Path, "/authapi/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth path does not exist"})
			return
		}

		// Otherwise, return admin UI entry point
		c.File("./admin-web/index.html")
	})
}

// Logger middleware
func (s *AdminServer) loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		s.logger.Printf("[ADMIN] %s | %3d | %13v | %15s | %s",
			method, statusCode, latency, clientIP, path)
	}
}

// CORS middleware
func (s *AdminServer) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			// Use actual Origin from request instead of wildcard
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			// Allow requests with credentials
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// IP restriction middleware
func (s *AdminServer) ipRestrictionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(s.config.AllowedIPs) > 0 {
			clientIP := c.ClientIP()
			allowed := false

			for _, ip := range s.config.AllowedIPs {
				if ip == clientIP {
					allowed = true
					break
				}
			}

			if !allowed {
				s.logger.Printf("Access request from %s denied", clientIP)
				c.JSON(http.StatusForbidden, gin.H{"error": "IP address not in allowed list"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// Authentication middleware
func (s *AdminServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		// Check if user information exists in session
		username := session.Get(sessionUserKey)
		if username == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			c.Abort()
			return
		}

		// Get role information
		rolesJSON := session.Get(sessionRoleKey)
		if rolesJSON == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session is corrupted"})
			c.Abort()
			return
		}

		var roles []string
		if err := json.Unmarshal([]byte(rolesJSON.(string)), &roles); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse session"})
			c.Abort()
			return
		}

		// Update session activity time
		s.sessionMu.Lock()
		if adminSession, exists := s.sessions[username.(string)]; exists {
			adminSession.LastActivity = time.Now()
		}
		s.sessionMu.Unlock()

		// Set user information and roles to context
		c.Set("username", username)
		c.Set("roles", roles)

		c.Next()
	}
}

// Login handler
func (s *AdminServer) handleLogin(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Validate username and password
	var matchedAccount *config.Account
	for _, account := range s.config.Accounts {
		if subtle.ConstantTimeCompare([]byte(account.Username), []byte(loginReq.Username)) == 1 {
			matchedAccount = &account
			break
		}
	}

	if matchedAccount == nil {
		s.logger.Printf("Login failed: Username %s does not exist", loginReq.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Validate password (assuming password is bcrypt hash)
	err := bcrypt.CompareHashAndPassword([]byte(matchedAccount.Password), []byte(loginReq.Password))
	if err != nil {
		s.logger.Printf("Login failed: User %s password error", loginReq.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Create session
	session := sessions.Default(c)

	// Convert roles to JSON string
	rolesJSON, err := json.Marshal(matchedAccount.Roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Store user information to session
	session.Set(sessionUserKey, matchedAccount.Username)
	session.Set(sessionRoleKey, string(rolesJSON))
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Record active session
	s.sessionMu.Lock()
	s.sessions[matchedAccount.Username] = &AdminSession{
		Username:     matchedAccount.Username,
		Roles:        matchedAccount.Roles,
		IP:           c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(s.config.SessionTTL) * time.Minute),
	}
	s.sessionMu.Unlock()

	s.logger.Printf("User %s login successful, IP: %s", matchedAccount.Username, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"username": matchedAccount.Username,
		"roles":    matchedAccount.Roles,
	})
}

// Logout handler
func (s *AdminServer) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(sessionUserKey)

	// Delete session
	s.sessionMu.Lock()
	if username != nil {
		delete(s.sessions, username.(string))
	}
	s.sessionMu.Unlock()

	session.Clear()
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// Get user statistics
func (s *AdminServer) handleGetStats(c *gin.Context) {
	var stats struct {
		TotalUsers     int64 `json:"total_users"`
		ActiveUsers    int64 `json:"active_users"`
		InactiveUsers  int64 `json:"inactive_users"`
		LockedUsers    int64 `json:"locked_users"`
		BannedUsers    int64 `json:"banned_users"`
		NewToday       int64 `json:"new_today"`
		NewThisWeek    int64 `json:"new_this_week"`
		NewThisMonth   int64 `json:"new_this_month"`
		LoginToday     int64 `json:"login_today"`
		LoginThisWeek  int64 `json:"login_this_week"`
		LoginThisMonth int64 `json:"login_this_month"`
		SocialUsers    int64 `json:"social_users"`
		LocalUsers     int64 `json:"local_users"`
	}

	// Current time
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	weekStart := today.AddDate(0, 0, -int(now.Weekday()))
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	// Query user statistics
	s.db.Model(&auth.User{}).Count(&stats.TotalUsers)

	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusActive).Count(&stats.ActiveUsers)
	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusInactive).Count(&stats.InactiveUsers)
	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusLocked).Count(&stats.LockedUsers)
	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusBanned).Count(&stats.BannedUsers)

	s.db.Model(&auth.User{}).Where("created_at >= ?", today).Count(&stats.NewToday)
	s.db.Model(&auth.User{}).Where("created_at >= ?", weekStart).Count(&stats.NewThisWeek)
	s.db.Model(&auth.User{}).Where("created_at >= ?", monthStart).Count(&stats.NewThisMonth)

	s.db.Model(&auth.User{}).Where("last_login >= ?", today).Count(&stats.LoginToday)
	s.db.Model(&auth.User{}).Where("last_login >= ?", weekStart).Count(&stats.LoginThisWeek)
	s.db.Model(&auth.User{}).Where("last_login >= ?", monthStart).Count(&stats.LoginThisMonth)

	// Remove non-existent field query
	/*
		s.db.Model(&auth.User{}).Where("verified = ?", true).Count(&stats.VerifiedUsers)
		s.db.Model(&auth.User{}).Where("verified = ?", false).Count(&stats.UnverifiedUsers)
		s.db.Model(&auth.User{}).Where("two_factor_enabled = ?", true).Count(&stats.TwoFactorEnabled)
	*/

	// According to actual structure for adjustment, temporarily commented
	/*
		s.db.Model(&auth.User{}).Where("provider != ?", "local").Count(&stats.SocialUsers)
		s.db.Model(&auth.User{}).Where("provider = ?", "local").Count(&stats.LocalUsers)
	*/

	// Temporary set some values
	stats.SocialUsers = 0
	stats.LocalUsers = stats.TotalUsers

	c.JSON(http.StatusOK, stats)
}

// Get user list
func (s *AdminServer) handleGetUsers(c *gin.Context) {
	// Pagination parameters
	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
	}

	pageSize := 20
	if sizeStr := c.Query("size"); sizeStr != "" {
		fmt.Sscanf(sizeStr, "%d", &pageSize)
		if pageSize < 1 || pageSize > 100 {
			pageSize = 20
		}
	}

	// Filter parameters
	status := c.Query("status")
	provider := c.Query("provider")
	search := c.Query("search")

	// Build query conditions
	query := s.db.Model(&auth.User{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if provider != "" {
		// If auth.User does not have provider field, this part may need adjustment
		// query = query.Where("provider = ?", provider)
	}

	if search != "" {
		searchTerm := "%" + search + "%"
		// According to actual field adjustment
		query = query.Where("user_id LIKE ?", searchTerm)
	}

	// Total result count
	var total int64
	query.Count(&total)

	// Paginated query
	var users []auth.User
	offset := (page - 1) * pageSize

	err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&users).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user list"})
		return
	}

	// Remove sensitive information
	for i := range users {
		users[i].Password = ""
		// Delete non-existent TwoFactorSecret field, according to actual User structure definition
		// users[i].TwoFactorSecret = ""
	}

	c.JSON(http.StatusOK, gin.H{
		"users":      users,
		"total":      total,
		"page":       page,
		"page_size":  pageSize,
		"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// Get user activity
func (s *AdminServer) handleGetActivity(c *gin.Context) {
	// Date range parameters
	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
		if days < 1 || days > 90 {
			days = 30
		}
	}

	// Calculate start date
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days)

	// Prepare return result
	type DailyActivity struct {
		Date           string `json:"date"`
		NewUsers       int64  `json:"new_users"`
		ActiveUsers    int64  `json:"active_users"`
		LoginAttempts  int64  `json:"login_attempts"`
		SuccessfulAuth int64  `json:"successful_auth"`
		FailedAuth     int64  `json:"failed_auth"`
	}

	result := make([]DailyActivity, 0, days)

	// Calculate daily data
	current := startDate
	for current.Before(endDate) || current.Equal(endDate) {
		currentEnd := current.AddDate(0, 0, 1)

		var activity DailyActivity
		activity.Date = current.Format("2006-01-02")

		// New users
		s.db.Model(&auth.User{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.NewUsers)

		// Active users (users with login activity)
		s.db.Model(&auth.User{}).Where("last_login >= ? AND last_login < ?", current, currentEnd).Count(&activity.ActiveUsers)

		// Login attempts - may need adjustment LoginAttempt structure
		if s.db.Migrator().HasTable(&auth.LoginAttempt{}) {
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.LoginAttempts)

			// Successful authentication
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, true).Count(&activity.SuccessfulAuth)

			// Failed authentication
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, false).Count(&activity.FailedAuth)
		} else {
			// If there is no LoginAttempt table, give default value
			activity.LoginAttempts = 0
			activity.SuccessfulAuth = 0
			activity.FailedAuth = 0
		}

		result = append(result, activity)
		current = currentEnd
	}

	c.JSON(http.StatusOK, result)
}

// Get user session list
func (s *AdminServer) handleGetUserSessions(c *gin.Context) {
	userID := c.Param("id")

	// Parameter validation
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID cannot be empty"})
		return
	}

	s.logger.Printf("Get user %s session list", userID)

	// Create session manager
	sessionManager := s.sessionMgr

	// Use optimized method to get sessions
	sessions, err := sessionManager.GetUserSessions(userID)
	if err != nil {
		s.logger.Printf("Failed to get user sessions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query sessions"})
		return
	}

	// Ensure sessions are not null
	if sessions == nil {
		sessions = []*auth.Session{}
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		// "jwt_sessions": jwtSessions,
		// "total":        len(sessions),
	})
}

// Terminate specific user session
func (s *AdminServer) handleTerminateUserSession(c *gin.Context) {
	userID := c.Param("id")
	sessionID := c.Param("session_id")

	// Parameter validation
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID cannot be empty"})
		return
	}

	// Create session manager
	sessionManager := s.sessionMgr

	// Delete session from Redis
	if err := sessionManager.DeleteSession(userID, sessionID); err != nil {
		s.logger.Printf("Failed to terminate session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate session"})
		return
	}

	// Revoke JWT session
	if err := s.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
		s.logger.Printf("Failed to revoke JWT session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke JWT session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session successfully terminated"})
}

// Terminate all user sessions
func (s *AdminServer) handleTerminateAllUserSessions(c *gin.Context) {
	userID := c.Param("id")

	// Parameter validation
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID cannot be empty"})
		return
	}

	s.logger.Printf("Preparing to terminate all sessions for user %s", userID)

	// Create session manager
	sessionManager := s.sessionMgr

	// Terminate all regular sessions
	deletedCount, err := sessionManager.DeleteUserSessions(userID)
	if err != nil {
		s.logger.Printf("Failed to terminate user sessions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate regular sessions"})
		return
	}

	// Revoke JWT sessions
	for _, sessionID := range deletedCount {
		if err := s.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
			s.logger.Printf("Failed to revoke JWT session: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke JWT session"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "All user sessions successfully terminated",
		"user_id":       userID,
		"deleted_count": len(deletedCount),
		// "jwt_terminated": jwtTerminated,
	})
}
