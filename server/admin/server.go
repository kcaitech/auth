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

// AdminServer 管理服务器
type AdminServer struct {
	config    *config.AdminConfig
	db        *gorm.DB
	router    *gin.Engine
	server    *http.Server
	sessions  map[string]*AdminSession
	sessionMu sync.Mutex
	logger    *log.Logger
	redis     *auth.RedisStore // 添加Redis存储字段
}

// AdminSession 管理会话
type AdminSession struct {
	Username     string
	Roles        []string
	IP           string
	UserAgent    string
	LastActivity time.Time
	ExpiresAt    time.Time
}

// NewAdminServer 创建管理服务器
func NewAdminServer(cfg *config.Config, db *gorm.DB, logger *log.Logger) *AdminServer {
	if !cfg.Admin.Enabled {
		return nil
	}

	// 如果没有管理员账号，禁用管理界面
	if len(cfg.Admin.Accounts) == 0 {
		logger.Println("警告: 管理界面已配置启用，但未配置管理员账号，将禁用管理界面")
		return nil
	}

	// 初始化RedisStore
	redisAddr := cfg.Redis.GetRedisAddr()
	redisStore, err := auth.NewRedisStore(redisAddr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		logger.Printf("警告: 初始化Redis连接失败: %v", err)
		logger.Println("部分功能可能无法正常工作，例如JWT会话管理")
	}

	// 创建管理服务器
	server := &AdminServer{
		config:   &cfg.Admin,
		db:       db,
		sessions: make(map[string]*AdminSession),
		logger:   logger,
		redis:    redisStore,
	}

	// 设置Gin模式
	if gin.Mode() == gin.DebugMode {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建路由器
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(server.loggerMiddleware())
	router.Use(server.corsMiddleware())

	// 初始化会话存储
	store := cookie.NewStore([]byte(cfg.Admin.SecretKey))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   cfg.Admin.SessionTTL * 60, // 转换为秒
		HttpOnly: true,
		Secure:   cfg.Admin.RequireTLS,
	})
	router.Use(sessions.Sessions("admin_session", store))

	// 添加IP限制中间件
	router.Use(server.ipRestrictionMiddleware())

	// 注册路由
	server.registerRoutes(router)
	server.router = router

	// 创建HTTP服务器
	server.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Admin.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	return server
}

// Start 启动管理服务器
func (s *AdminServer) Start() error {
	s.logger.Printf("管理服务器启动在 :%d", s.config.Port)
	return s.server.ListenAndServe()
}

// Shutdown 关闭管理服务器
func (s *AdminServer) Shutdown(ctx context.Context) error {
	// 关闭Redis连接
	if s.redis != nil {
		if err := s.redis.Close(); err != nil {
			s.logger.Printf("关闭Redis连接失败: %v", err)
		}
	}
	return s.server.Shutdown(ctx)
}

// 注册路由
func (s *AdminServer) registerRoutes(r *gin.Engine) {
	// 公共路由
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API路由组（需要认证）
	admin := r.Group("/admin")
	// 登录路由
	admin.POST("/login", s.handleLogin)

	admin.Use(s.authMiddleware())
	{
		// 用户统计信息
		admin.GET("/stats", s.handleGetStats)

		// 用户列表
		admin.GET("/users", s.handleGetUsers)

		// 用户活跃情况
		admin.GET("/activity", s.handleGetActivity)

		// 用户会话信息
		admin.GET("/user/:id/sessions", s.handleGetUserSessions)
		admin.DELETE("/user/:id/sessions/:session_id", s.handleTerminateUserSession)
		admin.DELETE("/user/:id/sessions", s.handleTerminateAllUserSessions)

		// 注销
		admin.POST("/logout", s.handleLogout)
	}

	// 静态文件路由
	// r.Static("/assets", "./admin/assets")

	// 所有其他路由重定向到管理页面入口点
	r.NoRoute(func(c *gin.Context) {
		// 如果是API请求返回404错误
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API路径不存在"})
			return
		}

		// 否则返回管理UI入口点
		c.File("./admin/index.html")
	})
}

// 日志中间件
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

// CORS中间件
func (s *AdminServer) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			// 使用请求的实际Origin而不是通配符
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			// 允许请求带有凭据
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

// IP限制中间件
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
				s.logger.Printf("拒绝来自 %s 的访问请求", clientIP)
				c.JSON(http.StatusForbidden, gin.H{"error": "IP地址不在允许列表中"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// 验证中间件
func (s *AdminServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		// 检查会话中是否有用户信息
		username := session.Get(sessionUserKey)
		if username == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
			c.Abort()
			return
		}

		// 获取角色信息
		rolesJSON := session.Get(sessionRoleKey)
		if rolesJSON == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "会话已损坏"})
			c.Abort()
			return
		}

		var roles []string
		if err := json.Unmarshal([]byte(rolesJSON.(string)), &roles); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "会话解析失败"})
			c.Abort()
			return
		}

		// 更新会话活动时间
		s.sessionMu.Lock()
		if adminSession, exists := s.sessions[username.(string)]; exists {
			adminSession.LastActivity = time.Now()
		}
		s.sessionMu.Unlock()

		// 将用户信息和角色设置到上下文中
		c.Set("username", username)
		c.Set("roles", roles)

		c.Next()
	}
}

// 登录处理
func (s *AdminServer) handleLogin(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 验证用户名和密码
	var matchedAccount *config.Account
	for _, account := range s.config.Accounts {
		if subtle.ConstantTimeCompare([]byte(account.Username), []byte(loginReq.Username)) == 1 {
			matchedAccount = &account
			break
		}
	}

	if matchedAccount == nil {
		s.logger.Printf("登录失败: 用户名 %s 不存在", loginReq.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户名或密码"})
		return
	}

	// 验证密码（假设密码是bcrypt哈希）
	err := bcrypt.CompareHashAndPassword([]byte(matchedAccount.Password), []byte(loginReq.Password))
	if err != nil {
		s.logger.Printf("登录失败: 用户 %s 密码错误", loginReq.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户名或密码"})
		return
	}

	// 创建会话
	session := sessions.Default(c)

	// 将角色转换为JSON字符串
	rolesJSON, err := json.Marshal(matchedAccount.Roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部服务器错误"})
		return
	}

	// 存储用户信息到会话
	session.Set(sessionUserKey, matchedAccount.Username)
	session.Set(sessionRoleKey, string(rolesJSON))
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法创建会话"})
		return
	}

	// 记录活跃会话
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

	s.logger.Printf("用户 %s 登录成功，IP: %s", matchedAccount.Username, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"username": matchedAccount.Username,
		"roles":    matchedAccount.Roles,
	})
}

// 注销处理
func (s *AdminServer) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(sessionUserKey)

	// 删除会话
	s.sessionMu.Lock()
	if username != nil {
		delete(s.sessions, username.(string))
	}
	s.sessionMu.Unlock()

	session.Clear()
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "已成功注销"})
}

// 获取用户统计信息
func (s *AdminServer) handleGetStats(c *gin.Context) {
	var stats struct {
		TotalUsers       int64 `json:"total_users"`
		ActiveUsers      int64 `json:"active_users"`
		InactiveUsers    int64 `json:"inactive_users"`
		LockedUsers      int64 `json:"locked_users"`
		BannedUsers      int64 `json:"banned_users"`
		NewToday         int64 `json:"new_today"`
		NewThisWeek      int64 `json:"new_this_week"`
		NewThisMonth     int64 `json:"new_this_month"`
		LoginToday       int64 `json:"login_today"`
		LoginThisWeek    int64 `json:"login_this_week"`
		LoginThisMonth   int64 `json:"login_this_month"`
		VerifiedUsers    int64 `json:"verified_users"`
		UnverifiedUsers  int64 `json:"unverified_users"`
		TwoFactorEnabled int64 `json:"two_factor_enabled"`
		SocialUsers      int64 `json:"social_users"`
		LocalUsers       int64 `json:"local_users"`
	}

	// 当前时间
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	weekStart := today.AddDate(0, 0, -int(now.Weekday()))
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	// 查询用户统计信息
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

	s.db.Model(&auth.User{}).Where("verified = ?", true).Count(&stats.VerifiedUsers)
	s.db.Model(&auth.User{}).Where("verified = ?", false).Count(&stats.UnverifiedUsers)

	s.db.Model(&auth.User{}).Where("two_factor_enabled = ?", true).Count(&stats.TwoFactorEnabled)

	s.db.Model(&auth.User{}).Where("provider != ?", "local").Count(&stats.SocialUsers)
	s.db.Model(&auth.User{}).Where("provider = ?", "local").Count(&stats.LocalUsers)

	c.JSON(http.StatusOK, stats)
}

// 获取用户列表
func (s *AdminServer) handleGetUsers(c *gin.Context) {
	// 分页参数
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

	// 筛选参数
	status := c.Query("status")
	provider := c.Query("provider")
	verified := c.Query("verified")
	search := c.Query("search")

	// 构建查询条件
	query := s.db.Model(&auth.User{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if provider != "" {
		query = query.Where("provider = ?", provider)
	}

	if verified == "true" {
		query = query.Where("verified = ?", true)
	} else if verified == "false" {
		query = query.Where("verified = ?", false)
	}

	if search != "" {
		searchTerm := "%" + search + "%"
		query = query.Where("username LIKE ? OR email LIKE ?", searchTerm, searchTerm)
	}

	// 统计结果总数
	var total int64
	query.Count(&total)

	// 分页查询
	var users []auth.User
	offset := (page - 1) * pageSize

	err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&users).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户列表失败"})
		return
	}

	// 移除敏感信息
	for i := range users {
		users[i].Password = ""
		users[i].TwoFactorSecret = ""
	}

	c.JSON(http.StatusOK, gin.H{
		"users":      users,
		"total":      total,
		"page":       page,
		"page_size":  pageSize,
		"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// 获取用户活跃情况
func (s *AdminServer) handleGetActivity(c *gin.Context) {
	// 日期范围参数
	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
		if days < 1 || days > 90 {
			days = 30
		}
	}

	// 计算开始日期
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days)

	// 准备返回结果
	type DailyActivity struct {
		Date           string `json:"date"`
		NewUsers       int64  `json:"new_users"`
		ActiveUsers    int64  `json:"active_users"`
		LoginAttempts  int64  `json:"login_attempts"`
		SuccessfulAuth int64  `json:"successful_auth"`
		FailedAuth     int64  `json:"failed_auth"`
	}

	result := make([]DailyActivity, 0, days)

	// 计算每日数据
	current := startDate
	for current.Before(endDate) || current.Equal(endDate) {
		currentEnd := current.AddDate(0, 0, 1)

		var activity DailyActivity
		activity.Date = current.Format("2006-01-02")

		// 新用户
		s.db.Model(&auth.User{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.NewUsers)

		// 活跃用户（有登录活动的用户）
		s.db.Model(&auth.User{}).Where("last_login >= ? AND last_login < ?", current, currentEnd).Count(&activity.ActiveUsers)

		// 登录尝试
		s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.LoginAttempts)

		// 成功认证
		s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, true).Count(&activity.SuccessfulAuth)

		// 失败认证
		s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, false).Count(&activity.FailedAuth)

		result = append(result, activity)
		current = currentEnd
	}

	c.JSON(http.StatusOK, result)
}

// 获取用户会话列表
func (s *AdminServer) handleGetUserSessions(c *gin.Context) {
	userIDStr := c.Param("id")
	var userID int
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID无效"})
		return
	}

	// 查询用户会话
	var sessions []auth.Session
	err := s.db.Where("user_id = ?", userID).Order("created_at DESC").Find(&sessions).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询会话失败"})
		return
	}

	// 查询JWT会话（如果使用了JWT）
	jwtSessions := []auth.JWTSession{}
	if s.redis != nil {
		jwtService := auth.NewJWTService(s.redis)

		tempJwtSessions, err := jwtService.GetUserActiveSessions(int64(userID))
		if err != nil {
			// 仅记录错误，不中断响应
			s.logger.Printf("获取JWT会话失败: %v", err)
		} else {
			jwtSessions = tempJwtSessions
		}
	} else {
		s.logger.Println("Redis连接未初始化，无法获取JWT会话信息")
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions":     sessions,
		"jwt_sessions": jwtSessions,
	})
}

// 终止用户特定会话
func (s *AdminServer) handleTerminateUserSession(c *gin.Context) {
	userIDStr := c.Param("id")
	sessionID := c.Param("session_id")

	var userID int
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID无效"})
		return
	}

	// 判断会话类型（普通会话或JWT会话）
	if strings.HasPrefix(sessionID, "jwt:") {
		// 处理JWT会话
		if s.redis == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis连接未初始化，无法终止JWT会话"})
			return
		}

		jwtID := strings.TrimPrefix(sessionID, "jwt:")
		jwtService := auth.NewJWTService(s.redis)

		err := jwtService.RevokeJWT(jwtID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("终止JWT会话失败: %v", err)})
			return
		}
	} else {
		// 处理普通会话
		if err := s.db.Where("id = ? AND user_id = ?", sessionID, userID).Delete(&auth.Session{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "终止会话失败"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "会话已成功终止"})
}

// 终止用户所有会话
func (s *AdminServer) handleTerminateAllUserSessions(c *gin.Context) {
	userIDStr := c.Param("id")
	var userID int
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID无效"})
		return
	}

	// 终止所有普通会话
	if err := s.db.Where("user_id = ?", userID).Delete(&auth.Session{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "终止普通会话失败"})
		return
	}

	// 终止所有JWT会话
	if s.redis == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis连接未初始化，无法终止JWT会话"})
		return
	}

	jwtService := auth.NewJWTService(s.redis)

	err := jwtService.RevokeAllUserTokens(fmt.Sprintf("user_%d", userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("终止JWT会话失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "用户所有会话已成功终止"})
}
