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
	config     *config.AdminConfig
	db         *gorm.DB
	router     *gin.Engine
	server     *http.Server
	sessions   map[string]*AdminSession
	sessionMu  sync.Mutex
	logger     *log.Logger
	redis      *auth.RedisStore // 添加Redis存储字段
	sessionMgr *auth.SessionManager
	jwtService *auth.JWTService
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

	// 初始化会话管理器
	sessionManager := auth.NewSessionManager(nil)
	if redisStore != nil {
		// 创建会话Redis存储
		sessionRedisStore := auth.NewSessionRedisStore(redisStore.GetClient())
		sessionManager = auth.NewSessionManager(sessionRedisStore)

		// 初始化会话管理器
		if err := sessionManager.Init(); err != nil {
			logger.Printf("警告: 初始化会话管理器失败: %v", err)
		} else {
			logger.Println("会话管理器初始化成功")
		}
	}

	// 初始化JWT服务
	jwtService := auth.NewJWTService(redisStore, auth.JWTConfig{
		Issuer: cfg.Auth.JWT.Issuer,
	})

	// 创建管理服务器
	server := &AdminServer{
		config:     &cfg.Admin,
		db:         db,
		sessions:   make(map[string]*AdminSession),
		logger:     logger,
		redis:      redisStore,
		sessionMgr: sessionManager,
		jwtService: jwtService,
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

	// 获取超时配置
	readTimeout, err := cfg.Server.GetReadTimeout()
	if err != nil {
		logger.Printf("警告: 解析读取超时配置失败: %v，使用默认值15秒", err)
		readTimeout = 15 * time.Second
	}

	writeTimeout, err := cfg.Server.GetWriteTimeout()
	if err != nil {
		logger.Printf("警告: 解析写入超时配置失败: %v，使用默认值15秒", err)
		writeTimeout = 15 * time.Second
	}

	// 创建HTTP服务器
	server.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Admin.Port),
		Handler:      router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
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

	// 移除不存在的字段查询
	/*
		s.db.Model(&auth.User{}).Where("verified = ?", true).Count(&stats.VerifiedUsers)
		s.db.Model(&auth.User{}).Where("verified = ?", false).Count(&stats.UnverifiedUsers)
		s.db.Model(&auth.User{}).Where("two_factor_enabled = ?", true).Count(&stats.TwoFactorEnabled)
	*/

	// 根据实际结构进行调整，暂时注释
	/*
		s.db.Model(&auth.User{}).Where("provider != ?", "local").Count(&stats.SocialUsers)
		s.db.Model(&auth.User{}).Where("provider = ?", "local").Count(&stats.LocalUsers)
	*/

	// 临时设置一些值
	stats.SocialUsers = 0
	stats.LocalUsers = stats.TotalUsers

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
	search := c.Query("search")

	// 构建查询条件
	query := s.db.Model(&auth.User{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if provider != "" {
		// 如果auth.User没有provider字段，这部分可能需要调整
		// query = query.Where("provider = ?", provider)
	}

	if search != "" {
		searchTerm := "%" + search + "%"
		// 根据实际字段调整
		query = query.Where("user_id LIKE ?", searchTerm)
	}

	// 统计结果总数
	var total int64
	query.Count(&total)

	// 分页查询
	var users []auth.User
	offset := (page - 1) * pageSize

	err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&users).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户列表失败"})
		return
	}

	// 移除敏感信息
	for i := range users {
		users[i].Password = ""
		// 删除不存在的TwoFactorSecret字段，根据实际User结构定义调整
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

		// 登录尝试 - 可能需要调整LoginAttempt结构
		if s.db.Migrator().HasTable(&auth.LoginAttempt{}) {
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.LoginAttempts)

			// 成功认证
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, true).Count(&activity.SuccessfulAuth)

			// 失败认证
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, false).Count(&activity.FailedAuth)
		} else {
			// 如果没有LoginAttempt表，赋予默认值
			activity.LoginAttempts = 0
			activity.SuccessfulAuth = 0
			activity.FailedAuth = 0
		}

		result = append(result, activity)
		current = currentEnd
	}

	c.JSON(http.StatusOK, result)
}

// 获取用户会话列表
func (s *AdminServer) handleGetUserSessions(c *gin.Context) {
	userID := c.Param("id")

	// 参数验证
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID不能为空"})
		return
	}

	s.logger.Printf("获取用户 %s 的会话列表", userID)

	// 创建会话管理器
	sessionManager := s.sessionMgr

	// 使用优化的方式获取会话
	sessions, err := sessionManager.GetUserSessions(userID)
	if err != nil {
		s.logger.Printf("获取用户会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询会话失败"})
		return
	}

	// 确保sessions不是null
	if sessions == nil {
		sessions = []*auth.Session{}
	}

	// 查询JWT会话（如果使用了JWT）
	// jwtSessions := []auth.JWTSession{}
	// if s.redis != nil {
	// 	// 注意：由于JWT会话API需要int64参数，但我们现在使用string作为userID，
	// 	// 后续需要根据实际API进行适配。这里暂时不调用JWT会话API。
	// 	s.logger.Printf("获取用户%s的JWT会话需要实现类型转换，暂不支持", userID)
	// } else {
	// 	s.logger.Println("Redis连接未初始化，无法获取JWT会话信息")
	// }

	// s.logger.Printf("成功获取用户 %s 的会话列表，共 %d 个会话", userID, len(sessions))

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		// "jwt_sessions": jwtSessions,
		// "total":        len(sessions),
	})
}

// 终止用户特定会话
func (s *AdminServer) handleTerminateUserSession(c *gin.Context) {
	userID := c.Param("id")
	sessionID := c.Param("session_id")

	// 参数验证
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "会话ID不能为空"})
		return
	}

	// 创建会话管理器
	sessionManager := s.sessionMgr

	// 判断会话类型（普通会话或JWT会话）
	// if strings.HasPrefix(sessionID, "jwt:") {
	// 	// 处理JWT会话
	// 	if s.redis == nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis连接未初始化，无法终止JWT会话"})
	// 		return
	// 	}

	// 	jwtID := strings.TrimPrefix(sessionID, "jwt:")
	// 	// 注意：此处应该使用JWTService撤销JWT会话
	// 	// 暂时不实现，需要根据实际API调整
	// 	s.logger.Printf("撤销JWT会话%s需要实现JWTService.RevokeJWT方法", jwtID)
	// 	c.JSON(http.StatusNotImplemented, gin.H{"error": "撤销JWT会话功能未实现"})
	// 	return
	// } else {
	// 从Redis中删除会话
	if err := sessionManager.DeleteSession(sessionID); err != nil {
		s.logger.Printf("终止会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "终止会话失败"})
		return
	}

	// s.logger.Printf("成功终止用户 %s 的会话 %s", userID, sessionID)
	// }
	// 撤销JWT会话
	if err := s.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
		s.logger.Printf("撤销JWT会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销JWT会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "会话已成功终止"})
}

// 终止用户所有会话
func (s *AdminServer) handleTerminateAllUserSessions(c *gin.Context) {
	userID := c.Param("id")

	// 参数验证
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID不能为空"})
		return
	}

	s.logger.Printf("准备终止用户 %s 的所有会话", userID)

	// 创建会话管理器
	sessionManager := s.sessionMgr

	// 终止所有普通会话
	deletedCount, err := sessionManager.DeleteUserSessions(userID)
	if err != nil {
		s.logger.Printf("终止用户会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "终止普通会话失败"})
		return
	}

	// s.logger.Printf("成功终止用户 %s 的 %d 个会话", userID, deletedCount)

	// 终止所有JWT会话的标志
	// jwtTerminated := false
	// 撤销JWT会话
	for _, sessionID := range deletedCount {
		if err := s.jwtService.RevokeJWTByID(userID, sessionID); err != nil {
			s.logger.Printf("撤销JWT会话失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销JWT会话失败"})
			return
		}
	}

	// // 终止所有JWT会话
	// if s.redis == nil {
	// 	s.logger.Println("Redis连接未初始化，无法终止JWT会话")
	// } else {
	// 	// 注意：此处应该使用JWTService撤销所有用户的JWT会话
	// 	// 暂时不实现，需要根据实际API调整
	// 	s.logger.Printf("撤销用户%s的所有JWT会话需要实现JWTService.RevokeAllUserTokens方法", userID)
	// 	// jwtTerminated = true; // 实现JWT会话终止后设置为true
	// }

	c.JSON(http.StatusOK, gin.H{
		"message":       "用户所有会话已成功终止",
		"user_id":       userID,
		"deleted_count": len(deletedCount),
		// "jwt_terminated": jwtTerminated,
	})
}
