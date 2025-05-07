package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"kcaitech.com/kcauth/server/admin"
	"kcaitech.com/kcauth/server/auth"
	"kcaitech.com/kcauth/server/auth/storage"
	"kcaitech.com/kcauth/server/config"
	"kcaitech.com/kcauth/server/handlers"
	"kcaitech.com/kcauth/server/middleware"
)

// Global variables - reduce multiple passing of DB
var (
	globalDB         *gorm.DB
	globalRedisStore *auth.RedisStore
)

func main() {
	// Parse command line arguments
	configPath := flag.String("config", "config/config.json", "Configuration file path")
	flag.Parse()

	// Load configuration file
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration file: %v", err)
	}

	// Initialize database connection
	globalDB, err = gorm.Open(mysql.Open(cfg.Database.GetDSN()), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize Redis connection
	globalRedisStore, err = auth.NewRedisStore(
		cfg.Redis.GetRedisAddr(),
		cfg.Redis.Password,
		cfg.Redis.DB,
	)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer globalRedisStore.Close()

	// Initialize email service - not in use currently
	// _ = auth.NewEmailService(auth.SmtpConfig{
	// 	Host:     cfg.Auth.Smtp.Host,
	// 	Port:     cfg.Auth.Smtp.Port,
	// 	Username: cfg.Auth.Smtp.Username,
	// 	Password: cfg.Auth.Smtp.Password,
	// 	From:     cfg.Auth.Smtp.From,
	// 	BaseURL:  cfg.Auth.Smtp.BaseURL,
	// })

	// Create AccountAuth instance
	accountAuth := auth.NewAccountAuth(globalDB, auth.AccountAuthConfig{
		MaxLoginAttempts:  5,
		LoginLockDuration: time.Minute * 15,
		Redis:             auth.NewAccountRedisStore(globalRedisStore.GetClient()), // Set temporarily to nil to avoid type errors
	})

	// Execute database migration, ensure all tables are created
	if err := accountAuth.AutoMigrate(); err != nil {
		log.Fatalf("Database migration failed: %v", err)
	}

	// Set Gin mode
	if gin.Mode() == gin.DebugMode {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin engine
	r := gin.Default()

	// Initialize authentication handler
	var authHandler *handlers.AuthHandler
	if err := initAuthHandler(cfg, accountAuth, &authHandler, r); err != nil {
		log.Fatalf("Failed to initialize authentication handler: %v", err)
	}

	// Add CORS middleware
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"*"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	corsConfig.AllowCredentials = true
	r.Use(cors.New(corsConfig))

	// Initialize session middleware
	store, err := redis.NewStore(10, "tcp", cfg.Redis.GetRedisAddr(), cfg.Redis.Password, []byte("secret"))
	if err != nil {
		log.Fatalf("Failed to initialize Redis session storage: %v", err)
	}
	r.Use(sessions.Sessions("kcauth_session", store))

	r.Use(auth.ErrorHandler())

	// Add monitoring middleware
	r.Use(middleware.MetricsMiddleware())

	// Add rate limiting middleware
	rateLimiter := middleware.RateLimiter{}
	r.Use(rateLimiter.RateLimitMiddleware())

	// Add health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Register routes
	authHandler.RegisterRoutes(r.Group("/authapi"), cfg)

	// 添加静态文件服务
	// 前端静态文件
	r.Static("/assets", "./web/dist/assets")
	// 添加 favicon.ico 路由
	r.StaticFile("/favicon.ico", "./web/dist/favicon.ico")
	// 将前端其他请求重定向到index.html以支持单页应用
	r.NoRoute(func(c *gin.Context) {
		// 如果是API请求，返回404
		if c.Request.URL.Path == "/auth" || strings.HasPrefix(c.Request.URL.Path, "/auth/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth endpoint not found"})
			return
		}

		// 如果是admin请求，由admin服务器处理
		if strings.HasPrefix(c.Request.URL.Path, "/admin") {
			c.Status(http.StatusNotFound)
			return
		}
		log.Println("Redirecting to index.html")
		// 其他所有请求返回前端index.html
		c.File("./web/dist/index.html")
	})

	// Create main HTTP server
	readTimeout, err := cfg.Server.GetReadTimeout()
	if err != nil {
		log.Fatalf("Failed to parse read timeout configuration: %v", err)
	}

	writeTimeout, err := cfg.Server.GetWriteTimeout()
	if err != nil {
		log.Fatalf("Failed to parse write timeout configuration: %v", err)
	}

	mainServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	// Create and start admin server (if enabled)
	var adminServer *admin.AdminServer
	if cfg.Admin.Enabled {
		logger := log.New(os.Stdout, "[ADMIN] ", log.LstdFlags)
		adminServer = admin.NewAdminServer(cfg, globalDB, logger)

		if adminServer != nil {
			go func() {
				if err := adminServer.Start(); err != nil && err != http.ErrServerClosed {
					log.Fatalf("Admin server startup failed: %v", err)
				}
			}()
		}
	}

	// Start main server (non-blocking)
	go func() {
		log.Printf("Main server started on port :%d", cfg.Server.Port)
		if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Main server startup failed: %v", err)
		}
	}()

	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Create context for shutdown timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown admin server (if started)
	if adminServer != nil {
		if err := adminServer.Shutdown(ctx); err != nil {
			log.Fatalf("Admin server shutdown failed: %v", err)
		}
		log.Println("Admin server has been shut down")
	}

	// Shutdown main server
	if err := mainServer.Shutdown(ctx); err != nil {
		log.Fatalf("Main server shutdown failed: %v", err)
	}
	log.Println("Main server has been shut down")
}

func initAuthHandler(cfg *config.Config, accountAuth *auth.AccountAuth, handler **handlers.AuthHandler, r *gin.Engine) error {
	// Initialize email authentication
	var emailAuth *auth.EmailAuth
	if containsProvider(cfg.Auth.EnabledProviders, "email") && cfg.Auth.Smtp.Host != "" {
		// Create email service
		emailService := auth.NewEmailService(auth.SmtpConfig{
			Host:     cfg.Auth.Smtp.Host,
			Port:     cfg.Auth.Smtp.Port,
			Username: cfg.Auth.Smtp.Username,
			Password: cfg.Auth.Smtp.Password,
			From:     cfg.Auth.Smtp.From,
		})

		emailAuth = auth.NewEmailAuth(globalDB, auth.EmailAutnConfig{
			VerificationExpiry: time.Hour * 24,
			EmailService:       emailService,
			Redis:              auth.NewAccountRedisStore(globalRedisStore.GetClient()),
		})

		// Execute table structure migration
		if err := emailAuth.AutoMigrate(); err != nil {
			return fmt.Errorf("email account table migration failed: %v", err)
		}
	}

	// Initialize storage client
	storageClient, err := storage.NewStorageClient(&cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize Storage: %v", err)
	}

	// Initialize avatar service
	avatarService := auth.NewAvatarService(storageClient.Bucket, cfg.StorageUrl.Attatch)

	// Initialize Google OAuth
	var googleOAuth *auth.GoogleOAuth
	if containsProvider(cfg.Auth.EnabledProviders, "google") {
		googleOAuth, err = auth.NewGoogleOAuth(auth.GoogleOAuthConfig{
			ClientID:      cfg.Auth.Google.ClientID,
			ClientSecret:  cfg.Auth.Google.ClientSecret,
			RedirectURL:   cfg.Auth.Google.RedirectURL,
			Scopes:        cfg.Auth.Google.Scopes,
			DB:            globalDB,
			AvatarService: avatarService,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize Google OAuth: %v", err)
		}

		// Execute table structure migration
		if err := googleOAuth.AutoMigrate(); err != nil {
			return fmt.Errorf("google OAuth table migration failed: %v", err)
		}
	}

	// Initialize WeChat login
	var weixinLogin *auth.WeixinLogin
	if containsProvider(cfg.Auth.EnabledProviders, "weixin") {
		weixinLogin, err = auth.NewWeixinLogin(globalDB, auth.WeixinConfig{
			AppID:             cfg.Auth.Weixin.AppID,
			AppSecret:         cfg.Auth.Weixin.AppSecret,
			RedirectURL:       cfg.Auth.Weixin.RedirectURL,
			DomainVerifyToken: cfg.Auth.Weixin.DomainVerifyToken,
		}, avatarService)
		if err != nil {
			return fmt.Errorf("failed to initialize WeChat login: %v", err)
		}

		// Execute table structure migration
		if err := weixinLogin.AutoMigrate(); err != nil {
			return fmt.Errorf("WeChat login table migration failed: %v", err)
		}
	}

	// Initialize phone authentication
	var phoneAuth *auth.PhoneAuth
	if containsProvider(cfg.Auth.EnabledProviders, "phone") {
		// Create SMS service
		smsService := auth.NewSMSService(auth.SMSConfig{
			Provider:   cfg.Auth.SMS.Provider,
			AccessKey:  cfg.Auth.SMS.AccessKey,
			SecretKey:  cfg.Auth.SMS.SecretKey,
			SignName:   cfg.Auth.SMS.SignName,
			TemplateID: cfg.Auth.SMS.TemplateID,
			Region:     cfg.Auth.SMS.Region,
		})

		phoneAuth = auth.NewPhoneAuth(globalDB, auth.PhoneAuthConfig{
			VerificationExpiry: time.Minute * 10,
			SMSService:         smsService,
			Redis:              auth.NewAccountRedisStore(globalRedisStore.GetClient()),
		})

		// Execute table structure migration
		if err := phoneAuth.AutoMigrate(); err != nil {
			return fmt.Errorf("phone login table migration failed: %v", err)
		}
	}

	// Initialize two-factor authentication
	var twoFactor *auth.TwoFactorAuth
	if cfg.Auth.TwoFactor.Enabled {
		twoFactorConfig := &auth.TwoFactorConfig{
			Issuer:     cfg.Auth.TwoFactor.Issuer,
			Period:     cfg.Auth.TwoFactor.Period,
			Digits:     otp.Digits(cfg.Auth.TwoFactor.Digits),
			Algorithm:  otp.AlgorithmSHA1,
			SecretSize: cfg.Auth.TwoFactor.SecretSize,
			WindowSize: 1,
		}
		twoFactor = auth.NewTwoFactorAuth(globalDB, twoFactorConfig)
	}

	// Initialize JWT service
	jwtService := auth.NewJWTService(globalRedisStore, auth.JWTConfig{Issuer: cfg.Auth.JWT.Issuer})

	// Initialize session manager
	sessionMgr := auth.NewSessionManager(auth.NewSessionRedisStore(globalRedisStore.GetClient()))

	// Initialize auth handler
	*handler = handlers.NewAuthHandler(
		containsProvider(cfg.Auth.EnabledProviders, "account"),
		accountAuth,
		emailAuth,
		googleOAuth,
		weixinLogin,
		phoneAuth,
		twoFactor,
		jwtService,
		sessionMgr,
		globalRedisStore,
		storageClient,
		avatarService,
		cfg,
	)

	return nil
}

func containsProvider(providers []string, provider string) bool {
	for _, p := range providers {
		if p == provider {
			return true
		}
	}
	return false
}
