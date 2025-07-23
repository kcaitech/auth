/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/contrib/gzip"
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

const defaultConfigFilePath = "config/config.yaml"
const defaultPort = 80
const defaultWebFilePath = "/app/web"
const defaultAdminPort = 81
const defaultAdminWebFilePath = "/app/admin-web"

const API_ROUTER_PATH = config.API_ROUTER_PATH

var StaticFileSuffix = []string{".html", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"}

func isStaticFile(path string) bool {
	// 先获取path后缀
	suffix := filepath.Ext(path)
	if suffix == "" {
		return false
	}
	return slices.Contains(StaticFileSuffix, suffix)
}

func joinPath(dir, path string) string {
	if !strings.HasPrefix(path, "/") {
		return dir + "/" + path
	}
	return dir + path
}

func onNotFound(webFilePath string) gin.HandlerFunc {
	return func(c *gin.Context) {

		path := c.Request.URL.Path
		if path == API_ROUTER_PATH || strings.HasPrefix(path, API_ROUTER_PATH+"/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth endpoint not found"})
			return
		}

		if isStaticFile(path) {
			c.File(joinPath(webFilePath, path))
			return
		}

		// 设置缓存时间为15分钟
		c.Header("Cache-Control", "public, max-age=900")
		c.File(webFilePath + "/index.html")
	}

}

func main() {
	// Parse command line arguments
	configPath := flag.String("config", defaultConfigFilePath, "Configuration file path")
	webFilePath := flag.String("web", defaultWebFilePath, "Web file path")
	port := flag.Int("port", defaultPort, "Port")
	adminPort := flag.Int("admin-port", defaultAdminPort, "Admin port")
	adminWebFilePath := flag.String("admin-web", defaultAdminWebFilePath, "Admin web file path")
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
	r := gin.New()

	// Add CORS middleware
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"*"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	corsConfig.AllowCredentials = true
	r.Use(cors.New(corsConfig))

	// web server
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	r.Use(static.Serve("/", static.LocalFile(*webFilePath, false))) // 前端工程
	r.NoRoute(onNotFound(*webFilePath))

	// Add health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Initialize session middleware
	// store, err := redis.NewStore(10, "tcp", cfg.Redis.GetRedisAddr(), cfg.Redis.Password, []byte("secret"))
	// if err != nil {
	// 	log.Fatalf("Failed to initialize Redis session storage: %v", err)
	// }
	// r.Use(sessions.Sessions("kcauth_session", store))

	r.Use(auth.ErrorHandler())

	// Add monitoring middleware
	r.Use(middleware.MetricsMiddleware())

	// Add rate limiting middleware
	rateLimiter := middleware.RateLimiter{}
	r.Use(rateLimiter.RateLimitMiddleware())

	// Initialize authentication handler
	var authHandler *handlers.AuthHandler
	if err := initAuthHandler(cfg, accountAuth, &authHandler); err != nil {
		log.Fatalf("Failed to initialize authentication handler: %v", err)
	}
	// Register routes
	authHandler.RegisterRoutes(r.Group(API_ROUTER_PATH), cfg)

	mainServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: r,
	}

	// Create and start admin server (if enabled)
	var adminServer *admin.AdminServer
	if cfg.Admin.Enabled {
		logger := log.New(os.Stdout, "[ADMIN] ", log.LstdFlags)
		adminServer = admin.NewAdminServer(cfg, globalDB, logger, *adminWebFilePath, *adminPort)

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
		log.Printf("Server started on port :%d", *port)
		if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server startup failed: %v", err)
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

func initAuthHandler(cfg *config.Config, accountAuth *auth.AccountAuth, handler **handlers.AuthHandler) error {
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
	avatarService := auth.NewAvatarService(storageClient.Bucket, cfg.StorageUrl.Auth)

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

	// Initialize WeChat Mini Program login
	var weixinMiniLogin *auth.WeixinMiniLogin
	if containsProvider(cfg.Auth.EnabledProviders, "weixin_mini") {
		weixinMiniLogin, err = auth.NewWeixinMiniLogin(globalDB, auth.WeixinMiniConfig{
			AppID:     cfg.Auth.WeixinMini.AppID,
			AppSecret: cfg.Auth.WeixinMini.AppSecret,
			GrantType: "authorization_code",
		}, avatarService)
		if err != nil {
			return fmt.Errorf("failed to initialize WeChat mini program login: %v", err)
		}

		// Execute table structure migration
		if err := weixinMiniLogin.AutoMigrate(); err != nil {
			return fmt.Errorf("WeChat mini program login table migration failed: %v", err)
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
		weixinMiniLogin,
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
