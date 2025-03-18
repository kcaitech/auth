package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	"kcaitech.com/kcauth/server/config"
	"kcaitech.com/kcauth/server/handlers"
)

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "config/config.json", "配置文件路径")
	flag.Parse()

	// 加载配置文件
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 初始化数据库连接
	db, err := gorm.Open(mysql.Open(cfg.Database.GetDSN()), &gorm.Config{})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	// 初始化Redis连接
	redisStore, err := auth.NewRedisStore(
		cfg.Redis.GetRedisAddr(),
		cfg.Redis.Password,
		cfg.Redis.DB,
	)
	if err != nil {
		log.Fatalf("连接Redis失败: %v", err)
	}
	defer redisStore.Close()

	// 创建 AccountAuth 实例
	accountAuth := auth.NewAccountAuth(db, auth.AccountAuthConfig{
		MaxLoginAttempts:   5,
		LoginLockDuration:  time.Minute * 15,
		VerificationExpiry: time.Hour * 24,
	})

	// 执行数据库迁移，确保所有表已创建
	if err := accountAuth.AutoMigrate(); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	// 初始化认证处理器
	var authHandler *handlers.AuthHandler
	if err := initAuthHandler(cfg, accountAuth, redisStore, &authHandler); err != nil {
		log.Fatalf("初始化认证处理器失败: %v", err)
	}

	// 设置Gin模式
	if gin.Mode() == gin.DebugMode {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建Gin引擎
	r := gin.Default()

	// 添加CORS中间件
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:3000"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	corsConfig.AllowCredentials = true
	r.Use(cors.New(corsConfig))

	// 初始化session中间件
	store, err := redis.NewStore(10, "tcp", cfg.Redis.GetRedisAddr(), cfg.Redis.Password, []byte("secret"))
	if err != nil {
		log.Fatalf("初始化Redis session存储失败: %v", err)
	}
	r.Use(sessions.Sessions("kcauth_session", store))

	// 注册路由
	authHandler.RegisterRoutes(r)

	// 创建主HTTP服务器
	mainServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// 创建并启动管理服务器（如果启用）
	var adminServer *admin.AdminServer
	if cfg.Admin.Enabled {
		logger := log.New(os.Stdout, "[ADMIN] ", log.LstdFlags)
		adminServer = admin.NewAdminServer(cfg, db, logger)

		if adminServer != nil {
			go func() {
				if err := adminServer.Start(); err != nil && err != http.ErrServerClosed {
					log.Fatalf("管理服务器启动失败: %v", err)
				}
			}()
		}
	}

	// 启动主服务器（非阻塞）
	go func() {
		log.Printf("主服务器启动在 :%d", cfg.Server.Port)
		if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("主服务器启动失败: %v", err)
		}
	}()

	// 设置优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("正在关闭服务器...")

	// 创建关闭超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 关闭管理服务器（如果已启动）
	if adminServer != nil {
		if err := adminServer.Shutdown(ctx); err != nil {
			log.Fatalf("管理服务器关闭失败: %v", err)
		}
		log.Println("管理服务器已关闭")
	}

	// 关闭主服务器
	if err := mainServer.Shutdown(ctx); err != nil {
		log.Fatalf("主服务器关闭失败: %v", err)
	}
	log.Println("主服务器已关闭")
}

func initAuthHandler(cfg *config.Config, accountAuth *auth.AccountAuth, redisStore *auth.RedisStore, handler **handlers.AuthHandler) error {
	// 根据配置创建Google OAuth处理器
	var googleOAuth *auth.GoogleOAuth
	if containsProvider(cfg.Auth.EnabledProviders, "google") {
		var err error
		googleOAuth, err = auth.NewGoogleOAuth(auth.GoogleOAuthConfig{
			ClientID:     cfg.Auth.Google.ClientID,
			ClientSecret: cfg.Auth.Google.ClientSecret,
			RedirectURL:  cfg.Auth.Google.RedirectURL,
			Scopes:       cfg.Auth.Google.Scopes,
		})
		if err != nil {
			return fmt.Errorf("初始化Google OAuth失败: %v", err)
		}
	}

	// 根据配置创建微信登录处理器
	var weixinLogin *auth.WeixinLogin
	if containsProvider(cfg.Auth.EnabledProviders, "weixin") {
		var err error
		weixinLogin, err = auth.NewWeixinLogin(auth.WeixinConfig{
			AppID:       cfg.Auth.Weixin.AppID,
			AppSecret:   cfg.Auth.Weixin.AppSecret,
			RedirectURL: cfg.Auth.Weixin.RedirectURL,
		})
		if err != nil {
			return fmt.Errorf("初始化微信登录失败: %v", err)
		}
	}

	// 创建双因素认证服务
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
		twoFactor = auth.NewTwoFactorAuth(twoFactorConfig, accountAuth)
	}

	// 创建认证处理器
	*handler = handlers.NewAuthHandler(
		accountAuth,
		googleOAuth,
		weixinLogin,
		twoFactor,
		auth.NewJWTService(redisStore),
		auth.NewRateLimiter(redisStore, auth.DefaultRateLimiterConfig()),
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
