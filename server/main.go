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

// 全局变量 - 减少对DB的多次传递
var (
	globalDB         *gorm.DB
	globalRedisStore *auth.RedisStore
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
	globalDB, err = gorm.Open(mysql.Open(cfg.Database.GetDSN()), &gorm.Config{})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	// 初始化Redis连接
	globalRedisStore, err = auth.NewRedisStore(
		cfg.Redis.GetRedisAddr(),
		cfg.Redis.Password,
		cfg.Redis.DB,
	)
	if err != nil {
		log.Fatalf("连接Redis失败: %v", err)
	}
	defer globalRedisStore.Close()

	// 初始化邮件服务 - 暂时不使用
	// _ = auth.NewEmailService(auth.SmtpConfig{
	// 	Host:     cfg.Auth.Smtp.Host,
	// 	Port:     cfg.Auth.Smtp.Port,
	// 	Username: cfg.Auth.Smtp.Username,
	// 	Password: cfg.Auth.Smtp.Password,
	// 	From:     cfg.Auth.Smtp.From,
	// 	BaseURL:  cfg.Auth.Smtp.BaseURL,
	// })

	// 创建 AccountAuth 实例
	accountAuth := auth.NewAccountAuth(globalDB, auth.AccountAuthConfig{
		MaxLoginAttempts:  5,
		LoginLockDuration: time.Minute * 15,
		Redis:             auth.NewAccountRedisStore(globalRedisStore.GetClient()), // 暂时设为nil，避免类型错误
	})

	// 执行数据库迁移，确保所有表已创建
	if err := accountAuth.AutoMigrate(); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	// 初始化认证处理器
	var authHandler *handlers.AuthHandler
	if err := initAuthHandler(cfg, accountAuth, &authHandler); err != nil {
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

	// todo
	// 初始化session中间件
	store, err := redis.NewStore(10, "tcp", cfg.Redis.GetRedisAddr(), cfg.Redis.Password, []byte("secret"))
	if err != nil {
		log.Fatalf("初始化Redis session存储失败: %v", err)
	}
	r.Use(sessions.Sessions("kcauth_session", store))

	// 注册路由
	authHandler.RegisterRoutes(r)

	// 创建主HTTP服务器
	readTimeout, err := cfg.Server.GetReadTimeout()
	if err != nil {
		log.Fatalf("解析读取超时配置失败: %v", err)
	}

	writeTimeout, err := cfg.Server.GetWriteTimeout()
	if err != nil {
		log.Fatalf("解析写入超时配置失败: %v", err)
	}

	mainServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	// 创建并启动管理服务器（如果启用）
	var adminServer *admin.AdminServer
	if cfg.Admin.Enabled {
		logger := log.New(os.Stdout, "[ADMIN] ", log.LstdFlags)
		adminServer = admin.NewAdminServer(cfg, globalDB, logger)

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

func initAuthHandler(cfg *config.Config, accountAuth *auth.AccountAuth, handler **handlers.AuthHandler) error {
	// 配置邮件账号
	var emailAuth *auth.EmailAuth
	if containsProvider(cfg.Auth.EnabledProviders, "email") && cfg.Auth.Smtp.Host != "" {
		// 创建邮件服务
		emailService := auth.NewEmailService(auth.SmtpConfig{
			Host:     cfg.Auth.Smtp.Host,
			Port:     cfg.Auth.Smtp.Port,
			Username: cfg.Auth.Smtp.Username,
			Password: cfg.Auth.Smtp.Password,
			From:     cfg.Auth.Smtp.From,
			// BaseURL:  cfg.Auth.Smtp.BaseURL,
		})

		// 使用文件中导入的类型，不要手动定义结构类型
		// 这里我们直接创建类型并传递参数
		emailAuth = auth.NewEmailAuth(globalDB, auth.EmailAutnConfig{
			VerificationExpiry: time.Hour * 24,
			EmailService:       emailService,
			Redis:              auth.NewAccountRedisStore(globalRedisStore.GetClient()), // 暂时为nil
		})

		// 执行表结构迁移
		if err := emailAuth.AutoMigrate(); err != nil {
			return fmt.Errorf("邮件账号表迁移失败: %v", err)
		}
	}

	// 根据配置创建Google OAuth处理器
	var googleOAuth *auth.GoogleOAuth
	if containsProvider(cfg.Auth.EnabledProviders, "google") {
		var err error
		googleOAuth, err = auth.NewGoogleOAuth(auth.GoogleOAuthConfig{
			ClientID:     cfg.Auth.Google.ClientID,
			ClientSecret: cfg.Auth.Google.ClientSecret,
			RedirectURL:  cfg.Auth.Google.RedirectURL,
			Scopes:       cfg.Auth.Google.Scopes,
			DB:           globalDB,
		})
		if err != nil {
			return fmt.Errorf("初始化Google OAuth失败: %v", err)
		}

		// 执行表结构迁移
		if err := googleOAuth.AutoMigrate(); err != nil {
			return fmt.Errorf("google OAuth表迁移失败: %v", err)
		}
	}

	// 根据配置创建微信登录处理器
	var weixinLogin *auth.WeixinLogin
	if containsProvider(cfg.Auth.EnabledProviders, "weixin") {
		var err error
		weixinLogin, err = auth.NewWeixinLogin(globalDB, auth.WeixinConfig{
			AppID:       cfg.Auth.Weixin.AppID,
			AppSecret:   cfg.Auth.Weixin.AppSecret,
			RedirectURL: cfg.Auth.Weixin.RedirectURL,
		})
		if err != nil {
			return fmt.Errorf("初始化微信登录失败: %v", err)
		}
		// autoMigrate
		// 执行表结构迁移
		if err := weixinLogin.AutoMigrate(); err != nil {
			return fmt.Errorf("微信登录表迁移失败: %v", err)
		}
	}

	// 根据配置创建手机号登录处理器
	var phoneAuth *auth.PhoneAuth
	if containsProvider(cfg.Auth.EnabledProviders, "phone") {
		// 创建短信服务
		smsService := auth.NewSMSService(auth.SMSConfig{
			Provider:   cfg.Auth.SMS.Provider,
			AccessKey:  cfg.Auth.SMS.AccessKey,
			SecretKey:  cfg.Auth.SMS.SecretKey,
			SignName:   cfg.Auth.SMS.SignName,
			TemplateID: cfg.Auth.SMS.TemplateID,
			Region:     cfg.Auth.SMS.Region,
		})

		// 创建手机认证
		phoneAuth = auth.NewPhoneAuth(globalDB, auth.PhoneAuthConfig{
			VerificationExpiry: time.Minute * 10, // 10分钟
			SMSService:         smsService,
			Redis:              auth.NewAccountRedisStore(globalRedisStore.GetClient()),
		})

		// 执行表结构迁移
		if err := phoneAuth.AutoMigrate(); err != nil {
			return fmt.Errorf("手机登录表迁移失败: %v", err)
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
		twoFactor = auth.NewTwoFactorAuth(globalDB, twoFactorConfig)
	}

	// 创建空的JWTService和SessionManager
	jwtService := auth.NewJWTService(globalRedisStore, auth.JWTConfig{Issuer: cfg.Auth.JWT.Issuer})
	sessionMgr := auth.NewSessionManager(auth.NewSessionRedisStore(globalRedisStore.GetClient()))
	// rateLimiter := &middleware.RateLimiter{}
	// 使用构造函数创建认证处理器
	*handler = handlers.NewAuthHandler(
		containsProvider(cfg.Auth.EnabledProviders, "account"), // 使用账号认证
		*accountAuth,
		emailAuth,
		googleOAuth,
		weixinLogin,
		phoneAuth,
		twoFactor,
		jwtService,
		// rateLimiter,
		sessionMgr,
		globalRedisStore,
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
