package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "kcaitech.com/kcauth/server/auth"
    "gorm.io/gorm"
    "gorm.io/driver/mysql"
)

func main() {
    // 初始化数据库连接
    db, err := gorm.Open(mysql.Open("user:password@tcp(localhost:3306)/kcauth?charset=utf8mb4&parseTime=True&loc=Local"), &gorm.Config{})
    if err != nil {
        panic("failed to connect database")
    }

    // 创建 AccountAuth 实例
    accountAuth := auth.NewAccountAuth(db, auth.AccountAuthConfig{
        MaxLoginAttempts:    5,
        LoginLockDuration:   time.Minute * 15,
        VerificationExpiry:  time.Hour * 24,
    })

    r := gin.Default()
    
    // 创建认证处理器
    authHandler := auth.NewAuthHandler(
        "your-client-id",
        "your-client-secret",
        "http://your-domain/auth/google/callback",
        accountAuth,
        nil, // RedisStore 参数，这里暂时传 nil
    )
    
    authHandler.RegisterRoutes(r)
    
    r.Run(":8080")
}