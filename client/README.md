# KCAuth 客户端

这个包提供了与KCAuth认证服务交互的客户端库和中间件，用于在业务服务中验证JWT令牌。

## 功能特性

- JWT客户端：与认证服务通信，处理登录、刷新令牌和登出等操作
- JWT中间件：用于验证请求中的JWT令牌
- 令牌刷新：自动刷新过期的令牌
- 令牌缓存：减少对认证服务的请求
- 可选认证：支持公开资源的差异化访问

## 安装

```bash
go get github.com/kcauth/client
```

## 使用方法

### 创建JWT客户端和中间件

```go
// 创建JWT客户端
jwtClient := auth.NewJWTClient("http://auth-service:8080")

// 创建JWT中间件
jwtMiddleware := auth.NewJWTMiddleware(jwtClient)
```

### 设置令牌刷新器（可选）

```go
// 创建令牌存储
tokenStore := auth.NewMemoryTokenStore("", "", 0)

// 设置令牌刷新器
jwtMiddleware.SetTokenRefresher(tokenStore, func(tokenResp *auth.TokenResponse) {
    log.Println("令牌已刷新")
})
```

### 在Gin中使用中间件

```go
// 创建Gin引擎
r := gin.Default()

// 公开路由
r.GET("/", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "message": "欢迎访问API",
    })
})

// 需要认证的路由
protected := r.Group("/api")
protected.Use(jwtMiddleware.AuthRequired())
{
    protected.GET("/profile", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "message": "这是受保护的资源",
        })
    })
}

// 可选认证的路由
optional := r.Group("/public")
optional.Use(jwtMiddleware.OptionalAuth())
{
    optional.GET("/data", func(c *gin.Context) {
        authenticated, exists := c.Get("authenticated")
        if exists && authenticated.(bool) {
            c.JSON(http.StatusOK, gin.H{
                "message": "您已认证，这是完整数据",
                "data": []string{"item1", "item2", "item3", "item4", "item5"},
            })
        } else {
            c.JSON(http.StatusOK, gin.H{
                "message": "您未认证，这是有限数据",
                "data": []string{"item1", "item2"},
            })
        }
    })
}
```

### 在业务代码中使用JWT客户端

```go
// 创建JWT客户端
jwtClient := auth.NewJWTClient("http://auth-service:8080")

// 登录获取令牌
tokenResp, err := jwtClient.Login("user@example.com", "password")
if err != nil {
    log.Fatalf("登录失败: %v", err)
}

// 创建令牌存储
tokenStore := auth.NewMemoryTokenStore(
    tokenResp.AccessToken,
    tokenResp.RefreshToken,
    tokenResp.ExpiresIn,
)

// 使用令牌进行API调用
// ...

// 刷新令牌
newTokenResp, err := jwtClient.RefreshToken(tokenStore.GetRefreshToken())
if err != nil {
    log.Fatalf("刷新令牌失败: %v", err)
}

// 更新令牌存储
tokenStore.SetTokens(
    newTokenResp.AccessToken,
    newTokenResp.RefreshToken,
    newTokenResp.ExpiresIn,
)

// 登出
err = jwtClient.Logout(tokenStore.AccessToken)
if err != nil {
    log.Fatalf("登出失败: %v", err)
}
```

## 自定义令牌存储

您可以实现自己的令牌存储，只需实现`TokenStore`接口：

```go
// TokenStore 令牌存储接口
type TokenStore interface {
    GetRefreshToken() string
    SetTokens(accessToken, refreshToken string, expiresIn int)
}
```

例如，您可以创建一个Redis或数据库令牌存储，以便在服务重启后保持令牌状态。

## 配置选项

- `AuthServerURL`：认证服务的URL
- `Timeout`：HTTP请求超时时间
- `cacheExpiry`：令牌缓存过期时间

## 注意事项

- 确保认证服务的`/auth/validate`端点可用，用于验证令牌
- 在生产环境中，应使用HTTPS进行通信
- 令牌刷新应在后台进行，避免阻塞用户请求 