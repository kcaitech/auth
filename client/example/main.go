package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kcauth/client/auth"
)

func main() {
	// 创建JWT客户端
	jwtClient := auth.NewJWTClient("http://auth-service:8080")

	// 创建JWT中间件
	jwtMiddleware := auth.NewJWTMiddleware(jwtClient)

	// 可选：设置令牌刷新器
	// 创建令牌存储
	tokenStore := auth.NewMemoryTokenStore("", "", 0)

	// 设置令牌刷新器
	jwtMiddleware.SetTokenRefresher(tokenStore, func(tokenResp *auth.TokenResponse) {
		log.Println("令牌已刷新")
	})

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

	// 启动服务器
	addr := ":8081"
	fmt.Printf("服务器启动在 %s\n", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}

// 示例：如何在业务代码中使用JWT客户端
func exampleUsage() {
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
} 