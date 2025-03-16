package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	googleOAuth *GoogleOAuth
}

func NewAuthHandler(clientID, clientSecret, redirectURL string) *AuthHandler {
	return &AuthHandler{
		googleOAuth: NewGoogleOAuth(clientID, clientSecret, redirectURL),
	}
}

func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.GET("/google/login", h.GoogleLogin)
		auth.GET("/google/callback", h.GoogleCallback)
	}
}

func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	// 生成随机state，实际使用时应该存储在session中进行验证
	state := "random-state"
	url := h.googleOAuth.GetAuthURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	// 实际使用时应该验证state
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Code not found",
		})
		return
	}

	user, err := h.googleOAuth.HandleCallback(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 这里可以根据需求处理用户信息
	// 比如保存到数据库、生成JWT token等
	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}