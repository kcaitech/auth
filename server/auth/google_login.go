package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleUser 表示从 Google 获取的用户信息
type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// GoogleOAuthConfig 配置选项
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Timeout      time.Duration
}

// GoogleOAuth 处理 Google OAuth2 认证
type GoogleOAuth struct {
	config     *oauth2.Config
	httpClient *http.Client
}

// NewGoogleOAuth 创建新的 Google OAuth 处理器
func NewGoogleOAuth(cfg GoogleOAuthConfig) (*GoogleOAuth, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("missing required configuration")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		}
	}

	return &GoogleOAuth{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:      cfg.Scopes,
			Endpoint:    google.Endpoint,
		},
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

// GenerateState 生成随机 state 参数
func (g *GoogleOAuth) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetAuthURL 获取 Google 授权 URL
func (g *GoogleOAuth) GetAuthURL(state string) string {
	// 添加 PKCE 支持
	verifier := g.generateCodeVerifier()
	challenge := g.generateCodeChallenge(verifier)
	
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	
	return g.config.AuthCodeURL(state, opts...)
}

// HandleCallback 处理 OAuth 回调
func (g *GoogleOAuth) HandleCallback(ctx context.Context, code, state, expectedState string) (*GoogleUser, error) {
	if state == "" || state != expectedState {
		return nil, fmt.Errorf("invalid state parameter")
	}

	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	if !token.Valid() {
		return nil, fmt.Errorf("received invalid token")
	}

	user, err := g.getUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %w", err)
	}

	return user, nil
}

// getUserInfo 获取用户信息
func (g *GoogleOAuth) getUserInfo(ctx context.Context, accessToken string) (*GoogleUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", 
		"https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+accessToken)
	
	var retries int
	for {
		resp, err := g.httpClient.Do(req)
		if err != nil {
			if retries < 3 {
				retries++
				time.Sleep(time.Second * time.Duration(retries))
				continue
			}
			return nil, fmt.Errorf("failed getting user info after %d retries: %w", retries, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, fmt.Errorf("failed getting user info: status=%d, body=%s", 
				resp.StatusCode, string(body))
		}

		var user GoogleUser
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return nil, fmt.Errorf("failed parsing user info: %w", err)
		}

		return &user, nil
	}
}

// RefreshToken 刷新访问令牌
func (g *GoogleOAuth) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	
	newToken, err := g.config.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	
	return newToken, nil
}

// PKCE 相关辅助函数
func (g *GoogleOAuth) generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *GoogleOAuth) generateCodeChallenge(verifier string) string {
	// 使用 SHA256 生成 code challenge
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (g *GoogleOAuth) HandleCallbackWithError(ctx context.Context, code, state, expectedState string) (*GoogleUser, error) {
	if state == "" || state != expectedState {
		return nil, fmt.Errorf("invalid state parameter")
	}

	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		log.Printf("Google OAuth error: %v", err)
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	if !token.Valid() {
		return nil, fmt.Errorf("received invalid token")
	}

	user, err := g.getUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %w", err)
	}

	return user, nil
}