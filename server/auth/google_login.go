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
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// GoogleUserInfo 表示从 Google 获取的用户信息
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type GoogleUser struct {
	UserID        string `json:"user_id" gorm:"primarykey"`
	GoogleID      string `json:"google_id" gorm:"index"`
	Email         string `json:"email" gorm:"index"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// GoogleOAuthConfig 配置选项
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Timeout      time.Duration
	DB           *gorm.DB // 新增数据库连接
}

// GoogleOAuth 合并后的结构体，同时处理OAuth和用户管理
type GoogleOAuth struct {
	config     *oauth2.Config
	httpClient *http.Client
	db         *gorm.DB
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
			Scopes:       cfg.Scopes,
			Endpoint:     google.Endpoint,
		},
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		db: cfg.DB,
	}, nil
}

// AutoMigrate 自动迁移数据库表结构
func (g *GoogleOAuth) AutoMigrate() error {
	if g.db == nil {
		return fmt.Errorf("数据库未初始化")
	}

	if err := g.db.AutoMigrate(
		&User{},
		&GoogleUser{},
	); err != nil {
		return err
	}
	return nil
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
func (g *GoogleOAuth) HandleCallback(ctx context.Context, code, state, expectedState string) (*GoogleUserInfo, error) {
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
func (g *GoogleOAuth) getUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
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

		var user GoogleUserInfo
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

// GetUserByGoogleID 通过 Google ID 获取用户
func (g *GoogleOAuth) GetUserByGoogleID(googleID string) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	// 先查询 Google 用户表
	var googleUser GoogleUser
	err := g.db.Where("google_id = ?", googleID).First(&googleUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 未找到，返回nil，让后续流程处理
		}
		return nil, err
	}

	// 再查询对应的User记录
	var user User
	if err := g.db.Where("user_id = ?", googleUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "用户不存在", err)
		}
		return nil, err
	}

	return &user, nil
}

// RegisterOrLoginWithGoogle 通过 Google 登录或注册用户
func (g *GoogleOAuth) RegisterOrLoginWithGoogle(ctx context.Context, code, state, expectedState string) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	// 1. 处理 Google 回调，获取用户信息
	googleUserInfo, err := g.HandleCallback(ctx, code, state, expectedState)
	if err != nil {
		return nil, fmt.Errorf("处理Google回调失败: %w", err)
	}

	// 2. 查询是否已存在该 Google 用户
	user, err := g.GetUserByGoogleID(googleUserInfo.ID)
	if err != nil {
		return nil, err
	}

	// 3. 如果用户不存在，则创建新用户
	if user == nil {
		user, err = g.CreateUserFromGoogle(googleUserInfo)
		if err != nil {
			return nil, fmt.Errorf("创建Google用户失败: %w", err)
		}
	} else {
		// 4. 如果用户已存在，则更新用户信息
		if err := g.UpdateGoogleUserInfo(user.UserID, googleUserInfo); err != nil {
			log.Printf("更新Google用户信息失败: %v", err)
			// 不影响登录流程，只记录日志
		}
	}

	// 5. 更新最后登录时间
	now := time.Now()
	user.LastLogin = &now
	if err := g.db.Save(user).Error; err != nil {
		log.Printf("更新用户最后登录时间失败: %v", err)
		// 不影响登录流程，只记录日志
	}

	return user, nil
}

// CreateUserFromGoogle 从 Google 用户信息创建系统用户
func (g *GoogleOAuth) CreateUserFromGoogle(googleInfo *GoogleUserInfo) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	// 生成随机UserID
	// b := make([]byte, 8)
	// if _, err := rand.Read(b); err != nil {
	// 	return nil, fmt.Errorf("生成随机ID失败: %v", err)
	// }
	userID, err := GenerateBase62ID()
	if err != nil {
		return nil, fmt.Errorf("生成随机ID失败: %v", err)
	}

	// 确保UserID唯一
	for {
		var count int64
		g.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// 生成新的UserID
		userID, err = GenerateBase62ID()
		if err != nil {
			return nil, fmt.Errorf("生成随机ID失败: %v", err)
		}
	}

	// 使用事务确保数据一致性
	tx := g.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 生成随机密码（用户无法直接使用密码登录）
	randomPassword := make([]byte, 16)
	if _, err := rand.Read(randomPassword); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("生成随机密码失败: %v", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("密码加密失败: %v", err)
	}

	// 提取用户名作为昵称
	nickname := googleInfo.Name
	if nickname == "" {
		// 如果没有名称，使用邮箱前缀作为默认昵称
		if googleInfo.Email != "" {
			parts := strings.Split(googleInfo.Email, "@")
			nickname = parts[0]
		} else {
			nickname = userID
		}
	}

	// 创建基本用户记录
	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: string(hashedPassword),
		Status:   UserStatusActive,
		Profile: UserProfile{
			Nickname: nickname,
			Avatar:   googleInfo.Picture,
		},
		// LastAttempt: now,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("创建用户失败: %v", err)
	}

	// 创建Google用户关联记录
	googleUser := &GoogleUser{
		UserID:        userID,
		GoogleID:      googleInfo.ID,
		Email:         googleInfo.Email,
		VerifiedEmail: googleInfo.VerifiedEmail,
		Name:          googleInfo.Name,
		Picture:       googleInfo.Picture,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := tx.Create(googleUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("创建Google用户关联失败: %v", err)
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("保存数据失败: %v", err)
	}

	return user, nil
}

// UpdateGoogleUserInfo 更新 Google 用户信息
func (g *GoogleOAuth) UpdateGoogleUserInfo(userID string, googleInfo *GoogleUserInfo) error {
	if g.db == nil {
		return fmt.Errorf("数据库未初始化")
	}

	// 更新Google用户表信息
	result := g.db.Model(&GoogleUser{}).Where("user_id = ?", userID).Updates(map[string]interface{}{
		"name":           googleInfo.Name,
		"email":          googleInfo.Email,
		"verified_email": googleInfo.VerifiedEmail,
		"picture":        googleInfo.Picture,
		"updated_at":     time.Now(),
	})

	if result.Error != nil {
		return result.Error
	}

	// 提取用户名作为昵称
	nickname := googleInfo.Name
	if nickname == "" {
		// 如果没有名称，使用邮箱前缀作为默认昵称
		if googleInfo.Email != "" {
			parts := strings.Split(googleInfo.Email, "@")
			nickname = parts[0]
		}
	}

	// 同时更新用户资料
	return g.db.Model(&User{}).Where("user_id = ?", userID).Update("profile", UserProfile{
		Nickname: nickname,
		Avatar:   googleInfo.Picture,
	}).Error
}
