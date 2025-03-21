package auth

// WeChat Login

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// WeixinConfig WeChat login configuration
type WeixinConfig struct {
	AppID       string
	AppSecret   string
	RedirectURL string
}

// Validate Validate configuration
func (c *WeixinConfig) Validate() error {
	if c.AppID == "" || c.AppSecret == "" || c.RedirectURL == "" {
		return ErrInvalidConfig("Invalid WeChat login configuration")
	}
	return nil
}

// WeixinLoginResponse WeChat login response
type WeixinLoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

// WeixinUserInfo WeChat user information
type WeixinUserInfo struct {
	OpenID     string `json:"openid" gorm:"unique"`
	Nickname   string `json:"nickname"`
	Sex        int    `json:"sex"`
	Province   string `json:"province"`
	City       string `json:"city"`
	Country    string `json:"country"`
	HeadImgURL string `json:"headimgurl"`
	UnionID    string `json:"unionid" gorm:"unique"`
}

// WeixinErrorResponse WeChat error response
type WeixinErrorResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type WeixinUser struct {
	UserID string `json:"user_id" gorm:"primarykey"`
	WeixinUserInfo
}

// WeixinLogin WeChat login handler struct
type WeixinLogin struct {
	Config WeixinConfig
	db     *gorm.DB
}

// NewWeixinLogin Create WeChat login instance
func NewWeixinLogin(db *gorm.DB, config WeixinConfig) (*WeixinLogin, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &WeixinLogin{
		Config: config,
		db:     db,
	}, nil
}

func (a *WeixinLogin) AutoMigrate() error {
	if err := a.db.AutoMigrate(
		&User{},
		&WeixinUser{},
	); err != nil {
		return err
	}
	return nil
}

// GetAuthURL Get WeChat authorization URL
func (w *WeixinLogin) GetAuthURL(state string) string {
	return fmt.Sprintf(
		"https://open.weixin.qq.com/connect/qrconnect?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
		url.QueryEscape(w.Config.AppID),
		url.QueryEscape(w.Config.RedirectURL),
		url.QueryEscape(state),
	)
}

// HandleCallback Handle WeChat callback
func (w *WeixinLogin) HandleCallback(code string) (*WeixinLoginResponse, error) {
	if code == "" {
		return nil, ErrInvalidCode("Authorization code is empty")
	}

	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		w.Config.AppID,
		w.Config.AppSecret,
		code,
	)
	return doRequest[WeixinLoginResponse](url)
}

// RefreshToken Refresh access token
func (w *WeixinLogin) RefreshToken(refreshToken string) (*WeixinLoginResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=%s&grant_type=refresh_token&refresh_token=%s",
		w.Config.AppID,
		refreshToken,
	)
	return doRequest[WeixinLoginResponse](url)
}

// GetUserInfo Get user information
func (w *WeixinLogin) GetUserInfo(accessToken, openID string) (*WeixinUserInfo, error) {
	if accessToken == "" || openID == "" {
		return nil, errors.New("access token and openid are required")
	}

	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s",
		accessToken,
		openID,
	)
	return doRequest[WeixinUserInfo](url)
}

// ValidateAccessToken Validate whether access token is valid
func (w *WeixinLogin) ValidateAccessToken(accessToken, openID string) error {
	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/auth?access_token=%s&openid=%s",
		accessToken,
		openID,
	)
	resp, err := doRequest[WeixinErrorResponse](url)
	if err != nil {
		return err
	}

	if resp.ErrCode != 0 {
		return fmt.Errorf("invalid access token: %s", resp.ErrMsg)
	}

	return nil
}

// doRequest Execute HTTP request and handle response
func doRequest[T any](url string) (*T, error) {
	log.Printf("Requesting WeChat API: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrAPIRequest(err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w", ErrAPIRequest(fmt.Sprintf("status code %d", resp.StatusCode)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if it contains error response
	if strings.Contains(string(body), "errcode") {
		var errResp WeixinErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		if errResp.ErrCode != 0 {
			return nil, fmt.Errorf("weixin api error: %d - %s", errResp.ErrCode, errResp.ErrMsg)
		}
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &result, nil
}

// GetUserByWeixinID Get user by WeChat UnionID
func (w *WeixinLogin) GetUserByWeixinID(unionID string) (*User, error) {
	// First query WeChat user table
	var weixinUser WeixinUser
	err := w.db.Where("union_id = ?", unionID).First(&weixinUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // Not found, return nil to let subsequent process handle
		}
		return nil, err
	}

	// Then query the corresponding User record
	var user User
	if err := w.db.Where("user_id = ?", weixinUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	return &user, nil
}

// RegisterOrLoginWithWeixin Register or login user via WeChat
func (w *WeixinLogin) RegisterOrLoginWithWeixin(code string) (*User, *WeixinLoginResponse, error) {
	// 1. Handle WeChat callback, get access token and OpenID
	loginResp, err := w.HandleCallback(code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to process WeChat callback: %w", err)
	}

	// 2. Get WeChat user information
	userInfo, err := w.GetUserInfo(loginResp.AccessToken, loginResp.OpenID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get WeChat user information: %w", err)
	}

	// 3. Check if this WeChat user already exists
	user, err := w.GetUserByWeixinID(userInfo.UnionID)
	if err != nil {
		return nil, nil, err
	}

	// 4. If user doesn't exist, create a new user
	if user == nil {
		user, err = w.CreateUserFromWeixin(userInfo)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create WeChat user: %w", err)
		}
	} else {
		// 5. If user already exists, update user information
		if err := w.UpdateWeixinUserInfo(user.UserID, userInfo); err != nil {
			log.Printf("failed to update WeChat user information: %v", err)
			// Doesn't affect login process, just log it
		}
	}

	// 6. Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := w.db.Save(user).Error; err != nil {
		log.Printf("failed to update user's last login time: %v", err)
		// Doesn't affect login process, just log it
	}

	return user, loginResp, nil
}

// CreateUserFromWeixin Create system user from WeChat user information
func (w *WeixinLogin) CreateUserFromWeixin(weixinInfo *WeixinUserInfo) (*User, error) {
	// Generate random UserID
	userID, err := GenerateBase62ID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}

	// Ensure UserID is unique
	for {
		var count int64
		w.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// Generate new UserID
		userID, err = GenerateBase62ID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ID: %v", err)
		}
	}

	// Use transaction to ensure data consistency
	tx := w.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Generate random password (user cannot login directly with password)
	randomPassword := make([]byte, 16)
	if _, err := rand.Read(randomPassword); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to generate random password: %v", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to encrypt password: %v", err)
	}

	// Create basic user record
	now := time.Now()

	// Convert gender to string
	gender := "unknown"
	if weixinInfo.Sex == 1 {
		gender = "male"
	} else if weixinInfo.Sex == 2 {
		gender = "female"
	}

	user := &User{
		UserID:   userID,
		Password: string(hashedPassword),
		Status:   UserStatusActive,
		Profile: UserProfile{
			Nickname: weixinInfo.Nickname,
			Avatar:   weixinInfo.HeadImgURL,
			Gender:   gender,
			Location: fmt.Sprintf("%s %s %s", weixinInfo.Country, weixinInfo.Province, weixinInfo.City),
		},
		// LastAttempt: now,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Create WeChat user association record
	weixinUser := &WeixinUser{
		UserID:         userID,
		WeixinUserInfo: *weixinInfo,
	}

	if err := tx.Create(weixinUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create WeChat user association: %v", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// UpdateWeixinUserInfo Update WeChat user information
func (w *WeixinLogin) UpdateWeixinUserInfo(userID string, weixinInfo *WeixinUserInfo) error {
	// Update WeChat user table information
	result := w.db.Model(&WeixinUser{}).Where("user_id = ?", userID).Updates(map[string]interface{}{
		"nickname":     weixinInfo.Nickname,
		"sex":          weixinInfo.Sex,
		"province":     weixinInfo.Province,
		"city":         weixinInfo.City,
		"country":      weixinInfo.Country,
		"head_img_url": weixinInfo.HeadImgURL,
	})

	if result.Error != nil {
		return result.Error
	}

	// Convert gender to string
	gender := "unknown"
	if weixinInfo.Sex == 1 {
		gender = "male"
	} else if weixinInfo.Sex == 2 {
		gender = "female"
	}

	// Also update user profile
	return w.db.Model(&User{}).Where("user_id = ?", userID).Update("profile", UserProfile{
		Nickname: weixinInfo.Nickname,
		Avatar:   weixinInfo.HeadImgURL,
		Gender:   gender,
		Location: fmt.Sprintf("%s %s %s", weixinInfo.Country, weixinInfo.Province, weixinInfo.City),
	}).Error
}
