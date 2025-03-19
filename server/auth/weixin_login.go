package auth

// 微信登录

import (
	"crypto/rand"
	"encoding/hex"
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

// WeixinConfig 微信登录配置
type WeixinConfig struct {
	AppID       string
	AppSecret   string
	RedirectURL string
}

// Validate 验证配置
func (c *WeixinConfig) Validate() error {
	if c.AppID == "" || c.AppSecret == "" || c.RedirectURL == "" {
		return ErrInvalidConfig("微信登录配置无效")
	}
	return nil
}

// WeixinLoginResponse 微信登录响应
type WeixinLoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

// WeixinUserInfo 微信用户信息
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

// WeixinErrorResponse 微信错误响应
type WeixinErrorResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type WeixinUser struct {
	UserID string `json:"user_id" gorm:"primarykey"`
	WeixinUserInfo
}

// WeixinLogin 微信登录处理结构体
type WeixinLogin struct {
	Config WeixinConfig
	db     *gorm.DB
}

// NewWeixinLogin 创建微信登录实例
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

// GetAuthURL 获取微信授权URL
func (w *WeixinLogin) GetAuthURL(state string) string {
	return fmt.Sprintf(
		"https://open.weixin.qq.com/connect/qrconnect?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
		url.QueryEscape(w.Config.AppID),
		url.QueryEscape(w.Config.RedirectURL),
		url.QueryEscape(state),
	)
}

// HandleCallback 处理微信回调
func (w *WeixinLogin) HandleCallback(code string) (*WeixinLoginResponse, error) {
	if code == "" {
		return nil, ErrInvalidCode("授权码为空")
	}

	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		w.Config.AppID,
		w.Config.AppSecret,
		code,
	)
	return doRequest[WeixinLoginResponse](url)
}

// RefreshToken 刷新访问令牌
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

// GetUserInfo 获取用户信息
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

// ValidateAccessToken 验证访问令牌是否有效
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

// doRequest 执行HTTP请求并处理响应
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

	// 检查是否包含错误响应
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

// GetUserByWeixinID 通过微信UnionID获取用户
func (w *WeixinLogin) GetUserByWeixinID(unionID string) (*User, error) {
	// 先查询微信用户表
	var weixinUser WeixinUser
	err := w.db.Where("union_id = ?", unionID).First(&weixinUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 未找到，返回nil，让后续流程处理
		}
		return nil, err
	}

	// 再查询对应的User记录
	var user User
	if err := w.db.Where("user_id = ?", weixinUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "用户不存在", err)
		}
		return nil, err
	}

	return &user, nil
}

// RegisterOrLoginWithWeixin 通过微信登录或注册用户
func (w *WeixinLogin) RegisterOrLoginWithWeixin(code string) (*User, *WeixinLoginResponse, error) {
	// 1. 处理微信回调，获取访问令牌和OpenID
	loginResp, err := w.HandleCallback(code)
	if err != nil {
		return nil, nil, fmt.Errorf("处理微信回调失败: %w", err)
	}

	// 2. 获取微信用户信息
	userInfo, err := w.GetUserInfo(loginResp.AccessToken, loginResp.OpenID)
	if err != nil {
		return nil, nil, fmt.Errorf("获取微信用户信息失败: %w", err)
	}

	// 3. 查询是否已存在该微信用户
	user, err := w.GetUserByWeixinID(userInfo.UnionID)
	if err != nil {
		return nil, nil, err
	}

	// 4. 如果用户不存在，则创建新用户
	if user == nil {
		user, err = w.CreateUserFromWeixin(userInfo)
		if err != nil {
			return nil, nil, fmt.Errorf("创建微信用户失败: %w", err)
		}
	} else {
		// 5. 如果用户已存在，则更新用户信息
		if err := w.UpdateWeixinUserInfo(user.UserID, userInfo); err != nil {
			log.Printf("更新微信用户信息失败: %v", err)
			// 不影响登录流程，只记录日志
		}
	}

	// 6. 更新最后登录时间
	now := time.Now()
	user.LastLogin = &now
	if err := w.db.Save(user).Error; err != nil {
		log.Printf("更新用户最后登录时间失败: %v", err)
		// 不影响登录流程，只记录日志
	}

	return user, loginResp, nil
}

// CreateUserFromWeixin 从微信用户信息创建系统用户
func (w *WeixinLogin) CreateUserFromWeixin(weixinInfo *WeixinUserInfo) (*User, error) {
	// 生成随机UserID
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("生成随机ID失败: %v", err)
	}
	userID := fmt.Sprintf("wx_%s", hex.EncodeToString(b))

	// 确保UserID唯一
	for {
		var count int64
		w.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// 生成新的UserID
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("生成随机ID失败: %v", err)
		}
		userID = fmt.Sprintf("wx_%s", hex.EncodeToString(b))
	}

	// 使用事务确保数据一致性
	tx := w.db.Begin()
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

	// 创建基本用户记录
	now := time.Now()

	// 性别转换为字符串
	gender := "未知"
	if weixinInfo.Sex == 1 {
		gender = "男"
	} else if weixinInfo.Sex == 2 {
		gender = "女"
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
		return nil, fmt.Errorf("创建用户失败: %v", err)
	}

	// 创建微信用户关联记录
	weixinUser := &WeixinUser{
		UserID:         userID,
		WeixinUserInfo: *weixinInfo,
	}

	if err := tx.Create(weixinUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("创建微信用户关联失败: %v", err)
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("保存数据失败: %v", err)
	}

	return user, nil
}

// UpdateWeixinUserInfo 更新微信用户信息
func (w *WeixinLogin) UpdateWeixinUserInfo(userID string, weixinInfo *WeixinUserInfo) error {
	// 更新微信用户表信息
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

	// 性别转换为字符串
	gender := "未知"
	if weixinInfo.Sex == 1 {
		gender = "男"
	} else if weixinInfo.Sex == 2 {
		gender = "女"
	}

	// 同时更新用户资料
	return w.db.Model(&User{}).Where("user_id = ?", userID).Update("profile", UserProfile{
		Nickname: weixinInfo.Nickname,
		Avatar:   weixinInfo.HeadImgURL,
		Gender:   gender,
		Location: fmt.Sprintf("%s %s %s", weixinInfo.Country, weixinInfo.Province, weixinInfo.City),
	}).Error
}
