/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	mathRand "math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// WeixinMiniConfig 微信小程序配置
type WeixinMiniConfig struct {
	AppID     string
	AppSecret string
	GrantType string
}

// Validate 验证配置
func (c *WeixinMiniConfig) Validate() error {
	if c.AppID == "" || c.AppSecret == "" || c.GrantType == "" {
		return ErrInvalidConfig("Invalid WeChat mini program configuration")
	}
	return nil
}

// WeixinMiniLogin 微信小程序登录处理器
type WeixinMiniLogin struct {
	Config        WeixinMiniConfig
	db            *gorm.DB
	avatarService *AvatarService
}

// NewWeixinMiniLogin 创建微信小程序登录实例
func NewWeixinMiniLogin(db *gorm.DB, config WeixinMiniConfig, avatarService *AvatarService) (*WeixinMiniLogin, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &WeixinMiniLogin{
		Config:        config,
		db:            db,
		avatarService: avatarService,
	}, nil
}

// MiniProgramSessionResponse 微信小程序 code2session 响应
type MiniProgramSessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

// MiniProgramLogin 微信小程序登录
// jsCode: 前端 wx.login() 获取的 code
func (w *WeixinMiniLogin) MiniProgramLogin(jsCode string) (*User, *MiniProgramSessionResponse, error) {
	if jsCode == "" {
		return nil, nil, errors.New("jsCode is required")
	}

	// 1. code2session
	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=%s",
		w.Config.AppID,
		w.Config.AppSecret,
		jsCode,
		w.Config.GrantType,
	)
	resp, err := doRequest[MiniProgramSessionResponse](url)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to call code2session: %w", err)
	}
	if resp.ErrCode != 0 {
		return nil, resp, fmt.Errorf("code2session error: %d %s", resp.ErrCode, resp.ErrMsg)
	}

	// 2. 获取 unionid（优先用 code2session 返回的 unionid）
	unionID := resp.UnionID
	if unionID == "" {
		return nil, resp, errors.New("unionid not found")
	}

	// 3. 查找或注册用户
	user, err := w.GetUserByWeixinID(unionID)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, resp, err
	}
	if user == nil {
		// 这里只能用 openid/unionid 注册，昵称头像等需前端补充
		userInfo := &WeixinUserInfo{
			OpenID:  resp.OpenID,
			UnionID: unionID,
		}
		user, err = w.CreateUserFromWeixin(userInfo)
		if err != nil {
			return nil, resp, fmt.Errorf("failed to create user: %w", err)
		}
	} else {
		// 更新最后登录时间
		err := w.db.Model(&User{}).Where("user_id = ?", user.UserID).Updates(map[string]interface{}{
			"last_login": time.Now(),
		}).Error
		if err != nil {
			log.Printf("failed to update user's last login time: %v", err)
		}
	}

	return user, resp, nil
}

// GetUserByWeixinID 通过微信 UnionID 获取用户
func (w *WeixinMiniLogin) GetUserByWeixinID(unionID string) (*User, error) {
	var weixinUser WeixinUser
	err := w.db.Where("union_id = ?", unionID).First(&weixinUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	var user User
	if err := w.db.Where("user_id = ?", weixinUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	return &user, nil
}

// CreateUserFromWeixin 从微信用户信息创建系统用户
func (w *WeixinMiniLogin) CreateUserFromWeixin(weixinInfo *WeixinUserInfo) (*User, error) {
	userID, err := GenerateUserID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}

	for {
		var count int64
		w.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		userID, err = GenerateUserID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ID: %v", err)
		}
	}

	// 处理头像URL - 小程序登录时可能为空
	var avatarURL string
	if weixinInfo.HeadImgURL != "" {
		// 只有当头像URL不为空时才尝试下载和上传
		avatarURL, err = w.avatarService.DownloadAndUploadAvatar(userID, weixinInfo.HeadImgURL)
		if err != nil {
			// 头像处理失败不应该阻止用户创建，记录日志但继续
			log.Printf("failed to process avatar for user %s: %v", userID, err)
			avatarURL = "" // 设置为空，允许后续更新
		}
	}

	tx := w.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

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

	now := time.Now()

	// 处理昵称 - 小程序登录时可能为空，使用默认值
	nickname := weixinInfo.Nickname
	if nickname == "" {
		// 生成 wx_{sha256后12位}{4位随机数字} 格式的昵称
		hash := sha256.Sum256([]byte(weixinInfo.UnionID))
		hashStr := fmt.Sprintf("%x", hash)
		// 取 sha256 的后12位
		hashSuffix := hashStr[len(hashStr)-12:]

		// 生成4位随机数字
		randomNum := mathRand.Intn(10000)
		randomStr := fmt.Sprintf("%04d", randomNum)

		nickname = fmt.Sprintf("wx_%s%s", hashSuffix, randomStr)
	}

	user := &User{
		UserID:    userID,
		Password:  string(hashedPassword),
		Status:    UserStatusActive,
		Nickname:  nickname,
		Avatar:    avatarURL,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	weixinUser := &WeixinUser{
		UserID:         userID,
		WeixinUserInfo: *weixinInfo,
	}
	// 更新处理后的头像URL
	weixinUser.HeadImgURL = avatarURL

	if err := tx.Create(weixinUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create WeChat user association: %v", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// UpdateUserProfile 更新小程序用户的个人信息（昵称和头像）
func (w *WeixinMiniLogin) UpdateUserProfile(userID string, nickname string, avatarURL string) error {
	tx := w.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 处理头像上传（如果提供了头像URL）
	var processedAvatarURL string
	if avatarURL != "" {
		var err error
		processedAvatarURL, err = w.avatarService.DownloadAndUploadAvatar(userID, avatarURL)
		if err != nil {
			log.Printf("failed to process avatar for user %s: %v", userID, err)
			// 头像处理失败不影响昵称更新
			processedAvatarURL = ""
		}
	}

	// 准备更新数据
	updates := make(map[string]interface{})
	if nickname != "" {
		updates["nickname"] = nickname
	}
	if processedAvatarURL != "" {
		updates["avatar"] = processedAvatarURL
	}
	if len(updates) > 0 {
		updates["updated_at"] = time.Now()
	}

	// 更新用户表
	if len(updates) > 0 {
		if err := tx.Model(&User{}).Where("user_id = ?", userID).Updates(updates).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to update user profile: %w", err)
		}
	}

	// 更新微信用户表
	weixinUpdates := make(map[string]interface{})
	if nickname != "" {
		weixinUpdates["nickname"] = nickname
	}
	if processedAvatarURL != "" {
		weixinUpdates["head_img_url"] = processedAvatarURL
	}
	if len(weixinUpdates) > 0 {
		weixinUpdates["updated_at"] = time.Now()
		if err := tx.Model(&WeixinUser{}).Where("user_id = ?", userID).Updates(weixinUpdates).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to update weixin user profile: %w", err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit profile updates: %w", err)
	}

	return nil
}

// AutoMigrate 自动迁移数据库表结构
func (w *WeixinMiniLogin) AutoMigrate() error {
	if err := w.db.AutoMigrate(
		&User{},
		&WeixinUser{},
	); err != nil {
		return err
	}
	return nil
}
