package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 用户角色
type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
	RoleGuest UserRole = "guest"
)

// 权限
type Permission string

const (
	PermReadBasic   Permission = "read:basic"
	PermReadAdmin   Permission = "read:admin"
	PermWriteBasic  Permission = "write:basic"
	PermWriteAdmin  Permission = "write:admin"
	PermDeleteBasic Permission = "delete:basic"
	PermDeleteAdmin Permission = "delete:admin"
)

// 验证类型
type VerificationType string

const (
	VerificationTypeEmail     VerificationType = "email"
	VerificationTypePassword  VerificationType = "password"
	VerificationTypeTwoFactor VerificationType = "2fa"
)

// 登录尝试记录
type LoginAttempt struct {
	ID        uint   `gorm:"primarykey"`
	UserID    uint   `gorm:"index"`
	IP        string `gorm:"size:45"`
	Success   bool
	CreatedAt time.Time
}

// 验证记录
type Verification struct {
	ID        uint             `gorm:"primarykey"`
	UserID    uint             `gorm:"index"`
	Type      VerificationType `gorm:"size:20"`
	Token     string           `gorm:"size:100;index"`
	ExpiresAt time.Time
	CreatedAt time.Time
}

// 用户角色关联
type UserRoleMapping struct {
	UserID    uint   `gorm:"primarykey"`
	Role      string `gorm:"primarykey;size:20"`
	CreatedAt time.Time
}

// User 用户模型
type User struct {
	ID               uint        `json:"id" gorm:"primarykey"`
	Username         string      `json:"username" gorm:"unique;not null"`
	Email            string      `json:"email" gorm:"unique"`
	Password         string      `json:"-" gorm:"not null"`
	Provider         string      `json:"provider" gorm:"not null"`
	SocialID         string      `json:"social_id" gorm:"unique"`
	Status           UserStatus  `json:"status" gorm:"not null;default:'active'"`
	Profile          UserProfile `json:"profile" gorm:"embedded"`
	Verified         bool        `json:"verified" gorm:"default:false"`
	TwoFactorAuth    bool        `json:"two_factor_auth" gorm:"default:false"`
	LastLogin        *time.Time  `json:"last_login"`
	LoginAttempts    int         `json:"login_attempts" gorm:"default:0"`
	LastAttempt      time.Time   `json:"last_attempt"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	TwoFactorEnabled bool        `json:"two_factor_enabled"`
	TwoFactorSecret  string      `json:"-"`
	Roles            []string    `json:"roles" gorm:"-"`
}

// 扩展 AccountAuth
type AccountAuth struct {
	db                 *gorm.DB
	maxLoginAttempts   int
	loginLockDuration  time.Duration
	verificationExpiry time.Duration
	emailService       EmailService
	redis              RedisStore
}

// EmailService 邮件服务接口
type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
	SendLoginNotificationEmail(email, ip string) error
}

// 配置选项
type AccountAuthConfig struct {
	MaxLoginAttempts   int
	LoginLockDuration  time.Duration
	VerificationExpiry time.Duration
	EmailService       EmailService
}

// NewAccountAuth 创建账户认证实例
func NewAccountAuth(db *gorm.DB, config AccountAuthConfig) *AccountAuth {
	return &AccountAuth{
		db:                 db,
		maxLoginAttempts:   config.MaxLoginAttempts,
		loginLockDuration:  config.LoginLockDuration,
		verificationExpiry: config.VerificationExpiry,
		emailService:       config.EmailService,
	}
}

// AutoMigrate 自动迁移数据库表结构
func (a *AccountAuth) AutoMigrate() error {
	// 确保先注册UserRole类型
	if err := a.db.AutoMigrate(
		&User{},
		&Session{},
		&LoginAttempt{},
		&Verification{},
		&UserRoleMapping{},
	); err != nil {
		return err
	}

	return nil
}

// 生成验证令牌
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// InitiatePasswordReset 发起密码重置
func (a *AccountAuth) InitiatePasswordReset(email string) (string, error) {
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	// 生成重置令牌
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	// 创建验证记录
	verification := &Verification{
		UserID:    user.ID,
		Type:      VerificationTypePassword,
		Token:     token,
		ExpiresAt: time.Now().Add(a.verificationExpiry),
		CreatedAt: time.Now(),
	}

	if err := a.db.Create(verification).Error; err != nil {
		return "", err
	}

	// 发送重置邮件
	if err := a.emailService.SendPasswordResetEmail(email, token); err != nil {
		return "", err
	}

	return token, nil
}

// CompletePasswordReset 完成密码重置
func (a *AccountAuth) CompletePasswordReset(token, newPassword string) error {
	var verification Verification
	if err := a.db.Where("token = ? AND type = ? AND expires_at > ?",
		token, VerificationTypePassword, time.Now()).First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidToken("Password reset token not found or expired")
		}
		return err
	}

	// 验证新密码强度
	if len(newPassword) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}

	// 更新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 使用事务更新密码并删除验证记录
	return a.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", verification.UserID).
			Update("password", string(hashedPassword)).Error; err != nil {
			return err
		}

		return tx.Delete(&verification).Error
	})
}

// SendVerificationEmail 发送验证邮件
func (a *AccountAuth) SendVerificationEmail(userID uint) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	if user.Verified {
		return errors.New("user already verified")
	}

	token, err := generateToken()
	if err != nil {
		return err
	}

	verification := &Verification{
		UserID:    user.ID,
		Type:      VerificationTypeEmail,
		Token:     token,
		ExpiresAt: time.Now().Add(a.verificationExpiry),
		CreatedAt: time.Now(),
	}

	if err := a.db.Create(verification).Error; err != nil {
		return err
	}

	return a.emailService.SendVerificationEmail(user.Email, token)
}

// VerifyEmail 验证邮箱
func (a *AccountAuth) VerifyEmail(token string) error {
	var verification Verification
	if err := a.db.Where("token = ? AND type = ? AND expires_at > ?",
		token, VerificationTypeEmail, time.Now()).First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidToken("Email verification token not found or expired")
		}
		return err
	}

	return a.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", verification.UserID).
			Update("verified", true).Error; err != nil {
			return err
		}

		return tx.Delete(&verification).Error
	})
}

// AssignRole 分配角色
func (a *AccountAuth) AssignRole(userID uint, role UserRole) error {
	// 先获取用户
	var user User
	if err := a.db.First(&user, userID).Error; err != nil {
		return err
	}

	// 创建角色映射记录
	roleMapping := &UserRoleMapping{
		UserID:    userID,
		Role:      string(role), // 将 UserRole 转换为字符串
		CreatedAt: time.Now(),
	}

	// 明确指定表名来避免GORM的类型处理问题
	return a.db.Table("user_role_mappings").Create(roleMapping).Error
}

// RemoveRole 移除角色
func (a *AccountAuth) RemoveRole(userID uint, role UserRole) error {
	return a.db.Where("user_id = ? AND role = ?", userID, string(role)).
		Delete(&UserRoleMapping{}).Error
}

// GetUserRoles 获取用户角色
func (a *AccountAuth) GetUserRoles(userID uint) ([]UserRole, error) {
	var mappings []UserRoleMapping
	if err := a.db.Where("user_id = ?", userID).Find(&mappings).Error; err != nil {
		return nil, err
	}

	roles := make([]UserRole, len(mappings))
	for i, mapping := range mappings {
		roles[i] = UserRole(mapping.Role)
	}
	return roles, nil
}

// RecordLoginAttempt 记录登录尝试
func (a *AccountAuth) RecordLoginAttempt(userID uint, ip string, success bool) error {
	attempt := &LoginAttempt{
		UserID:    userID,
		IP:        ip,
		Success:   success,
		CreatedAt: time.Now(),
	}
	return a.db.Create(attempt).Error
}

// CheckLoginAttempts 检查登录尝试次数
func (a *AccountAuth) CheckLoginAttempts(userID uint, ip string) error {
	var count int64
	if err := a.db.Model(&LoginAttempt{}).
		Where("user_id = ? AND ip = ? AND success = ? AND created_at > ?",
			userID, ip, false, time.Now().Add(-a.loginLockDuration)).
		Count(&count).Error; err != nil {
		return err
	}

	if count >= int64(a.maxLoginAttempts) {
		return NewAppError(ErrCodeTooManyRequests, "Too many login attempts", nil)
	}
	return nil
}

// Login 用户登录
func (a *AccountAuth) Login(username, password string) (*User, error) {
	var user User
	if err := a.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("Invalid username or password")
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("Invalid username or password")
	}

	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// CreateUser 创建新用户
func (a *AccountAuth) CreateUser(user *User) error {
	// 检查用户名是否已存在
	var count int64
	if err := a.db.Model(&User{}).Where("username = ?", user.Username).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrUsernameTaken("Username already taken")
	}

	// 检查邮箱是否已存在（如果提供了邮箱）
	if user.Email != "" {
		if err := a.db.Model(&User{}).Where("email = ?", user.Email).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrEmailTaken("Email already taken")
		}
	}

	// 如果是本地用户（非第三方登录），需要加密密码
	if user.Provider == "local" && user.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.Password = string(hashedPassword)
	}

	// 设置创建时间和更新时间
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	return a.db.Create(user).Error
}

// UpdateUser 更新用户信息
func (a *AccountAuth) UpdateUser(user *User) error {
	user.UpdatedAt = time.Now()
	return a.db.Save(user).Error
}

// GetUserByID 通过ID获取用户
func (a *AccountAuth) GetUserByID(id uint) (*User, error) {
	var user User
	if err := a.db.First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail 通过邮箱获取用户
func (a *AccountAuth) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := a.db.Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername 通过用户名获取用户
func (a *AccountAuth) GetUserByUsername(username string) (*User, error) {
	var user User
	if err := a.db.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByWeixinID 通过微信UnionID获取用户
func (a *AccountAuth) GetUserByWeixinID(weixinID string) (*User, error) {
	var user User
	if err := a.db.Where("social_id = ? AND provider = ?", weixinID, "weixin").First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	return &user, nil
}

// UpdateProfile 更新用户档案
func (a *AccountAuth) UpdateProfile(userID uint, updates map[string]interface{}) error {
	// 检查用户是否存在
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// 检查用户名是否已被占用
	if username, ok := updates["username"]; ok && username != user.Username {
		var count int64
		if err := a.db.Model(&User{}).Where("username = ?", username).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrUsernameTaken("Username already taken")
		}
	}

	// 检查邮箱是否已被占用
	if email, ok := updates["email"]; ok && email != user.Email {
		var count int64
		if err := a.db.Model(&User{}).Where("email = ?", email).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrEmailTaken("Email already taken")
		}
	}

	updates["updated_at"] = time.Now()
	return a.db.Model(user).Updates(updates).Error
}

// ChangePassword 修改用户密码
func (a *AccountAuth) ChangePassword(userID uint, oldPassword, newPassword string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return ErrInvalidPassword("Invalid old password")
	}

	// 验证新密码强度
	if len(newPassword) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return a.db.Model(user).Updates(map[string]interface{}{
		"password":   string(hashedPassword),
		"updated_at": time.Now(),
	}).Error
}

// CreateSession 创建新会话
func (a *AccountAuth) CreateSession(session *Session) error {
	return a.db.Create(session).Error
}

// GetSession 获取会话信息
func (a *AccountAuth) GetSession(sessionID string) (*Session, error) {
	var session Session
	if err := a.db.Where("id = ?", sessionID).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidSession
		}
		return nil, err
	}
	return &session, nil
}

// DeleteSession 删除会话
func (a *AccountAuth) DeleteSession(sessionID string) error {
	return a.db.Where("id = ?", sessionID).Delete(&Session{}).Error
}

// CleanExpiredSessions 清理过期会话
func (a *AccountAuth) CleanExpiredSessions() error {
	return a.db.Where("expires_at < ?", time.Now()).Delete(&Session{}).Error
}

// Register 用户注册
func (a *AccountAuth) Register(username, password, email string) error {
	if err := a.CheckDuplicateUsername(username); err != nil {
		return err
	}

	if err := a.CheckDuplicateEmail(email); err != nil {
		return err
	}

	if err := a.ValidatePassword(password); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	user := &User{
		Username: username,
		Password: string(hashedPassword),
		Email:    email,
		Status:   UserStatusActive,
	}

	if err := a.db.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	return nil
}

// GetTempTwoFactorSecret 获取临时的双因素认证密钥
func (a *AccountAuth) GetTempTwoFactorSecret(userID uint) (string, error) {
	var secret string
	err := a.db.Model(&User{}).
		Where("id = ?", userID).
		Pluck("two_factor_secret", &secret).
		Error
	if err != nil {
		return "", fmt.Errorf("failed to get temporary 2FA secret: %v", err)
	}
	return secret, nil
}

// EnableTwoFactor 启用双因素认证
func (a *AccountAuth) EnableTwoFactor(userID uint, secret string) error {
	return a.db.Model(&User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"two_factor_enabled": true,
			"two_factor_secret":  secret,
		}).Error
}

// DisableTwoFactor 禁用双因素认证
func (a *AccountAuth) DisableTwoFactor(userID uint) error {
	return a.db.Model(&User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"two_factor_enabled": false,
			"two_factor_secret":  "",
		}).Error
}

// SaveBackupCodes 保存备份码
func (a *AccountAuth) SaveBackupCodes(userID uint, codes []string) error {
	// 将备份码存储在Redis中
	key := fmt.Sprintf("2fa:backup:%d", userID)
	return a.redis.Set(key, codes, 0)
}

// GetBackupCodes 获取备份码
func (a *AccountAuth) GetBackupCodes(userID uint) ([]string, error) {
	key := fmt.Sprintf("2fa:backup:%d", userID)
	var codes []string
	err := a.redis.Get(key, &codes)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup codes: %v", err)
	}
	return codes, nil
}

// ValidateToken 验证令牌
func (a *AccountAuth) ValidateToken(token string) error {
	if token == "" {
		return ErrInvalidToken("Token cannot be empty")
	}
	return nil
}

// ValidatePassword 验证密码
func (a *AccountAuth) ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}
	return nil
}

// CheckDuplicateUsername 检查用户名是否重复
func (a *AccountAuth) CheckDuplicateUsername(username string) error {
	var count int64
	if err := a.db.Model(&User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Username already taken")
	}
	return nil
}

// CheckDuplicateEmail 检查邮箱是否重复
func (a *AccountAuth) CheckDuplicateEmail(email string) error {
	var count int64
	if err := a.db.Model(&User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Email already taken")
	}
	return nil
}

// CleanExpiredVerifications 清理过期的验证记录
func (a *AccountAuth) CleanExpiredVerifications() error {
	return a.db.Where("expires_at < ?", time.Now()).Delete(&Verification{}).Error
}

// CleanOldLoginAttempts 清理旧的登录尝试记录
func (a *AccountAuth) CleanOldLoginAttempts() error {
	// 删除7天前的登录尝试记录
	return a.db.Where("created_at < ?", time.Now().AddDate(0, 0, -7)).Delete(&LoginAttempt{}).Error
}

// FindOrCreateUserByOAuth 根据社交登录信息查找或创建用户
func (a *AccountAuth) FindOrCreateUserByOAuth(ctx interface{}, provider, socialID, email, name, picture string) (*User, error) {
	// 首先尝试通过社交ID查找用户
	var user User
	err := a.db.Where("provider = ? AND social_id = ?", provider, socialID).First(&user).Error

	// 如果找到了用户，更新信息并返回
	if err == nil {
		// 更新用户信息
		updates := map[string]interface{}{
			"last_login": time.Now(),
		}

		// 如果邮箱不存在但提供了邮箱，则更新
		if user.Email == "" && email != "" {
			updates["email"] = email
		}

		// 更新用户资料
		if name != "" {
			updates["profile"] = UserProfile{
				Nickname: name,
				Avatar:   picture,
			}
		}

		a.db.Model(&user).Updates(updates)

		// 获取用户角色
		var mappings []UserRoleMapping
		if err := a.db.Where("user_id = ?", user.ID).Find(&mappings).Error; err == nil {
			roles := make([]string, len(mappings))
			for i, mapping := range mappings {
				roles[i] = mapping.Role
			}
			user.Roles = roles
		}

		return &user, nil
	}

	// 如果未找到用户，尝试通过邮箱查找
	if email != "" {
		err = a.db.Where("email = ?", email).First(&user).Error
		if err == nil {
			// 找到了具有相同邮箱的用户，更新社交登录信息
			updates := map[string]interface{}{
				"provider":   provider,
				"social_id":  socialID,
				"last_login": time.Now(),
			}

			if name != "" {
				updates["profile"] = UserProfile{
					Nickname: name,
					Avatar:   picture,
				}
			}

			a.db.Model(&user).Updates(updates)

			// 获取用户角色
			var mappings []UserRoleMapping
			if err := a.db.Where("user_id = ?", user.ID).Find(&mappings).Error; err == nil {
				roles := make([]string, len(mappings))
				for i, mapping := range mappings {
					roles[i] = mapping.Role
				}
				user.Roles = roles
			}

			return &user, nil
		}
	}

	// 如果还是没找到，创建新用户
	username := fmt.Sprintf("%s_%s", provider, socialID[:8])
	// 检查用户名是否已存在
	var count int64
	a.db.Model(&User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		// 如果已存在，添加随机后缀
		b := make([]byte, 4)
		rand.Read(b)
		username = fmt.Sprintf("%s_%s", username, hex.EncodeToString(b))
	}

	// 生成随机密码（用户不需要知道这个密码）
	randomPass := make([]byte, 16)
	rand.Read(randomPass)
	hashedPassword, _ := bcrypt.GenerateFromPassword(randomPass, bcrypt.DefaultCost)

	newUser := User{
		Username:  username,
		Email:     email,
		Password:  string(hashedPassword),
		Provider:  provider,
		SocialID:  socialID,
		Status:    "active",
		Verified:  true, // 社交登录用户默认验证通过
		LastLogin: func() *time.Time { now := time.Now(); return &now }(),
		Profile: UserProfile{
			Nickname: name,
			Avatar:   picture,
		},
		LastAttempt: time.Now(), // 设置最后尝试时间为当前时间，避免MySQL日期错误
		CreatedAt:   time.Now(), // 确保创建时间也设置
		UpdatedAt:   time.Now(), // 确保更新时间也设置
	}

	// 保存新用户
	tx := a.db.Begin()
	defer tx.Rollback() // 如果提交成功，这个回滚不会有效果；如果函数异常退出，确保回滚

	if err := tx.Create(&newUser).Error; err != nil {
		return nil, fmt.Errorf("创建用户失败: %w", err)
	}

	// 为新用户添加默认角色
	roleMapping := UserRoleMapping{
		UserID:    newUser.ID,
		Role:      string(RoleUser),
		CreatedAt: time.Now(),
	}

	if err := tx.Create(&roleMapping).Error; err != nil {
		return nil, fmt.Errorf("分配用户角色失败: %w", err)
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("保存用户数据失败: %w", err)
	}

	// 设置返回用户的角色
	newUser.Roles = []string{string(RoleUser)}

	return &newUser, nil
}
