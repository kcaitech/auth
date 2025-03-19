package auth

import (
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
	UserID    string `gorm:"primarykey"`
	IP        string `gorm:"size:45"`
	Success   bool
	CreatedAt time.Time
}

// User 用户模型
type User struct { // 系统自动生成的ID
	UserID        string      `json:"user_id" gorm:"primarykey"` // 登录标识符，对于普通账号即登录账号，邮箱账号则自动生成
	Password      string      `json:"-" gorm:"not null"`
	Status        UserStatus  `json:"status" gorm:"not null;default:'active'"`
	Profile       UserProfile `json:"profile" gorm:"embedded"`
	LastLogin     *time.Time  `json:"last_login"`
	LoginAttempts int         `json:"login_attempts" gorm:"default:0"`
	LastAttempt   *time.Time  `json:"last_attempt"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// 扩展 AccountAuth
type AccountAuth struct {
	db                *gorm.DB
	maxLoginAttempts  int
	loginLockDuration time.Duration
	redis             *AccountRedisStore // 使用 AccountRedisStore
}

// 配置选项
type AccountAuthConfig struct {
	MaxLoginAttempts  int
	LoginLockDuration time.Duration
	Redis             *AccountRedisStore // 使用 AccountRedisStore
}

// NewAccountAuth 创建账户认证实例
func NewAccountAuth(db *gorm.DB, config AccountAuthConfig) *AccountAuth {
	return &AccountAuth{
		db:                db,
		maxLoginAttempts:  config.MaxLoginAttempts,
		loginLockDuration: config.LoginLockDuration,
		redis:             config.Redis,
	}
}

// AutoMigrate 自动迁移数据库表结构
func (a *AccountAuth) AutoMigrate() error {
	// 确保先注册UserRole类型
	if err := a.db.AutoMigrate(
		&User{},
	); err != nil {
		return err
	}

	return nil
}

// RecordLoginAttempt 记录登录尝试
func (a *AccountAuth) RecordLoginAttempt(userID string, ip string, success bool) error {
	// 仅在登录失败时增加计数
	if !success {
		// 增加失败计数
		_, err := a.redis.IncrLoginAttempts(userID, ip, a.loginLockDuration)
		if err != nil {
			return fmt.Errorf("记录登录尝试失败: %w", err)
		}

		// 可以在此处记录登录失败的日志等
		return nil
	}

	// 如果登录成功，重置失败计数
	if success {
		return a.redis.ResetLoginAttempts(userID, ip)
	}

	return nil
}

// CheckLoginAttempts 检查登录尝试次数
func (a *AccountAuth) CheckLoginAttempts(userID string, ip string) error {
	// 获取指定用户IP的失败尝试次数
	count, err := a.redis.GetLoginAttempts(userID, ip)
	if err != nil {
		return fmt.Errorf("检查登录尝试次数失败: %w", err)
	}

	if count >= a.maxLoginAttempts {
		return NewAppError(ErrCodeTooManyRequests, "登录尝试次数过多，请稍后再试", nil)
	}

	return nil
}

// Login 用户登录
func (a *AccountAuth) Login(userID string, password string) (*User, error) {
	var user User

	// 尝试使用userID或邮箱登录
	err := a.db.Where("user_id = ?", userID).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("无效的账号密码")
		}
		return nil, err
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("无效的账号密码")
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
	// 检查UserID是否已存在
	var count int64
	if err := a.db.Model(&User{}).Where("user_id = ?", user.UserID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrUserIDTaken("账号ID已被使用")
	}

	// 需要加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	// 设置创建时间和更新时间
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	// user.LastAttempt = now

	return a.db.Create(user).Error
}

// UpdateUser 更新用户信息
func (a *AccountAuth) UpdateUser(user *User) error {
	user.UpdatedAt = time.Now()
	return a.db.Save(user).Error
}

// GetUserByID 通过ID获取用户
func (a *AccountAuth) GetUserByID(id string) (*User, error) {
	var user User
	if err := a.db.First(&user, "user_id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	return &user, nil
}

// UpdateProfile 更新用户档案
func (a *AccountAuth) UpdateProfile(userID string, updates map[string]interface{}) error {
	// 检查用户是否存在
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// 检查用户ID是否已被占用
	if newUserID, ok := updates["user_id"]; ok && newUserID != user.UserID {
		var count int64
		if err := a.db.Model(&User{}).Where("user_id = ?", newUserID).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrUserIDTaken("账号ID已被占用")
		}
	}

	updates["updated_at"] = time.Now()
	return a.db.Model(user).Updates(updates).Error
}

// ChangePassword 修改用户密码
func (a *AccountAuth) ChangePassword(userID string, oldPassword, newPassword string) error {
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

// Register 用户注册 (普通账号)
func (a *AccountAuth) Register(userID string, password string) error {

	if userID == "" {
		return ErrInvalidInput("普通账号必须提供账号ID")
	}

	// 检查UserID是否重复
	if err := a.CheckDuplicateUserID(userID); err != nil {
		return err
	}

	if err := a.ValidatePassword(password); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: string(hashedPassword),
		Status:   UserStatusActive,
		// LastAttempt: now,
		CreatedAt: now,
		UpdatedAt: now,
		Profile: UserProfile{
			Nickname: userID,
		},
	}

	if err := a.db.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	return nil
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
	return a.CheckDuplicateUserID(username)
}

// CleanExpiredVerifications 清理过期的验证记录
func (a *AccountAuth) CleanExpiredVerifications() error {
	// 使用Redis时不需要手动清理过期的验证记录，Redis会自动完成
	// 此方法保留以保持兼容性
	return nil
}

// GetUserByUserID 通过UserID获取用户
func (a *AccountAuth) GetUserByUserID(userID string) (*User, error) {
	var user User
	if err := a.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	return &user, nil
}

// CheckDuplicateUserID 检查UserID是否重复
func (a *AccountAuth) CheckDuplicateUserID(userID string) error {
	var count int64
	if err := a.db.Model(&User{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("账号ID已被使用")
	}
	return nil
}
