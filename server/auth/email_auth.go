package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// EmailUser 邮箱用户模型
type EmailUser struct {
	UserID    string    `json:"user_id" gorm:"primarykey"`     // 关联到 User 表的用户ID
	Email     string    `json:"email" gorm:"unique"`           // 邮箱，作为登录凭证
	Verified  bool      `json:"verified" gorm:"default:false"` // 邮箱是否已验证
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 扩展 AccountAuth
type EmailAuth struct {
	db *gorm.DB
	// maxLoginAttempts   int
	// loginLockDuration  time.Duration
	verificationExpiry time.Duration
	emailService       EmailService
	redis              *AccountRedisStore
}

// EmailService 邮件服务接口
type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
	SendLoginNotificationEmail(email, ip string) error
}

// 配置选项
type EmailAutnConfig struct {
	VerificationExpiry time.Duration
	EmailService       EmailService
	Redis              *AccountRedisStore
}

func NewEmailAuth(db *gorm.DB, config EmailAutnConfig) *EmailAuth {
	return &EmailAuth{
		db:                 db,
		verificationExpiry: config.VerificationExpiry,
		emailService:       config.EmailService,
		redis:              config.Redis, // 直接使用指针
	}
}

// AutoMigrate 自动迁移数据库表结构
func (a *EmailAuth) AutoMigrate() error {
	if err := a.db.AutoMigrate(
		&User{},
		&EmailUser{},
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
func (a *EmailAuth) InitiatePasswordReset(email string) (string, error) {
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	// 生成重置令牌
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	// 将验证记录存储到Redis中并设置过期时间
	if err := a.redis.StoreVerification(VerificationTypePassword, token, user.UserID, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("存储密码重置验证信息失败: %w", err)
	}

	// 发送重置邮件
	if err := a.emailService.SendPasswordResetEmail(email, token); err != nil {
		return "", err
	}

	return token, nil
}

// CompletePasswordReset 完成密码重置
func (a *EmailAuth) CompletePasswordReset(token, newPassword string) error {
	// 从Redis获取验证记录
	verification, err := a.redis.GetVerification(VerificationTypePassword, token)
	if err != nil {
		return ErrInvalidToken("密码重置令牌无效或已过期")
	}

	// 验证新密码强度
	if len(newPassword) < 8 {
		return ErrWeakPassword("密码至少需要8个字符")
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 更新 User 表中的密码
	result := a.db.Model(&User{}).Where("user_id = ?", verification.UserID).
		Update("password", string(hashedPassword))

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrInvalidToken("无效的用户ID")
	}

	// 使用完令牌后删除
	return a.redis.DeleteVerification(VerificationTypePassword, token)
}

// SendVerificationEmail 发送验证邮件
func (a *EmailAuth) SendVerificationEmail(userID string) error {
	// 查询 EmailUser 记录
	var emailUser EmailUser
	if err := a.db.Where("user_id = ?", userID).First(&emailUser).Error; err != nil {
		return err
	}

	if emailUser.Verified {
		return errors.New("用户邮箱已经验证过")
	}

	token, err := generateToken()
	if err != nil {
		return err
	}

	// 将验证记录存储到Redis中并设置过期时间
	if err := a.redis.StoreVerification(VerificationTypeEmail, token, userID, a.verificationExpiry); err != nil {
		return fmt.Errorf("存储邮箱验证信息失败: %w", err)
	}

	return a.emailService.SendVerificationEmail(emailUser.Email, token)
}

// VerifyEmail 验证邮箱
func (a *EmailAuth) VerifyEmail(token string) error {
	// 从Redis获取验证记录
	verification, err := a.redis.GetVerification(VerificationTypeEmail, token)
	if err != nil {
		return ErrInvalidToken("邮箱验证令牌无效或已过期")
	}

	// 更新 EmailUser 验证状态
	result := a.db.Model(&EmailUser{}).Where("user_id = ?", verification.UserID).
		Update("verified", true)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrInvalidToken("无效的用户ID")
	}

	// 使用完令牌后删除
	return a.redis.DeleteVerification(VerificationTypeEmail, token)
}

// EmailLogin 邮箱用户登录
func (a *EmailAuth) EmailLogin(email, password string) (*User, error) {
	// 首先查询对应的邮箱用户
	var emailUser EmailUser
	err := a.db.Where("email = ?", email).First(&emailUser).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("无效的邮箱或密码")
		}
		return nil, err
	}

	// 检查邮箱是否已验证
	if !emailUser.Verified {
		return nil, ErrEmailNotVerified("邮箱尚未验证，请先验证邮箱")
	}

	// 通过 UserID 查询关联的 User 信息
	var user User
	if err := a.db.Where("user_id = ?", emailUser.UserID).First(&user).Error; err != nil {
		return nil, err
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("无效的邮箱或密码")
	}

	// 更新最后登录时间
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail 通过邮箱获取用户
func (a *EmailAuth) GetUserByEmail(email string) (*User, error) {
	// 先查询 EmailUser 记录
	var emailUser EmailUser
	if err := a.db.Where("email = ?", email).First(&emailUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "用户不存在", err)
		}
		return nil, err
	}

	// 再通过 UserID 查询 User 记录
	var user User
	if err := a.db.Where("user_id = ?", emailUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "用户不存在", err)
		}
		return nil, err
	}

	return &user, nil
}

// CheckDuplicateEmail 检查邮箱是否重复
func (a *EmailAuth) CheckDuplicateEmail(email string) error {
	var count int64
	if err := a.db.Model(&EmailUser{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("邮箱已被使用")
	}
	return nil
}

// RegisterEmailUser 邮箱用户注册
func (a *EmailAuth) RegisterEmailUser(email, password, nickname string) (string, error) {
	// 邮箱必须提供
	if email == "" {
		return "", ErrInvalidInput("必须提供有效邮箱")
	}

	// 检查邮箱是否重复
	if err := a.CheckDuplicateEmail(email); err != nil {
		return "", err
	}

	// 生成随机UserID
	b := make([]byte, 8)
	rand.Read(b)
	userID := fmt.Sprintf("u_%s", hex.EncodeToString(b))

	// 确保UserID唯一
	for {
		var count int64
		a.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// 生成新的UserID
		rand.Read(b)
		userID = fmt.Sprintf("u_%s", hex.EncodeToString(b))
	}

	// 如果没有提供昵称，使用邮箱前缀作为默认昵称
	if nickname == "" {
		parts := strings.Split(email, "@")
		nickname = parts[0]
	}

	// 验证密码强度
	if err := a.ValidatePassword(password); err != nil {
		return "", err
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码加密失败: %v", err)
	}

	// 开始事务
	tx := a.db.Begin()
	if tx.Error != nil {
		return "", tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 创建基本用户记录
	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: string(hashedPassword),
		Status:   UserStatusActive,
		Profile: UserProfile{
			Nickname: nickname,
		},
		LastAttempt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return "", fmt.Errorf("创建用户失败: %v", err)
	}

	// 创建邮箱用户关联记录
	emailUser := &EmailUser{
		UserID:    userID,
		Email:     email,
		Verified:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(emailUser).Error; err != nil {
		tx.Rollback()
		return "", fmt.Errorf("创建邮箱用户关联失败: %v", err)
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		return "", fmt.Errorf("保存数据失败: %v", err)
	}

	// 发送验证邮件
	if err := a.SendVerificationEmail(userID); err != nil {
		// 仅记录错误，不影响注册流程
		fmt.Printf("发送验证邮件失败: %v\n", err)
	}

	return userID, nil
}

// ValidatePassword 验证密码强度
func (a *EmailAuth) ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword("密码至少需要8个字符")
	}
	return nil
}
