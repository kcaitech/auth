package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// PhoneUser 手机用户模型
type PhoneUser struct {
	UserID    string    `json:"user_id" gorm:"primarykey"`     // 关联到 User 表的用户ID
	Phone     string    `json:"phone" gorm:"unique"`           // 手机号，作为登录凭证
	Verified  bool      `json:"verified" gorm:"default:false"` // 手机号是否已验证
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SMSService 短信服务接口
type SMSService interface {
	SendVerificationSMS(phone, code string) error
	SendPasswordResetSMS(phone, code string) error
	SendLoginNotificationSMS(phone, ip string) error
}

// 验证类型
const (
	VerificationTypePhone      VerificationType = "phone"       // 新增：手机验证类型
	VerificationTypePhoneReset VerificationType = "phone_reset" // 手机密码重置
)

// PhoneAuth 手机认证结构体
type PhoneAuth struct {
	db                 *gorm.DB
	verificationExpiry time.Duration
	smsService         SMSService
	redis              *AccountRedisStore
}

// PhoneAuthConfig 手机认证配置
type PhoneAuthConfig struct {
	VerificationExpiry time.Duration
	SMSService         SMSService
	Redis              *AccountRedisStore
}

// NewPhoneAuth 创建手机认证实例
func NewPhoneAuth(db *gorm.DB, config PhoneAuthConfig) *PhoneAuth {
	return &PhoneAuth{
		db:                 db,
		verificationExpiry: config.VerificationExpiry,
		smsService:         config.SMSService,
		redis:              config.Redis,
	}
}

// AutoMigrate 自动迁移数据库表结构
func (a *PhoneAuth) AutoMigrate() error {
	if err := a.db.AutoMigrate(
		&User{},
		&PhoneUser{},
	); err != nil {
		return err
	}
	return nil
}

// 生成验证码
func generateVerificationCode() (string, error) {
	// 生成6位随机数字验证码
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// 格式化为6位数字，不足前面补0
	return fmt.Sprintf("%06d", n), nil
}

// InitiatePasswordReset 发起密码重置
func (a *PhoneAuth) InitiatePasswordReset(phone string) (string, error) {
	user, err := a.GetUserByPhone(phone)
	if err != nil {
		return "", err
	}

	// 生成验证码
	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	// 将验证记录存储到Redis中并设置过期时间
	if err := a.redis.StoreVerification(VerificationTypePhoneReset, code, user.UserID, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("存储手机密码重置验证信息失败: %w", err)
	}

	// 发送重置短信
	if err := a.smsService.SendPasswordResetSMS(phone, code); err != nil {
		return "", err
	}

	return code, nil
}

// CompletePasswordReset 完成密码重置
func (a *PhoneAuth) CompletePasswordReset(code, phone, newPassword string) error {
	// 从Redis获取验证记录
	verification, err := a.redis.GetVerification(VerificationTypePhoneReset, code)
	if err != nil {
		return ErrInvalidToken("验证码无效或已过期")
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

	// 使用完验证码后删除
	return a.redis.DeleteVerification(VerificationTypePhoneReset, code)
}

// SendVerificationSMS 发送验证短信
func (a *PhoneAuth) SendVerificationSMS(userID string) error {
	// 查询 PhoneUser 记录
	var phoneUser PhoneUser
	if err := a.db.Where("user_id = ?", userID).First(&phoneUser).Error; err != nil {
		return err
	}

	if phoneUser.Verified {
		return errors.New("用户手机号已经验证过")
	}

	code, err := generateVerificationCode()
	if err != nil {
		return err
	}

	// 将验证记录存储到Redis中
	if err := a.redis.StoreVerification(VerificationTypePhone, code, userID, a.verificationExpiry); err != nil {
		return fmt.Errorf("存储手机验证信息失败: %w", err)
	}

	// 发送验证短信
	return a.smsService.SendVerificationSMS(phoneUser.Phone, code)
}

// VerifyPhone 验证手机号
func (a *PhoneAuth) VerifyPhone(code string) error {
	// 从Redis获取验证记录
	verification, err := a.redis.GetVerification(VerificationTypePhone, code)
	if err != nil {
		return ErrInvalidToken("验证码无效或已过期")
	}

	// 更新PhoneUser记录
	result := a.db.Model(&PhoneUser{}).Where("user_id = ?", verification.UserID).
		Update("verified", true)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrInvalidToken("无效的用户ID")
	}

	// 使用完验证码后删除
	return a.redis.DeleteVerification(VerificationTypePhone, code)
}

// PhoneLogin 使用手机号登录
func (a *PhoneAuth) PhoneLogin(phone, password string) (*User, error) {
	// 查找手机用户记录
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials("无效的手机号码或密码")
		}
		return nil, err
	}

	// 检查手机号是否已验证
	if !phoneUser.Verified {
		return nil, ErrEmailNotVerified("手机号未验证，请先验证手机号")
	}

	// 通过userID获取User记录
	var user User
	if err := a.db.Where("user_id = ?", phoneUser.UserID).First(&user).Error; err != nil {
		return nil, err
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials("无效的手机号码或密码")
	}

	// 更新最后登录时间
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByPhone 通过手机号获取用户
func (a *PhoneAuth) GetUserByPhone(phone string) (*User, error) {
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound("未找到手机号对应的用户")
		}
		return nil, err
	}

	var user User
	if err := a.db.Where("user_id = ?", phoneUser.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound("未找到用户")
		}
		return nil, err
	}

	return &user, nil
}

// CheckDuplicatePhone 检查手机号是否已被使用
func (a *PhoneAuth) CheckDuplicatePhone(phone string) error {
	var count int64
	if err := a.db.Model(&PhoneUser{}).Where("phone = ?", phone).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrPhoneTaken("该手机号已被注册")
	}
	return nil
}

// RegisterPhoneUser 注册手机用户
func (a *PhoneAuth) RegisterPhoneUser(phone, password, nickname string) (*User, error) {
	// 检查手机号格式（这里简单示例，实际应该使用正则或其他方式进行严格验证）
	if len(phone) < 11 {
		return nil, ErrInvalidPhoneFormat("无效的手机号格式")
	}

	// 检查手机号是否已被使用
	if err := a.CheckDuplicatePhone(phone); err != nil {
		return nil, err
	}

	// 验证密码强度
	if len(password) < 8 {
		return nil, ErrWeakPassword("密码至少需要8个字符")
	}

	// 创建事务
	tx := a.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	// 如果发生错误则回滚事务
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 生成随机用户ID (使用手机号作为前缀)
	userID, err := GenerateBase62ID()
	if err != nil {
		return nil, fmt.Errorf("生成随机ID失败: %v", err)
	}
	// 确保UserID唯一
	for {
		var count int64
		a.db.Model(&User{}).Where("user_id = ?", userID).Count(&count) // todo 这也不对，没有在事务中检查
		if count == 0 {
			break
		}
		// 生成新的UserID
		userID, err = GenerateBase62ID()
		if err != nil {
			return nil, fmt.Errorf("生成随机ID失败: %v", err)
		}
	}
	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// 创建 User 记录
	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: string(hashedPassword),
		Status:   UserStatusActive,
		Profile: UserProfile{
			Nickname: nickname,
			Phone:    phone, // 同时设置手机号到Profile
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// 创建 PhoneUser 记录
	phoneUser := &PhoneUser{
		UserID:    userID,
		Phone:     phone,
		Verified:  false, // 需要验证
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(phoneUser).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return user, nil
}

// PhoneCodeLogin 手机验证码登录（不需要密码）
func (a *PhoneAuth) PhoneCodeLogin(phone, code string) (*User, error) {
	// 从Redis获取验证记录
	verification, err := a.redis.GetVerification(VerificationTypePhone, code)
	if err != nil {
		return nil, ErrInvalidToken("验证码无效或已过期")
	}

	// 查找手机用户记录
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ? AND user_id = ?", phone, verification.UserID).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials("无效的手机号码或验证码")
		}
		return nil, err
	}

	// 通过userID获取User记录
	var user User
	if err := a.db.Where("user_id = ?", phoneUser.UserID).First(&user).Error; err != nil {
		return nil, err
	}

	// 如果手机号未验证，则现在将其设为已验证
	if !phoneUser.Verified {
		phoneUser.Verified = true
		if err := a.db.Save(&phoneUser).Error; err != nil {
			return nil, err
		}
	}

	// 更新最后登录时间
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	// 使用完验证码后删除
	_ = a.redis.DeleteVerification(VerificationTypePhone, code)

	return &user, nil
}

// SendLoginSMS 发送登录验证码
func (a *PhoneAuth) SendLoginSMS(phone string) (string, error) {
	// 检查手机号是否已注册
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrUserNotFound("该手机号码未注册")
		}
		return "", err
	}

	// 生成验证码
	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	// 将验证记录存储到Redis中并设置过期时间(5分钟)
	verificationExpiry := 5 * time.Minute
	if err := a.redis.StoreVerification(VerificationTypePhone, code, phoneUser.UserID, verificationExpiry); err != nil {
		return "", fmt.Errorf("存储手机登录验证信息失败: %w", err)
	}

	// 发送验证码短信
	if err := a.smsService.SendVerificationSMS(phone, code); err != nil {
		return "", err
	}

	return code, nil
}

// ValidatePhoneFormat 验证手机号格式
func (a *PhoneAuth) ValidatePhoneFormat(phone string) error {
	// 这里仅做简单示例，实际应根据不同国家/地区的手机号规则进行严格验证
	if len(phone) < 11 {
		return ErrInvalidPhoneFormat("无效的手机号格式")
	}
	return nil
}
