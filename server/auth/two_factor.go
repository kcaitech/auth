package auth

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

// TwoFactorData 双因素认证数据
type TwoFactorData struct {
	UserID          string    `json:"user_id" gorm:"primarykey"`    // 关联到 User 表的 UserID
	Secret          string    `json:"secret" gorm:"size:100"`       // TOTP 密钥
	Enabled         bool      `json:"enabled" gorm:"default:false"` // 是否启用
	BackupCodes     string    `json:"-" gorm:"type:text"`           // 备份码（JSON格式存储）
	TempSecret      string    `json:"-" gorm:"size:100"`            // 临时密钥（等待验证）
	LastVerified    time.Time `json:"last_verified"`                // 最后验证时间
	SecretUpdatedAt time.Time `json:"secret_updated_at"`            // 密钥更新时间
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// TwoFactorConfig 双因素认证配置
type TwoFactorConfig struct {
	Issuer     string        // 发行方名称
	Period     uint          // TOTP 周期（默认30秒）
	Digits     otp.Digits    // TOTP 位数（默认6位）
	Algorithm  otp.Algorithm // 使用的算法（默认SHA1）
	SecretSize uint          // 密钥长度（默认20字节）
	WindowSize uint          // 验证窗口大小（默认1，即前后1个周期）
	RedisStore *RedisStore   // Redis存储（可选，用于临时存储）
}

// NewDefaultTwoFactorConfig 创建默认配置
func NewDefaultTwoFactorConfig(issuer string) *TwoFactorConfig {
	return &TwoFactorConfig{
		Issuer:     issuer,
		Period:     30,
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
		SecretSize: 20,
		WindowSize: 1,
	}
}

// TwoFactorAuth 双因素认证服务
type TwoFactorAuth struct {
	config *TwoFactorConfig
	db     *gorm.DB
	redis  *RedisStore
}

// NewTwoFactorAuth 创建双因素认证服务实例
func NewTwoFactorAuth(db *gorm.DB, config *TwoFactorConfig) *TwoFactorAuth {
	return &TwoFactorAuth{
		config: config,
		db:     db,
		redis:  config.RedisStore,
	}
}

// AutoMigrate 自动迁移数据库结构
func (t *TwoFactorAuth) AutoMigrate() error {
	return t.db.AutoMigrate(&TwoFactorData{})
}

// GetUserTwoFactorData 获取用户的2FA数据
func (t *TwoFactorAuth) GetUserTwoFactorData(userID string) (*TwoFactorData, error) {
	var data TwoFactorData
	err := t.db.Where("user_id = ?", userID).First(&data).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 如果记录不存在，则创建一个新记录
			data = TwoFactorData{
				UserID:    userID,
				Enabled:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			if err := t.db.Create(&data).Error; err != nil {
				return nil, fmt.Errorf("创建2FA记录失败: %v", err)
			}
			return &data, nil
		}
		return nil, fmt.Errorf("获取2FA数据失败: %v", err)
	}
	return &data, nil
}

// GenerateSecret 生成新的TOTP密钥
func (t *TwoFactorAuth) GenerateSecret(userID string, accountName string) (*otp.Key, error) {
	// 检查用户是否存在
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return nil, err
	}

	// 生成TOTP密钥
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.config.Issuer,
		AccountName: accountName,
		Period:      t.config.Period,
		Digits:      t.config.Digits,
		Algorithm:   t.config.Algorithm,
		SecretSize:  t.config.SecretSize,
	})
	if err != nil {
		return nil, fmt.Errorf("生成TOTP密钥失败: %v", err)
	}

	// 保存临时密钥
	data.TempSecret = key.Secret()
	data.UpdatedAt = time.Now()
	if err := t.db.Save(data).Error; err != nil {
		return nil, fmt.Errorf("保存临时密钥失败: %v", err)
	}

	return key, nil
}

// EnableTwoFactor 启用双因素认证
func (t *TwoFactorAuth) EnableTwoFactor(userID string, code string) error {
	// 获取用户2FA数据
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// 检查是否已有临时密钥
	if data.TempSecret == "" {
		return errors.New("未找到临时密钥，请先生成密钥")
	}

	// 验证代码
	if !t.ValidateCode(data.TempSecret, code) {
		return errors.New("无效的验证码")
	}

	// 生成备份码
	backupCodes, err := t.GenerateBackupCodes()
	if err != nil {
		return fmt.Errorf("生成备份码失败: %v", err)
	}

	// 将备份码存储为JSON
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return fmt.Errorf("序列化备份码失败: %v", err)
	}

	// 启用双因素认证
	data.Secret = data.TempSecret
	data.TempSecret = ""
	data.Enabled = true
	data.BackupCodes = string(backupCodesJSON)
	data.SecretUpdatedAt = time.Now()
	data.LastVerified = time.Now()
	data.UpdatedAt = time.Now()

	if err := t.db.Save(data).Error; err != nil {
		return fmt.Errorf("保存2FA数据失败: %v", err)
	}

	return nil
}

// DisableTwoFactor 禁用双因素认证
func (t *TwoFactorAuth) DisableTwoFactor(userID string, code string) error {
	// 获取用户2FA数据
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// 检查是否启用了2FA
	if !data.Enabled {
		return errors.New("双因素认证未启用")
	}

	// 验证代码
	validCode := t.ValidateCode(data.Secret, code)
	validBackup := t.ValidateBackupCode(userID, code)

	if !validCode && !validBackup {
		return errors.New("无效的验证码")
	}

	// 禁用双因素认证
	data.Enabled = false
	data.Secret = ""
	data.BackupCodes = ""
	data.UpdatedAt = time.Now()

	if err := t.db.Save(data).Error; err != nil {
		return fmt.Errorf("禁用2FA失败: %v", err)
	}

	return nil
}

// ValidateCode 验证TOTP代码
func (t *TwoFactorAuth) ValidateCode(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	return totp.Validate(code, secret)
}

// ParseBackupCodes 解析备份码
func (t *TwoFactorAuth) parseBackupCodes(userID string) ([]string, error) {
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return nil, err
	}

	if data.BackupCodes == "" {
		return []string{}, nil
	}

	var codes []string
	if err := json.Unmarshal([]byte(data.BackupCodes), &codes); err != nil {
		return nil, fmt.Errorf("解析备份码失败: %v", err)
	}

	return codes, nil
}

// ValidateBackupCode 验证备份码
func (t *TwoFactorAuth) ValidateBackupCode(userID string, code string) bool {
	// 获取用户的备份码
	codes, err := t.parseBackupCodes(userID)
	if err != nil || len(codes) == 0 {
		return false
	}

	// 验证备份码
	for i, storedCode := range codes {
		if storedCode == code {
			// 使用后删除备份码
			codes = append(codes[:i], codes[i+1:]...)

			// 将更新后的备份码保存回数据库
			codesJSON, err := json.Marshal(codes)
			if err != nil {
				return false
			}

			data, err := t.GetUserTwoFactorData(userID)
			if err != nil {
				return false
			}

			data.BackupCodes = string(codesJSON)
			data.UpdatedAt = time.Now()

			if err := t.db.Save(data).Error; err != nil {
				return false
			}

			return true
		}
	}

	return false
}

// GenerateBackupCodes 生成备份码
func (t *TwoFactorAuth) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 8) // 生成8个备份码
	for i := 0; i < 8; i++ {
		// 生成6字节的随机数据
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("生成随机字节失败: %v", err)
		}
		// 转换为base32编码并取前10位
		code := strings.ToUpper(base32.StdEncoding.EncodeToString(b))[:10]
		codes[i] = code
	}
	return codes, nil
}

// VerifyTwoFactor 验证双因素认证
func (t *TwoFactorAuth) VerifyTwoFactor(userID string, code string) error {
	// 获取用户2FA数据
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// 检查是否启用了双因素认证
	if !data.Enabled {
		return errors.New("双因素认证未启用")
	}

	// 先尝试验证TOTP代码
	if t.ValidateCode(data.Secret, code) {
		// 更新最后验证时间
		data.LastVerified = time.Now()
		data.UpdatedAt = time.Now()
		t.db.Save(data)
		return nil
	}

	// 如果TOTP验证失败，尝试验证备份码
	if t.ValidateBackupCode(userID, code) {
		// 更新最后验证时间
		data.LastVerified = time.Now()
		data.UpdatedAt = time.Now()
		t.db.Save(data)
		return nil
	}

	return errors.New("无效的验证码")
}

// GetBackupCodes 获取用户的备份码
func (t *TwoFactorAuth) GetBackupCodes(userID string) ([]string, error) {
	return t.parseBackupCodes(userID)
}

// GenerateRecoveryCodes 生成新的恢复码
func (t *TwoFactorAuth) GenerateRecoveryCodes(userID string, currentCode string) ([]string, error) {
	// 获取用户2FA数据
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return nil, err
	}

	// 检查是否启用了2FA
	if !data.Enabled {
		return nil, errors.New("双因素认证未启用")
	}

	// 验证当前TOTP代码
	if !t.ValidateCode(data.Secret, currentCode) {
		return nil, errors.New("无效的验证码")
	}

	// 生成新的备份码
	codes, err := t.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	// 将备份码存储为JSON
	codesJSON, err := json.Marshal(codes)
	if err != nil {
		return nil, fmt.Errorf("序列化备份码失败: %v", err)
	}

	// 更新数据库
	data.BackupCodes = string(codesJSON)
	data.UpdatedAt = time.Now()
	if err := t.db.Save(data).Error; err != nil {
		return nil, fmt.Errorf("保存备份码失败: %v", err)
	}

	return codes, nil
}

// IsTwoFactorEnabled 检查用户是否启用了双因素认证
func (t *TwoFactorAuth) IsTwoFactorEnabled(userID string) (bool, error) {
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return false, err
	}
	return data.Enabled, nil
}

// GetQRCodeURL 获取QR码URL
func (t *TwoFactorAuth) GetQRCodeURL(userID string) (string, error) {
	// 获取用户2FA数据
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return "", err
	}

	// 检查是否有临时密钥
	if data.TempSecret == "" {
		return "", errors.New("未找到临时密钥，请先生成密钥")
	}

	// 查询用户信息
	var user User
	if err := t.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return "", fmt.Errorf("获取用户信息失败: %v", err)
	}

	// 构造账户名称
	accountName := user.Profile.Nickname
	if accountName == "" {
		accountName = userID
	}

	// 生成OTP密钥对象
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		t.config.Issuer, accountName, data.TempSecret, t.config.Issuer))
	if err != nil {
		return "", fmt.Errorf("生成OTP密钥URL失败: %v", err)
	}

	return key.URL(), nil
}

// 使用Redis缓存临时状态（可选）
func (t *TwoFactorAuth) StoreTempSecretInRedis(userID string, secret string, duration time.Duration) error {
	if t.redis == nil {
		return errors.New("Redis未配置")
	}

	key := fmt.Sprintf("2fa:temp:%s", userID)
	return t.redis.Set(key, secret, duration)
}

func (t *TwoFactorAuth) GetTempSecretFromRedis(userID string) (string, error) {
	if t.redis == nil {
		return "", errors.New("Redis未配置")
	}

	key := fmt.Sprintf("2fa:temp:%s", userID)
	var secret string
	err := t.redis.Get(key, &secret)
	if err != nil {
		return "", err
	}
	return secret, nil
}
