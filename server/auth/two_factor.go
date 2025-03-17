package auth

import (
    "crypto/rand"
    "encoding/base32"
    "fmt"
    "strings"
    "errors"
    
    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
)

// TwoFactorConfig 双因素认证配置
type TwoFactorConfig struct {
    Issuer      string        // 发行方名称
    Period      uint          // TOTP 周期（默认30秒）
    Digits      otp.Digits    // TOTP 位数（默认6位）
    Algorithm   otp.Algorithm // 使用的算法（默认SHA1）
    SecretSize  uint          // 密钥长度（默认20字节）
    WindowSize  uint          // 验证窗口大小（默认1，即前后1个周期）
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
    auth   *AccountAuth
}

// NewTwoFactorAuth 创建双因素认证服务实例
func NewTwoFactorAuth(config *TwoFactorConfig, auth *AccountAuth) *TwoFactorAuth {
    return &TwoFactorAuth{
        config: config,
        auth:   auth,
    }
}

// GenerateSecret 生成新的TOTP密钥
func (t *TwoFactorAuth) GenerateSecret(userID uint) (*otp.Key, error) {
    // 获取用户信息
    user, err := t.auth.GetUserByID(userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user: %v", err)
    }

    // 生成TOTP密钥
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      t.config.Issuer,
        AccountName: user.Email,
        Period:      t.config.Period,
        Digits:      t.config.Digits,
        Algorithm:   t.config.Algorithm,
        SecretSize:  t.config.SecretSize,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to generate TOTP key: %v", err)
    }

    return key, nil
}

// EnableTwoFactor 启用双因素认证
func (t *TwoFactorAuth) EnableTwoFactor(userID uint, code string) error {
    // 获取用户的临时密钥
    tempSecret, err := t.auth.GetTempTwoFactorSecret(userID)
    if err != nil {
        return fmt.Errorf("failed to get temporary secret: %v", err)
    }

    // 验证代码
    if !t.ValidateCode(tempSecret, code) {
        return errors.New("invalid verification code")
    }

    // 启用双因素认证
    if err := t.auth.EnableTwoFactor(userID, tempSecret); err != nil {
        return fmt.Errorf("failed to enable 2FA: %v", err)
    }

    // 生成备份码
    backupCodes, err := t.GenerateBackupCodes()
    if err != nil {
        return fmt.Errorf("failed to generate backup codes: %v", err)
    }

    // 保存备份码
    if err := t.auth.SaveBackupCodes(userID, backupCodes); err != nil {
        return fmt.Errorf("failed to save backup codes: %v", err)
    }

    return nil
}

// DisableTwoFactor 禁用双因素认证
func (t *TwoFactorAuth) DisableTwoFactor(userID uint, code string) error {
    // 获取用户信息
    user, err := t.auth.GetUserByID(userID)
    if err != nil {
        return fmt.Errorf("failed to get user: %v", err)
    }

    // 验证代码
    if !t.ValidateCode(user.TwoFactorSecret, code) {
        return errors.New("invalid verification code")
    }

    // 禁用双因素认证
    return t.auth.DisableTwoFactor(userID)
}

// ValidateCode 验证TOTP代码
func (t *TwoFactorAuth) ValidateCode(secret, code string) bool {
    return totp.Validate(code, secret)
}

// ValidateBackupCode 验证备份码
func (t *TwoFactorAuth) ValidateBackupCode(userID uint, code string) bool {
    // 获取用户的备份码
    codes, err := t.auth.GetBackupCodes(userID)
    if err != nil {
        return false
    }

    // 验证备份码
    for i, storedCode := range codes {
        if storedCode == code {
            // 使用后删除备份码
            codes = append(codes[:i], codes[i+1:]...)
            t.auth.SaveBackupCodes(userID, codes)
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
            return nil, fmt.Errorf("failed to generate random bytes: %v", err)
        }
        // 转换为base32编码并取前10位
        code := strings.ToUpper(base32.StdEncoding.EncodeToString(b))[:10]
        codes[i] = code
    }
    return codes, nil
}

// VerifyTwoFactor 验证双因素认证
func (t *TwoFactorAuth) VerifyTwoFactor(userID uint, code string) error {
    // 获取用户信息
    user, err := t.auth.GetUserByID(userID)
    if err != nil {
        return fmt.Errorf("failed to get user: %v", err)
    }

    // 检查是否启用了双因素认证
    if !user.TwoFactorEnabled {
        return errors.New("two-factor authentication not enabled")
    }

    // 先尝试验证TOTP代码
    if t.ValidateCode(user.TwoFactorSecret, code) {
        return nil
    }

    // 如果TOTP验证失败，尝试验证备份码
    if t.ValidateBackupCode(userID, code) {
        return nil
    }

    return errors.New("invalid verification code")
}

// GenerateRecoveryCodes 生成新的恢复码
func (t *TwoFactorAuth) GenerateRecoveryCodes(userID uint, currentCode string) ([]string, error) {
    // 获取用户信息
    user, err := t.auth.GetUserByID(userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user: %v", err)
    }

    // 验证当前TOTP代码
    if !t.ValidateCode(user.TwoFactorSecret, currentCode) {
        return nil, errors.New("invalid verification code")
    }

    // 生成新的备份码
    codes, err := t.GenerateBackupCodes()
    if err != nil {
        return nil, err
    }

    // 保存新的备份码
    if err := t.auth.SaveBackupCodes(userID, codes); err != nil {
        return nil, err
    }

    return codes, nil
} 