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

// TwoFactorData Two-factor authentication data
type TwoFactorData struct {
	UserID          string    `json:"user_id" gorm:"primarykey"`    // Associated with User table's UserID
	Secret          string    `json:"secret" gorm:"size:100"`       // TOTP secret key
	Enabled         bool      `json:"enabled" gorm:"default:false"` // Whether enabled
	BackupCodes     string    `json:"-" gorm:"type:text"`           // Backup codes (stored in JSON format)
	TempSecret      string    `json:"-" gorm:"size:100"`            // Temporary secret (waiting for verification)
	LastVerified    time.Time `json:"last_verified"`                // Last verification time
	SecretUpdatedAt time.Time `json:"secret_updated_at"`            // Secret update time
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// TwoFactorConfig Two-factor authentication configuration
type TwoFactorConfig struct {
	Issuer     string        // Issuer name
	Period     uint          // TOTP period (default 30 seconds)
	Digits     otp.Digits    // TOTP digits (default 6 digits)
	Algorithm  otp.Algorithm // Algorithm used (default SHA1)
	SecretSize uint          // Secret key length (default 20 bytes)
	WindowSize uint          // Verification window size (default 1, meaning 1 period before and after)
	RedisStore *RedisStore   // Redis storage (optional, used for temporary storage)
}

// NewDefaultTwoFactorConfig Create default configuration
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

// TwoFactorAuth Two-factor authentication service
type TwoFactorAuth struct {
	config *TwoFactorConfig
	db     *gorm.DB
	redis  *RedisStore
}

// NewTwoFactorAuth Create two-factor authentication service instance
func NewTwoFactorAuth(db *gorm.DB, config *TwoFactorConfig) *TwoFactorAuth {
	return &TwoFactorAuth{
		config: config,
		db:     db,
		redis:  config.RedisStore,
	}
}

// AutoMigrate Automatically migrate database structure
func (a *TwoFactorAuth) AutoMigrate() error {
	return a.db.AutoMigrate(&TwoFactorData{})
}

// GetUserTwoFactorData Get user's 2FA data
func (a *TwoFactorAuth) GetUserTwoFactorData(userID string) (*TwoFactorData, error) {
	var data TwoFactorData
	result := a.db.Where("user_id = ?", userID).First(&data)

	// If record doesn't exist, create a new one
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		now := time.Now()
		data = TwoFactorData{
			UserID:    userID,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := a.db.Create(&data).Error; err != nil {
			return nil, fmt.Errorf("failed to create 2FA record: %v", err)
		}
		return &data, nil
	} else if result.Error != nil {
		return nil, fmt.Errorf("failed to get 2FA data: %v", result.Error)
	}

	return &data, nil
}

// GenerateSecret Generate new TOTP secret
func (a *TwoFactorAuth) GenerateSecret(userID, username string) (*TwoFactorData, error) {
	// Check if user exists
	var user User
	if err := a.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound("User not found")
		}
		return nil, err
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.config.Issuer,
		AccountName: username,
		SecretSize:  a.config.SecretSize,
		Period:      a.config.Period,
		Algorithm:   a.config.Algorithm,
		Digits:      a.config.Digits,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %v", err)
	}

	// Save temporary key
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to save temporary key: %v", err)
	}

	tfaData.TempSecret = key.Secret()
	tfaData.UpdatedAt = time.Now()
	return tfaData, a.db.Save(tfaData).Error
}

// EnableTwoFactor Enable two-factor authentication
func (a *TwoFactorAuth) EnableTwoFactor(userID, code string) error {
	// Get user's 2FA data
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// Check if temporary key exists
	if tfaData.TempSecret == "" {
		return ErrInvalidToken("No temporary secret found, please generate a new secret")
	}

	// Validate code
	if !a.ValidateCode(tfaData.TempSecret, code) {
		return errors.New("invalid verification code")
	}

	// Generate backup codes
	backupCodes, err := a.GenerateBackupCodes()
	if err != nil {
		return fmt.Errorf("failed to generate backup codes: %v", err)
	}

	// Save backup codes as JSON
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return fmt.Errorf("failed to serialize backup codes: %v", err)
	}

	// Enable two-factor authentication
	tfaData.Secret = tfaData.TempSecret
	tfaData.TempSecret = ""
	tfaData.Enabled = true
	tfaData.BackupCodes = string(backupCodesJSON)
	tfaData.SecretUpdatedAt = time.Now()
	tfaData.LastVerified = time.Now()
	tfaData.UpdatedAt = time.Now()

	return a.db.Save(tfaData).Error
}

// DisableTwoFactor Disable two-factor authentication
func (a *TwoFactorAuth) DisableTwoFactor(userID, code string) error {
	// Get user's 2FA data
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// Check if 2FA is enabled
	if !tfaData.Enabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// Validate code
	if !a.ValidateCode(tfaData.Secret, code) && !a.ValidateBackupCode(userID, code) {
		return errors.New("invalid verification code")
	}

	// Disable two-factor authentication
	tfaData.Secret = ""
	tfaData.TempSecret = ""
	tfaData.Enabled = false
	tfaData.BackupCodes = ""
	tfaData.UpdatedAt = time.Now()

	if err := a.db.Save(tfaData).Error; err != nil {
		return fmt.Errorf("failed to disable 2FA: %v", err)
	}

	return nil
}

// ValidateCode Validate TOTP code
func (a *TwoFactorAuth) ValidateCode(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	return totp.Validate(code, secret)
}

// ParseBackupCodes Parse backup codes
func (a *TwoFactorAuth) ParseBackupCodes(backupCodesJSON string) ([]string, error) {
	if backupCodesJSON == "" {
		return nil, nil
	}

	var backupCodes []string
	err := json.Unmarshal([]byte(backupCodesJSON), &backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse backup codes: %v", err)
	}

	return backupCodes, nil
}

// ValidateBackupCode Validate backup code
func (a *TwoFactorAuth) ValidateBackupCode(userID, code string) bool {
	// Get user's backup codes
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil || !tfaData.Enabled || tfaData.BackupCodes == "" {
		return false
	}

	// Validate backup code
	backupCodes, err := a.ParseBackupCodes(tfaData.BackupCodes)
	if err != nil {
		return false
	}

	// Remove backup code after use
	for i, backupCode := range backupCodes {
		if backupCode == code {
			// Save updated backup codes back to database
			backupCodes = append(backupCodes[:i], backupCodes[i+1:]...)
			backupCodesJSON, err := json.Marshal(backupCodes)
			if err != nil {
				return false
			}

			tfaData.BackupCodes = string(backupCodesJSON)
			tfaData.LastVerified = time.Now()
			tfaData.UpdatedAt = time.Now()
			if err := a.db.Save(tfaData).Error; err != nil {
				return false
			}

			return true
		}
	}

	return false
}

// GenerateBackupCodes Generate backup codes
func (a *TwoFactorAuth) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 8) // Generate 8 backup codes

	for i := 0; i < 8; i++ {
		// Generate 6 bytes of random data
		b := make([]byte, 6)
		_, err := rand.Read(b)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %v", err)
		}

		// Convert to base32 encoding and take first 10 characters
		encoded := base32.StdEncoding.EncodeToString(b)
		codes[i] = strings.ToUpper(encoded[:10])
	}

	return codes, nil
}

// VerifyTwoFactor Verify two-factor authentication
func (a *TwoFactorAuth) VerifyTwoFactor(userID string, code string) error {
	// Get user's 2FA data
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// Check if two-factor authentication is enabled
	if !tfaData.Enabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// First try to verify TOTP code
	if a.ValidateCode(tfaData.Secret, code) {
		// Update last verification time
		tfaData.LastVerified = time.Now()
		tfaData.UpdatedAt = time.Now()
		a.db.Save(tfaData)
		return nil
	}

	// If TOTP verification fails, try backup code
	if a.ValidateBackupCode(userID, code) {
		// Update last verification time
		tfaData.LastVerified = time.Now()
		tfaData.UpdatedAt = time.Now()
		a.db.Save(tfaData)
		return nil
	}

	return errors.New("invalid verification code")
}

// GetBackupCodes Get user's backup codes
func (a *TwoFactorAuth) GetBackupCodes(userID string) ([]string, error) {
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return nil, err
	}

	return a.ParseBackupCodes(tfaData.BackupCodes)
}

// VerifyCode Verify the TOTP or backup code
func (a *TwoFactorAuth) VerifyCode(userID string, code string) error {
	// Get user's 2FA data
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return err
	}

	// Check if 2FA is enabled
	if !tfaData.Enabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// Verify TOTP code
	if a.ValidateCode(tfaData.Secret, code) {
		// Update last verification time
		tfaData.LastVerified = time.Now()
		tfaData.UpdatedAt = time.Now()
		a.db.Save(tfaData)
		return nil
	}

	// If TOTP verification fails, try backup code
	if a.ValidateBackupCode(userID, code) {
		// Update last verification time
		tfaData.LastVerified = time.Now()
		tfaData.UpdatedAt = time.Now()
		a.db.Save(tfaData)
		return nil
	}

	return errors.New("invalid verification code")
}

// GenerateRecoveryCodes Generate new recovery codes
func (a *TwoFactorAuth) GenerateRecoveryCodes(userID string, currentCode string) ([]string, error) {
	// Get user's 2FA data
	tfaData, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return nil, err
	}

	// Check if 2FA is enabled
	if !tfaData.Enabled {
		return nil, errors.New("two-factor authentication is not enabled")
	}

	// Verify current TOTP code
	if !a.ValidateCode(tfaData.Secret, currentCode) {
		return nil, errors.New("invalid verification code")
	}

	// Generate new backup codes
	codes, err := a.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	// Save backup codes as JSON
	codesJSON, err := json.Marshal(codes)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize backup codes: %v", err)
	}

	// Save to database
	tfaData.BackupCodes = string(codesJSON)
	tfaData.UpdatedAt = time.Now()
	if err := a.db.Save(tfaData).Error; err != nil {
		return nil, fmt.Errorf("failed to save backup codes: %v", err)
	}

	return codes, nil
}

// IsTwoFactorEnabled Check if user has enabled two-factor authentication
func (a *TwoFactorAuth) IsTwoFactorEnabled(userID string) (bool, error) {
	data, err := a.GetUserTwoFactorData(userID)
	if err != nil {
		return false, err
	}
	return data.Enabled, nil
}

// GetQRCodeURL Get QR code URL
func (t *TwoFactorAuth) GetQRCodeURL(userID string) (string, error) {
	// Get user's 2FA data
	data, err := t.GetUserTwoFactorData(userID)
	if err != nil {
		return "", err
	}

	// Check if temporary key exists
	if data.TempSecret == "" {
		return "", errors.New("temporary key not found, please generate a key first")
	}

	// Get user information
	var user User
	if err := t.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return "", fmt.Errorf("failed to get user information: %v", err)
	}

	// Construct account name
	accountName := user.Profile.Nickname
	if accountName == "" {
		accountName = userID
	}

	// Generate OTP key object
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		t.config.Issuer, accountName, data.TempSecret, t.config.Issuer))
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP key URL: %v", err)
	}

	return key.URL(), nil
}

// Using Redis to cache temporary state (optional)
func (t *TwoFactorAuth) StoreTempSecretInRedis(userID string, secret string, duration time.Duration) error {
	if t.redis == nil {
		return errors.New("redis not configured")
	}

	key := fmt.Sprintf("2fa:temp:%s", userID)
	return t.redis.Set(key, secret, duration)
}

func (t *TwoFactorAuth) GetTempSecretFromRedis(userID string) (string, error) {
	if t.redis == nil {
		return "", errors.New("redis not configured")
	}

	key := fmt.Sprintf("2fa:temp:%s", userID)
	var secret string
	err := t.redis.Get(key, &secret)
	if err != nil {
		return "", err
	}
	return secret, nil
}
