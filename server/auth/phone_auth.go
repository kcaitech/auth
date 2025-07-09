/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"kcaitech.com/kcauth/server/common"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	RedisPrefixPhonePreregister = common.RedisKeyPhonePreregister
)

// PhoneUser Phone user model
type PhoneUser struct {
	UserID string `json:"user_id" gorm:"primarykey"` // Associated with User table's user ID
	Phone  string `json:"phone" gorm:"unique"`       // Phone number, used as login credential
	// Verified  bool      `json:"verified" gorm:"default:false"` // Whether the phone number is verified
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SMSService SMS service interface
type SMSService interface {
	SendVerificationSMS(phone, code string) error
	SendPasswordResetSMS(phone, code string) error
	SendLoginNotificationSMS(phone, ip string) error
}

// Verification types
const (
	VerificationTypePhone      VerificationType = "phone"       // New: Phone verification type
	VerificationTypePhoneReset VerificationType = "phone_reset" // Phone password reset
)

// Pre-registration information, stored in Redis
type PhonePreregisterInfo struct {
	Phone     string    `json:"phone"`
	Password  string    `json:"password"` // Encrypted password
	Nickname  string    `json:"nickname"`
	CreatedAt time.Time `json:"created_at"`
}

// PhoneAuth Phone authentication structure
type PhoneAuth struct {
	db                 *gorm.DB
	verificationExpiry time.Duration
	smsService         SMSService
	redis              *AccountRedisStore
}

// PhoneAuthConfig Phone authentication configuration
type PhoneAuthConfig struct {
	VerificationExpiry time.Duration
	SMSService         SMSService
	Redis              *AccountRedisStore
}

// NewPhoneAuth Create phone authentication instance
func NewPhoneAuth(db *gorm.DB, config PhoneAuthConfig) *PhoneAuth {
	return &PhoneAuth{
		db:                 db,
		verificationExpiry: config.VerificationExpiry,
		smsService:         config.SMSService,
		redis:              config.Redis,
	}
}

// AutoMigrate Automatically migrate database table structure
func (a *PhoneAuth) AutoMigrate() error {
	if err := a.db.AutoMigrate(
		&User{},
		&PhoneUser{},
	); err != nil {
		return err
	}
	return nil
}

// Generate verification code
func generateVerificationCode() (string, error) {
	// Generate 6-digit random numeric verification code
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// Format as 6 digits, pad with leading zeros if necessary
	return fmt.Sprintf("%06d", n), nil
}

// InitiatePasswordReset Initiate password reset
func (a *PhoneAuth) InitiatePasswordReset(phone string) (string, error) {
	user, err := a.GetUserByPhone(phone)
	if err != nil {
		return "", err
	}

	// Generate verification code
	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	// Store verification record in Redis with expiration time
	if err := a.redis.StoreVerification(VerificationTypePhoneReset, phone, code, user.UserID, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store phone password reset verification information: %w", err)
	}

	// Send reset SMS
	if err := a.smsService.SendPasswordResetSMS(phone, code); err != nil {
		return "", err
	}

	return code, nil
}

// CompletePasswordReset Complete password reset
func (a *PhoneAuth) CompletePasswordReset(code, phone, newPassword string) error {
	// Get verification record from Redis
	verification, err := a.redis.GetVerification(VerificationTypePhoneReset, phone)
	if err != nil {
		return ErrInvalidToken("Invalid or expired verification code")
	}

	// Validate new password strength
	if len(newPassword) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters")
	}

	// Encrypt new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password in User table
	result := a.db.Model(&User{}).Where("user_id = ?", verification.UserID).
		Update("password", string(hashedPassword))

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrInvalidToken("Invalid user ID")
	}

	// Delete verification code after use
	return a.redis.DeleteVerification(VerificationTypePhoneReset, phone, code)
}

// SendVerificationSMS Send verification SMS
// func (a *PhoneAuth) SendVerificationSMS(userID string) error {
// 	// Query PhoneUser record
// 	var phoneUser PhoneUser
// 	if err := a.db.Where("user_id = ?", userID).First(&phoneUser).Error; err != nil {
// 		return err
// 	}

// 	if phoneUser.Verified {
// 		return errors.New("user's phone number has already been verified")
// 	}

// 	code, err := generateVerificationCode()
// 	if err != nil {
// 		return err
// 	}

// 	// Store verification record in Redis
// 	if err := a.redis.StoreVerification(VerificationTypePhone, phoneUser.Phone, code, userID, a.verificationExpiry); err != nil {
// 		return fmt.Errorf("failed to store phone verification information: %w", err)
// 	}

// 	// Send verification SMS
// 	return a.smsService.SendVerificationSMS(phoneUser.Phone, code)
// }

// VerifyPhone Verify phone number
func (a *PhoneAuth) VerifyPhone(code string) error {
	// Get verification record from Redis
	verification, err := a.redis.GetVerificationByToken(VerificationTypePhone, code)
	if err != nil {
		return ErrInvalidToken("Invalid or expired verification code")
	}

	// Update PhoneUser record
	result := a.db.Model(&PhoneUser{}).Where("user_id = ?", verification.UserID).
		Update("verified", true)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrInvalidToken("Invalid user ID")
	}

	// Delete verification code after use
	return a.redis.DeleteVerification(VerificationTypePhone, verification.Identifier, code)
}

// Login Login with phone number and password
func (a *PhoneAuth) PhoneLogin(phone, password string) (*User, error) {
	// Validate phone number format
	if err := a.ValidatePhoneFormat(phone); err != nil {
		return nil, err
	}

	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials("Invalid phone number or password")
		}
		return nil, err
	}

	// Check if phone number is verified
	// if !phoneUser.Verified {
	// 	return nil, ErrEmailNotVerified("Phone number not verified, please verify first")
	// }

	// Get associated user record
	var user User
	if err := a.db.Where("user_id = ?", phoneUser.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials("User account not found")
		}
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials("Invalid phone number or password")
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByPhone Get user by phone number
func (a *PhoneAuth) GetUserByPhone(phone string) (*User, error) {
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound("User not found for this phone number")
		}
		return nil, err
	}

	var user User
	if err := a.db.Where("user_id = ?", phoneUser.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound("User not found")
		}
		return nil, err
	}

	return &user, nil
}

// CheckDuplicatePhone Check if phone number is already in use
func (a *PhoneAuth) CheckDuplicatePhone(phone string) error {
	var count int64
	if err := a.db.Model(&PhoneUser{}).Where("phone = ?", phone).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrPhoneTaken("This phone number is already registered")
	}
	return nil
}

// PhonePreregister Phone pre-registration, sends verification code but doesn't create user
func (a *PhoneAuth) PhonePreregister(phone, password, nickname string) (string, error) {
	// Check phone number format
	if err := a.ValidatePhoneFormat(phone); err != nil {
		return "", err
	}

	// Check if phone number is already in use
	if err := a.CheckDuplicatePhone(phone); err != nil {
		return "", err
	}

	// Validate password strength
	if len(password) < 8 {
		return "", ErrWeakPassword("Password must be at least 8 characters")
	}

	// Encrypt password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt password: %v", err)
	}

	// Generate verification code
	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	// Create pre-registration information
	preregInfo := &PhonePreregisterInfo{
		Phone:     phone,
		Password:  string(hashedPassword),
		Nickname:  nickname,
		CreatedAt: time.Now(),
	}

	// Store pre-registration information in Redis
	preregKey := fmt.Sprintf("%s%s:%s", RedisPrefixPhonePreregister, phone, code)
	if err := a.redis.Set(preregKey, preregInfo, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store pre-registration information: %w", err)
	}

	// Associate verification code with phone number
	if err := a.redis.StoreVerification(VerificationTypePhone, phone, code, "", a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store phone verification information: %w", err)
	}

	// Send verification SMS
	if err := a.smsService.SendVerificationSMS(phone, code); err != nil {
		return "", fmt.Errorf("failed to send verification SMS: %w", err)
	}

	return code, nil
}

// ResendPhoneVerification Resend phone verification code
func (a *PhoneAuth) ResendPhoneVerification(phone string) (string, error) {
	// Get previous verification record from Redis
	verification, err := a.redis.GetVerification(VerificationTypePhone, phone)
	if err != nil {
		return "", err
	}

	// Generate new verification code
	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	// Update verification record
	if err := a.redis.UpdateVerification(VerificationTypePhone, phone, verification.Token, code, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to update phone verification information: %w", err)
	}

	// Send verification SMS
	if err := a.smsService.SendVerificationSMS(phone, code); err != nil {
		return "", fmt.Errorf("failed to send verification SMS: %w", err)
	}

	return code, nil
}

// VerifyPhoneAndRegister Verify phone number and complete registration
func (a *PhoneAuth) VerifyPhoneAndRegister(phone, code string) (*User, error) {
	// Get verification record from Redis
	verification, err := a.redis.GetVerification(VerificationTypePhone, phone)
	if err != nil {
		return nil, ErrInvalidToken("Invalid or expired verification code")
	}

	// Verify verification code
	if verification.Token != code {
		return nil, ErrInvalidToken("Incorrect verification code")
	}

	// Try to get pre-registration information
	preregKey := fmt.Sprintf("%s%s:%s", RedisPrefixPhonePreregister, phone, code)
	var preregInfo PhonePreregisterInfo
	if err := a.redis.Get(preregKey, &preregInfo); err != nil {
		return nil, ErrInvalidToken("Pre-registration information not found or expired, please register again")
	}

	// Create transaction
	tx := a.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	// Rollback transaction if error occurs
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Generate random user ID
	userID, err := GenerateUserID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}

	// Ensure UserID is unique
	for {
		var count int64
		a.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// Generate new UserID
		userID, err = GenerateUserID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ID: %v", err)
		}
	}

	// Create User record
	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: preregInfo.Password, // Already encrypted password
		Status:   UserStatusActive,

		Nickname:  preregInfo.Nickname,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Create PhoneUser record
	phoneUser := &PhoneUser{
		UserID: userID,
		Phone:  phone,
		// Verified:  true, // Phone number is verified
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(phoneUser).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	// Delete verification code after use
	if err := a.redis.DeleteVerification(VerificationTypePhone, phone, code); err != nil {
		// Just log error, does not affect registration process
		fmt.Printf("Failed to delete verification code: %v\n", err)
	}

	// Delete pre-registration information
	if err := a.redis.Delete(preregKey); err != nil {
		// Just log error, does not affect registration process
		fmt.Printf("Failed to delete pre-registration information: %v\n", err)
	}

	return user, nil
}

// PhoneCodeLogin Phone verification code login (no password required)
func (a *PhoneAuth) PhoneCodeLogin(phone, code string) (*User, error) {
	// Get verification record from Redis
	_, err := a.redis.GetVerificationByToken(VerificationTypePhone, code)
	if err != nil {
		return nil, err
	}

	// Find phone user record
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound("Phone number not found")
		}
		return nil, err
	}

	// Get User record by userID
	var user User
	if err := a.db.First(&user, "user_id = ?", phoneUser.UserID).Error; err != nil {
		return nil, err
	}

	// If phone number is not verified, mark it as verified now
	// if !phoneUser.Verified {
	// 	phoneUser.Verified = true
	// 	if err := a.db.Save(&phoneUser).Error; err != nil {
	// 		return nil, err
	// 	}
	// }

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	// Delete verification code after use
	_ = a.redis.DeleteVerification(VerificationTypePhone, phone, code)

	return &user, nil
}

// SendLoginSMS Send login verification code
func (a *PhoneAuth) SendLoginSMS(phone string) (string, error) {
	// Check if phone number is registered
	var phoneUser PhoneUser
	if err := a.db.Where("phone = ?", phone).First(&phoneUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrUserNotFound("This phone number is not registered")
		}
		return "", err
	}

	// Generate verification code
	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	// Store verification record in Redis and set expiration time (5 minutes)
	if err := a.redis.StoreVerification(VerificationTypePhone, phone, code, phoneUser.UserID, time.Minute*5); err != nil {
		return "", err
	}

	// Send verification code SMS
	if err := a.smsService.SendVerificationSMS(phone, code); err != nil {
		return "", err
	}

	return code, nil
}

// ValidatePhoneFormat Validate phone number format
func (a *PhoneAuth) ValidatePhoneFormat(phone string) error {
	// This is just a simple example, actual implementation should strictly validate according to phone number rules for different countries/regions
	if len(phone) < 11 {
		return ErrInvalidPhoneFormat("Invalid phone number format")
	}
	return nil
}
