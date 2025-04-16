package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Email User Model
type EmailUser struct {
	UserID string `json:"user_id" gorm:"primarykey"` // User ID associated with the User table
	Email  string `json:"email" gorm:"unique"`       // Email, used as login credential
	// Verified  bool      `json:"verified" gorm:"default:false"` // Whether the email has been verified
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Extended AccountAuth
type EmailAuth struct {
	db *gorm.DB
	// maxLoginAttempts   int
	// loginLockDuration  time.Duration
	verificationExpiry time.Duration
	emailService       EmailService
	redis              *AccountRedisStore
}

// EmailService Email service interface
type EmailService interface {
	SendVerificationEmail(email, token, title, content string) error
	SendPasswordResetEmail(email, token, title, content string) error
	SendLoginNotificationEmail(email, ip, title, content string) error
}

// Pre-registration information, stored in Redis
type EmailPreregisterInfo struct {
	Email     string    `json:"email"`
	Password  string    `json:"password"` // Encrypted password
	Nickname  string    `json:"nickname"`
	CreatedAt time.Time `json:"created_at"`
}

// Configuration options
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
		redis:              config.Redis, // Use pointer directly
	}
}

// AutoMigrate Automatically migrate database table structure
func (a *EmailAuth) AutoMigrate() error {
	if err := a.db.AutoMigrate(
		&User{},
		&EmailUser{},
	); err != nil {
		return err
	}
	return nil
}

// Generate verification token
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// InitiatePasswordReset Initiate password reset
func (a *EmailAuth) InitiatePasswordReset(email, title, content string) (string, error) {
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	// Generate reset token
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	// Store verification record in Redis with expiration time
	if err := a.redis.StoreVerification(VerificationTypePassword, email, token, user.UserID, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store password reset verification information: %w", err)
	}

	// Send reset email
	if err := a.emailService.SendPasswordResetEmail(email, token, title, content); err != nil {
		return "", err
	}

	return token, nil
}

// CompletePasswordReset Complete password reset
func (a *EmailAuth) CompletePasswordReset(token, newPassword string) error {
	// Get verification record from Redis
	verification, err := a.redis.GetVerificationByToken(VerificationTypePassword, token)
	if err != nil {
		return ErrInvalidToken("Password reset token is invalid or expired")
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

	// Delete token after use
	return a.redis.DeleteVerification(VerificationTypePassword, verification.Identifier, token)
}

// EmailPreregister Email pre-registration, sends verification email but doesn't create user
func (a *EmailAuth) EmailPreregister(email, password, nickname, title, content string) (string, error) {
	// Email must be provided
	if email == "" {
		return "", ErrInvalidInput("Valid email must be provided")
	}

	// Check if email is duplicate
	if err := a.CheckDuplicateEmail(email); err != nil {
		return "", err
	}

	// If nickname is not provided, use email prefix as default nickname
	if nickname == "" {
		parts := strings.Split(email, "@")
		nickname = parts[0]
	}

	// Validate password strength
	if err := a.ValidatePassword(password); err != nil {
		return "", err
	}

	// Encrypt password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt password: %v", err)
	}

	// Generate verification token
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	// log.Println("email preregister token:", token)
	// Create pre-registration information
	preregInfo := &EmailPreregisterInfo{
		Email:     email,
		Password:  string(hashedPassword),
		Nickname:  nickname,
		CreatedAt: time.Now(),
	}

	// Store pre-registration information in Redis
	preregKey := fmt.Sprintf("email_prereg:%s:%s", email, token)
	if err := a.redis.Set(preregKey, preregInfo, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store pre-registration information: %w", err)
	}

	// Associate verification token with email
	if err := a.redis.StoreVerification(VerificationTypeEmail, email, token, "", a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store email verification information: %w", err)
	}

	// Send verification email
	if err := a.emailService.SendVerificationEmail(email, token, title, content); err != nil {
		return "", fmt.Errorf("failed to send verification email: %w", err)
	}

	return token, nil
}

func (a *EmailAuth) ResentEmailVerification(email, title, content string) (bool, error) {
	verification, err := a.redis.GetVerification(VerificationTypeEmail, email)
	if err != nil {
		return false, err
	}

	// Send verification email
	if err := a.emailService.SendVerificationEmail(email, verification.Token, title, content); err != nil {
		return false, fmt.Errorf("failed to send verification email: %w", err)
	}

	return true, nil
}

// RegisterEmailUser Email user registration - this function is now used internally, called after verification
func (a *EmailAuth) RegisterEmailUser(email, password, nickname string) (*User, error) {
	// Email must be provided
	if email == "" {
		return nil, ErrInvalidInput("Valid email must be provided")
	}

	// Check if email is duplicate
	if err := a.CheckDuplicateEmail(email); err != nil {
		return nil, err
	}

	// Generate random UserID
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

	// If nickname is not provided, use email prefix as default nickname
	if nickname == "" {
		parts := strings.Split(email, "@")
		nickname = parts[0]
	}

	// Start transaction
	tx := a.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create basic user record
	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: password, // Already encrypted password
		Status:   UserStatusActive,
		Profile: UserProfile{
			Nickname: nickname,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Create email user association record
	emailUser := &EmailUser{
		UserID: userID,
		Email:  email,
		// Verified:  true, // Email is verified
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(emailUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create email user association: %v", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// VerifyEmail Verify email and complete registration
func (a *EmailAuth) VerifyEmail(token string) (*User, error) {
	// Get verification record from Redis
	verification, err := a.redis.GetVerificationByToken(VerificationTypeEmail, token)
	if err != nil {
		log.Println("verify email error:", err)
		return nil, ErrInvalidToken("Email verification token is invalid or expired")
	}

	email := verification.Identifier

	// Try to get pre-registration information
	preregKey := fmt.Sprintf("email_prereg:%s:%s", email, token)
	var preregInfo EmailPreregisterInfo
	if err := a.redis.Get(preregKey, &preregInfo); err != nil {
		return nil, ErrInvalidToken("Pre-registration information not found or expired, please register again")
	}

	// Complete registration
	user, err := a.RegisterEmailUser(email, preregInfo.Password, preregInfo.Nickname)
	if err != nil {
		return nil, fmt.Errorf("failed to complete registration: %w", err)
	}

	// Delete token after use
	if err := a.redis.DeleteVerification(VerificationTypeEmail, email, token); err != nil {
		// Only log error, doesn't affect registration process
		fmt.Printf("Failed to delete verification token: %v\n", err)
	}

	// Delete pre-registration information
	if err := a.redis.Delete(preregKey); err != nil {
		// Only log error, doesn't affect registration process
		fmt.Printf("Failed to delete pre-registration information: %v\n", err)
	}

	return user, nil
}

// SendVerificationEmail Send verification email - now used for registered users to re-verify email
// func (a *EmailAuth) SendVerificationEmail(userID, title, content string) error {
// 	// Query EmailUser record
// 	var emailUser EmailUser
// 	if err := a.db.Where("user_id = ?", userID).First(&emailUser).Error; err != nil {
// 		return err
// 	}

// 	if emailUser.Verified {
// 		return errors.New("User email has already been verified")
// 	}

// 	token, err := generateToken()
// 	if err != nil {
// 		return err
// 	}

// 	// Store verification record in Redis with expiration time
// 	if err := a.redis.StoreVerification(VerificationTypeEmail, emailUser.Email, token, userID, a.verificationExpiry); err != nil {
// 		return fmt.Errorf("Failed to store email verification information: %w", err)
// 	}

// 	return a.emailService.SendVerificationEmail(emailUser.Email, token, title, content)
// }

// EmailLogin Email user login
func (a *EmailAuth) EmailLogin(email, password string) (*User, error) {
	// First query the corresponding email user
	var emailUser EmailUser
	err := a.db.Where("email = ?", email).First(&emailUser).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("Invalid email or password")
		}
		return nil, err
	}

	// Query associated User information through UserID
	var user User
	if err := a.db.Where("user_id = ?", emailUser.UserID).First(&user).Error; err != nil {
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("Invalid email or password")
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail Get user by email
func (a *EmailAuth) GetUserByEmail(email string) (*User, error) {
	// First query EmailUser record
	var emailUser EmailUser
	if err := a.db.Where("email = ?", email).First(&emailUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	// Then query User record through UserID
	var user User
	if err := a.db.Where("user_id = ?", emailUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	return &user, nil
}

// CheckDuplicateEmail Check if email is duplicate
func (a *EmailAuth) CheckDuplicateEmail(email string) error {
	var count int64
	if err := a.db.Model(&EmailUser{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Email is already in use")
	}
	return nil
}

// ValidatePassword Validate password strength
func (a *EmailAuth) ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters")
	}
	return nil
}
