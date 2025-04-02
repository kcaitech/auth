package auth

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User Roles
type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
	RoleGuest UserRole = "guest"
)

// Permissions
type Permission string

const (
	PermReadBasic   Permission = "read:basic"
	PermReadAdmin   Permission = "read:admin"
	PermWriteBasic  Permission = "write:basic"
	PermWriteAdmin  Permission = "write:admin"
	PermDeleteBasic Permission = "delete:basic"
	PermDeleteAdmin Permission = "delete:admin"
)

// Verification Types
type VerificationType string

const (
	VerificationTypeEmail     VerificationType = "email"
	VerificationTypePassword  VerificationType = "password"
	VerificationTypeTwoFactor VerificationType = "2fa"
)

// Login Attempt Record
type LoginAttempt struct {
	UserID    string `gorm:"primarykey"`
	IP        string `gorm:"size:45"`
	Success   bool
	CreatedAt time.Time
}

// User User Model
type User struct { // Automatically generated ID
	UserID        string      `json:"user_id" gorm:"primarykey"` // Login identifier, for normal accounts this is the login account, for email accounts it's automatically generated
	Password      string      `json:"-" gorm:"not null"`
	Status        UserStatus  `json:"status" gorm:"not null;default:'active'"`
	Profile       UserProfile `json:"profile" gorm:"embedded"`
	LastLogin     *time.Time  `json:"last_login"`
	LoginAttempts int         `json:"login_attempts" gorm:"default:0"`
	LastAttempt   *time.Time  `json:"last_attempt"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// Extended AccountAuth
type AccountAuth struct {
	db                *gorm.DB
	maxLoginAttempts  int
	loginLockDuration time.Duration
	redis             *AccountRedisStore // Using AccountRedisStore
}

// Configuration Options
type AccountAuthConfig struct {
	MaxLoginAttempts  int
	LoginLockDuration time.Duration
	Redis             *AccountRedisStore // Using AccountRedisStore
}

// NewAccountAuth Create account authentication instance
func NewAccountAuth(db *gorm.DB, config AccountAuthConfig) *AccountAuth {
	return &AccountAuth{
		db:                db,
		maxLoginAttempts:  config.MaxLoginAttempts,
		loginLockDuration: config.LoginLockDuration,
		redis:             config.Redis,
	}
}

// AutoMigrate Automatically migrate database table structure
func (a *AccountAuth) AutoMigrate() error {
	// Ensure UserRole type is registered first
	if err := a.db.AutoMigrate(
		&User{},
	); err != nil {
		return err
	}

	return nil
}

// RecordLoginAttempt Record login attempt
func (a *AccountAuth) RecordLoginAttempt(userID string, ip string, success bool) error {
	// Only increase count on login failure
	if !success {
		// Increase failure count
		_, err := a.redis.IncrLoginAttempts(userID, ip, a.loginLockDuration)
		if err != nil {
			return fmt.Errorf("failed to record login attempt: %w", err)
		}

		// Can log login failures here
		return nil
	}

	// If login successful, reset failure count
	if success {
		return a.redis.ResetLoginAttempts(userID, ip)
	}

	return nil
}

// CheckLoginAttempts Check login attempt count
func (a *AccountAuth) CheckLoginAttempts(userID string, ip string) error {
	// Get failure attempt count for specified user IP
	count, err := a.redis.GetLoginAttempts(userID, ip)
	if err != nil {
		return fmt.Errorf("failed to check login attempt count: %w", err)
	}

	if count >= a.maxLoginAttempts {
		return NewAppError(ErrCodeTooManyRequests, "Too many login attempts, please try again later", nil)
	}

	return nil
}

// Login User login
func (a *AccountAuth) Login(userID string, password string) (*User, error) {
	user, err := a.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("Invalid account or password")
		}
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("Invalid account or password")
	}

	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// VerifyPassword Verify password
// func (a *AccountAuth) VerifyPassword(userID string, password string) error {
// 	user, err := a.GetUserByID(userID)
// 	if err != nil {
// 		return err
// 	}
// 	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
// 		return ErrInvalidPassword("Invalid account or password")
// 	}
// 	return nil
// }

// CreateUser Create new user
func (a *AccountAuth) CreateUser(user *User) error {
	// Check if UserID already exists
	var count int64
	if err := a.db.Model(&User{}).Where("user_id = ?", user.UserID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrUserIDTaken("Account ID is already in use")
	}

	// Need to encrypt password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	// Set creation time and update time
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	// user.LastAttempt = now

	return a.db.Create(user).Error
}

// UpdateUser Update user information
func (a *AccountAuth) UpdateUser(user *User) error {
	user.UpdatedAt = time.Now()
	return a.db.Save(user).Error
}

// GetUserByID Get user by ID
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

// UpdateProfile Update user profile
func (a *AccountAuth) UpdateProfile(userID string, updates map[string]interface{}) error {
	// Check if user exists
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Check if user ID is already taken
	if newUserID, ok := updates["user_id"]; ok && newUserID != user.UserID {
		// var count int64
		// if err := a.db.Model(&User{}).Where("user_id = ?", newUserID).Count(&count).Error; err != nil {
		// 	return err
		// }
		// if count > 0 {
		// 	return ErrUserIDTaken("Account ID is already taken")
		// }
		return fmt.Errorf("user_id 不可变更")
	}

	updates["updated_at"] = time.Now()
	return a.db.Model(user).Updates(updates).Error
}

// ChangePassword Change user password
func (a *AccountAuth) ChangePassword(userID string, oldPassword, newPassword string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return ErrInvalidPassword("Invalid old password")
	}

	// Validate new password strength
	if len(newPassword) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}

	// Encrypt new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return a.db.Model(user).Updates(map[string]interface{}{
		"password":   string(hashedPassword),
		"updated_at": time.Now(),
	}).Error
}

// Register User registration (normal account)
func (a *AccountAuth) Register(userID string, password string) error {

	if userID == "" {
		return ErrInvalidInput("Account ID must be provided for normal account")
	}

	// Check if UserID is duplicate
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

// ValidateToken Validate token
func (a *AccountAuth) ValidateToken(token string) error {
	if token == "" {
		return ErrInvalidToken("Token cannot be empty")
	}
	return nil
}

// ValidatePassword Validate password
func (a *AccountAuth) ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}
	return nil
}

// CheckDuplicateUsername Check if username is duplicate
func (a *AccountAuth) CheckDuplicateUsername(username string) error {
	return a.CheckDuplicateUserID(username)
}

// CleanExpiredVerifications Clean expired verification records
func (a *AccountAuth) CleanExpiredVerifications() error {
	// Manual cleanup of expired verification records not needed when using Redis, Redis will handle this automatically
	// This method is kept for compatibility
	return nil
}

// GetUserByUserID Get user by UserID
// func (a *AccountAuth) GetUserByUserID(userID string) (*User, error) {
// 	var user User
// 	if err := a.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
// 		if err == gorm.ErrRecordNotFound {
// 			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
// 		}
// 		return nil, err
// 	}
// 	return &user, nil
// }

// CheckDuplicateUserID Check if UserID is duplicate
func (a *AccountAuth) CheckDuplicateUserID(userID string) error {
	var count int64
	if err := a.db.Model(&User{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Account ID is already in use")
	}
	return nil
}

// SetNickname Set nickname
func (a *AccountAuth) SetNickname(userID string, nickname string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}
	// todo 审核
	user.Profile.Nickname = nickname
	return a.db.Save(user).Error
}

// SetAvatar Set avatar
func (a *AccountAuth) SetAvatar(userID string, avatar string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}
	// todo 审核
	// todo 存oss
	user.Profile.Avatar = avatar
	return a.db.Save(user).Error
}

// GetUsersByIDs 批量获取用户信息
func (a *AccountAuth) GetUsersByIDs(ids []string) ([]User, error) {
	var users []User
	if err := a.db.Where("user_id IN ?", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
