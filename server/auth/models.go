/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import "time"

// User Status
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"   // Active
	UserStatusInactive UserStatus = "inactive" // Inactive
	UserStatusLocked   UserStatus = "locked"   // Locked
	UserStatusBanned   UserStatus = "banned"   // Banned
)

// Verification Record, store in Redis
type Verification struct {
	UserID     string           `gorm:"primarykey"`
	Type       VerificationType `gorm:"size:20"`
	Token      string           `gorm:"size:100;index"`
	Identifier string           `gorm:"size:100"`
	// ExpiresAt  time.Time
	CreatedAt time.Time
}

// User Role Association
// type UserRoleMapping struct {
// 	UserID    uint   `gorm:"primarykey"`
// 	Role      string `gorm:"primarykey;size:20"`
// 	CreatedAt time.Time
// }

// Session Information, store in Redis
type Session struct {
	ID        string    `json:"id" gorm:"primarykey;size:64"` // Session ID
	UserID    string    `json:"user_id" gorm:"index"`         // User ID
	IP        string    `json:"ip" gorm:"size:45"`            // IP Address
	UserAgent string    `json:"user_agent" gorm:"size:255"`   // User Agent
	ExpiresAt time.Time `json:"expires_at" gorm:"index"`      // Expiry Time
	CreatedAt time.Time `json:"created_at"`                   // Creation Time
	UpdatedAt time.Time `json:"updated_at"`                   // Update Time
}

// User User Model
type User struct { // Automatically generated ID
	UserID        string     `json:"user_id" gorm:"primarykey"` // Login identifier, for normal accounts this is the login account, for email accounts it's automatically generated
	Password      string     `json:"-" gorm:"not null"`
	Status        UserStatus `json:"status" gorm:"not null;default:'active'"`
	Nickname      string     `json:"nickname" gorm:"size:50"` // Nickname
	Avatar        string     `json:"avatar" gorm:"size:255"`  // Avatar URL
	LastLogin     *time.Time `json:"last_login"`
	LoginAttempts int        `json:"login_attempts" gorm:"default:0"`
	LastAttempt   *time.Time `json:"last_attempt"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Email User Model
type EmailUser struct {
	UserID string `json:"user_id" gorm:"primarykey"` // User ID associated with the User table
	Email  string `json:"email" gorm:"unique"`       // Email, used as login credential
	// Verified  bool      `json:"verified" gorm:"default:false"` // Whether the email has been verified
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type GoogleUser struct {
	UserID        string `json:"user_id" gorm:"primarykey"`
	GoogleID      string `json:"google_id" gorm:"index"`
	Email         string `json:"email" gorm:"index"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// PhoneUser Phone user model
type PhoneUser struct {
	UserID string `json:"user_id" gorm:"primarykey"` // Associated with User table's user ID
	Phone  string `json:"phone" gorm:"unique"`       // Phone number, used as login credential
	// Verified  bool      `json:"verified" gorm:"default:false"` // Whether the phone number is verified
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WeixinUserInfo WeChat user information
type WeixinUserInfo struct {
	OpenID     string `json:"openid" gorm:"unique"`
	Nickname   string `json:"nickname"`
	Sex        int    `json:"sex"`
	Province   string `json:"province"`
	City       string `json:"city"`
	Country    string `json:"country"`
	HeadImgURL string `json:"headimgurl"`
	UnionID    string `json:"unionid" gorm:"unique"`
}

type WeixinUser struct {
	UserID string `json:"user_id" gorm:"primarykey"`
	WeixinUserInfo
	CreatedAt time.Time
	UpdatedAt time.Time
}
