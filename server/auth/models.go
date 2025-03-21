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

// User Profile
type UserProfile struct {
	Nickname string `json:"nickname" gorm:"size:50"` // Nickname
	Avatar   string `json:"avatar" gorm:"size:255"`  // Avatar URL
	// Bio       string `json:"bio" gorm:"size:500"`       // Biography
	Location string `json:"location" gorm:"size:100"` // Location
	// Website   string `json:"website" gorm:"size:200"`   // Personal Website
	Birthday string `json:"birthday" gorm:"size:10"` // Birthday
	Gender   string `json:"gender" gorm:"size:10"`   // Gender
	// Phone     string `json:"phone" gorm:"size:20"`      // Phone Number
	// Company   string `json:"company" gorm:"size:100"`   // Company
	// Position  string `json:"position" gorm:"size:100"`  // Position
	// Education string `json:"education" gorm:"size:100"` // Education Background
	Language string `json:"language" gorm:"size:20"` // Preferred Language
	Timezone string `json:"timezone" gorm:"size:50"` // Timezone
}

// Verification Record
type Verification struct {
	UserID     string           `gorm:"primarykey"`
	Type       VerificationType `gorm:"size:20"`
	Token      string           `gorm:"size:100;index"`
	Identifier string           `gorm:"size:100"`
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// User Role Association
type UserRoleMapping struct {
	UserID    uint   `gorm:"primarykey"`
	Role      string `gorm:"primarykey;size:20"`
	CreatedAt time.Time
}

// Session Information
type Session struct {
	ID        string    `json:"id" gorm:"primarykey;size:64"` // Session ID
	UserID    string    `json:"user_id" gorm:"index"`         // User ID
	IP        string    `json:"ip" gorm:"size:45"`            // IP Address
	UserAgent string    `json:"user_agent" gorm:"size:255"`   // User Agent
	ExpiresAt time.Time `json:"expires_at" gorm:"index"`      // Expiry Time
	CreatedAt time.Time `json:"created_at"`                   // Creation Time
	UpdatedAt time.Time `json:"updated_at"`                   // Update Time
}

// ErrInvalidSession Invalid Session Error
// var ErrInvalidSession = NewAppError(ErrCodeInvalidSession, "Invalid session", nil)
