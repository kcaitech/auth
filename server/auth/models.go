/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
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
