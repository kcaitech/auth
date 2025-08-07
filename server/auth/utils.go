/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"fmt"

	"gorm.io/gorm"
)

func _generateUserID() (string, error) {
	return GenerateBase62String(10)
}

func GenerateUserID(db *gorm.DB) (string, error) {
	// Generate random UserID
	userID, err := _generateUserID()
	if err != nil {
		return "", fmt.Errorf("failed to generate random ID: %v", err)
	}

	// Ensure UserID is unique
	for {
		var count int64
		db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// Generate new UserID
		userID, err = _generateUserID()
		if err != nil {
			return "", fmt.Errorf("failed to generate random ID: %v", err)
		}
	}
	return userID, nil
}
