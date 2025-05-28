/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// AccountRedisStore Account-related Redis storage service
type AccountRedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewAccountRedisStore Create a new account Redis storage service
func NewAccountRedisStore(client *redis.Client) *AccountRedisStore {
	return &AccountRedisStore{
		client: client,
		ctx:    context.Background(),
	}
}

// CacheUser Cache user information
func (rs *AccountRedisStore) CacheUser(user *User) error {
	key := fmt.Sprintf("user:%s", user.UserID)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to serialize user data: %w", err)
	}

	// Set 1 hour expiration
	return rs.client.Set(rs.ctx, key, data, time.Hour).Err()
}

// GetCachedUser Get cached user information
func (rs *AccountRedisStore) GetCachedUser(userID string) (*User, error) {
	key := fmt.Sprintf("user:%s", userID)
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user data from cache: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	return &user, nil
}

// InvalidateUserCache Invalidate user cache
func (rs *AccountRedisStore) InvalidateUserCache(userID string) error {
	key := fmt.Sprintf("user:%s", userID)
	return rs.client.Del(rs.ctx, key).Err()
}

// CacheLoginAttempts Cache login attempt count
func (rs *AccountRedisStore) CacheLoginAttempts(userID string, ip string, count int, duration time.Duration) error {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	return rs.client.Set(rs.ctx, key, count, duration).Err()
}

// GetLoginAttempts Get login attempt count
func (rs *AccountRedisStore) GetLoginAttempts(userID string, ip string) (int, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	count, err := rs.client.Get(rs.ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get login attempts: %w", err)
	}
	return count, nil
}

// IncrLoginAttempts Increment login attempt count
func (rs *AccountRedisStore) IncrLoginAttempts(userID string, ip string, duration time.Duration) (int, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	pipe := rs.client.Pipeline()
	incr := pipe.Incr(rs.ctx, key)
	pipe.Expire(rs.ctx, key, duration)
	_, err := pipe.Exec(rs.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to increase login attempts: %w", err)
	}
	return int(incr.Val()), nil
}

// ResetLoginAttempts Reset login attempt count
func (rs *AccountRedisStore) ResetLoginAttempts(userID string, ip string) error {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	return rs.client.Del(rs.ctx, key).Err()
}

// Set Store generic data
func (rs *AccountRedisStore) Set(key string, value interface{}, expiry time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to serialize data: %w", err)
	}

	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// Get Get generic data
func (rs *AccountRedisStore) Get(key string, dest interface{}) error {
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("failed to get data: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to parse data: %w", err)
	}

	return nil
}

// Delete Delete generic data
func (rs *AccountRedisStore) Delete(key string) error {
	return rs.client.Del(rs.ctx, key).Err()
}

// StoreVerification Store verification information
func (rs *AccountRedisStore) StoreVerification(verificationType VerificationType, identifier string, token string, userID string, expiry time.Duration) error {
	verification := &Verification{
		UserID:     userID,
		Type:       verificationType,
		Token:      token,
		Identifier: identifier,
		ExpiresAt:  time.Now().Add(expiry),
		CreatedAt:  time.Now(),
	}

	key := fmt.Sprintf("verification:%s:%s", string(verificationType), identifier)
	err := rs.Set(key, verification, expiry)
	if err != nil {
		return fmt.Errorf("failed to store verification information: %w", err)
	}

	err = rs.Set(fmt.Sprintf("verification:token:%s", token), identifier, expiry)
	if err != nil {
		return fmt.Errorf("failed to store verification information (2): %w", err)
	}

	return nil
}

// GetVerification Get verification information
func (rs *AccountRedisStore) GetVerification(verificationType VerificationType, identifier string) (*Verification, error) {
	key := fmt.Sprintf("verification:%s:%s", string(verificationType), identifier)
	var verification Verification
	err := rs.Get(key, &verification)
	if err != nil {
		return nil, err
	}

	// Check if expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, NewAppError(ErrCodeInvalidToken, "Verification token has expired", nil)
	}

	return &verification, nil
}

// DeleteVerification Delete verification information
func (rs *AccountRedisStore) DeleteVerification(verificationType VerificationType, identifier string, token string) error {
	key := fmt.Sprintf("verification:%s:%s", string(verificationType), identifier)
	err := rs.Delete(key)
	if err != nil {
		return fmt.Errorf("failed to delete verification information: %w", err)
	}
	key = fmt.Sprintf("verification:token:%s", token)
	err = rs.Delete(key)
	if err != nil {
		return fmt.Errorf("failed to delete verification information (2): %w", err)
	}

	return nil
}

func (rs *AccountRedisStore) GetVerificationByToken(verificationType VerificationType, token string) (*Verification, error) {
	key := fmt.Sprintf("verification:token:%s", token)
	var identifier string
	err := rs.Get(key, &identifier)
	if err != nil {
		return nil, err
	}

	verification, err := rs.GetVerification(verificationType, identifier)
	if err != nil {
		return nil, err
	}

	// Verify it's the same token
	if verification.Token != token {
		return nil, NewAppError(ErrCodeInvalidToken, "Invalid verification token", nil)
	}

	return verification, nil
}

// UpdateVerification Update verification information
func (rs *AccountRedisStore) UpdateVerification(verificationType VerificationType, identifier string, oldToken string, newToken string, expiry time.Duration) error {
	// Delete old token association
	keyIdentifier := fmt.Sprintf("verification:token:%s", oldToken)
	err := rs.Delete(keyIdentifier)
	if err != nil {
		return fmt.Errorf("failed to delete old verification token association: %w", err)
	}

	// Get verification information
	key := fmt.Sprintf("verification:%s:%s", string(verificationType), identifier)
	var verification Verification
	err = rs.Get(key, &verification)
	if err != nil {
		return fmt.Errorf("failed to get verification information: %w", err)
	}

	// Update token and expiration time
	verification.Token = newToken
	verification.ExpiresAt = time.Now().Add(expiry)

	// Save updated verification information
	err = rs.Set(key, verification, expiry)
	if err != nil {
		return fmt.Errorf("failed to update verification information: %w", err)
	}

	// Add new token association
	err = rs.Set(fmt.Sprintf("verification:token:%s", newToken), identifier, expiry)
	if err != nil {
		return fmt.Errorf("failed to add new verification token association: %w", err)
	}

	return nil
}
