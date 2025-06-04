/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// Session Manager
type SessionManager struct {
	redis *SessionRedisStore
	// db    *gorm.DB
}

// NewSessionManager Create a new session manager
func NewSessionManager(redis *SessionRedisStore) *SessionManager {
	return &SessionManager{
		redis: redis,
		// db:    db,
	}
}

// CreateSession Create a new session and save to Redis
func (s *SessionManager) CreateSession(userId string, session *Session) error {
	// Calculate expiration time (seconds relative to current time)
	expiration := time.Until(session.ExpiresAt)
	if expiration <= 0 {
		return fmt.Errorf("invalid session expiration time")
	}

	// Save session to Redis
	if err := s.redis.StoreSession(userId, session.ID, session, expiration); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	// Save user session list
	if err := s.redis.StoreUserSessionList(userId, session.ID); err != nil {
		return fmt.Errorf("failed to save user session list: %w", err)
	}

	return nil
}

// GetSession Get session information from Redis
func (s *SessionManager) GetSession(userID, sessionID string) (*Session, error) {
	return s.redis.GetSession(userID, sessionID)
}

// DeleteSession Delete session from Redis
func (s *SessionManager) DeleteSession(userID, sessionID string) error {
	return s.redis.DeleteSession(userID, sessionID)
}

// RefreshSession Refresh session expiration time
func (s *SessionManager) RefreshSession(userID string, sessionID string, duration time.Duration) error {
	// Get existing session
	session, err := s.GetSession(userID, sessionID)
	if err != nil {
		return err
	}

	// Update expiration time
	session.ExpiresAt = time.Now().Add(duration)
	session.UpdatedAt = time.Now()

	// Save back to Redis
	return s.CreateSession(userID, session)
}

// Generate session ID
// func (s *SessionManager) GenerateSessionID() (string, error) {
// 	b := make([]byte, 32)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate random bytes: %w", err)
// 	}

// 	// Use base62 encoding (numbers + uppercase and lowercase letters) to shorten ID length
// 	return Base62Encode(b), nil
// }

// Create a new user session
func (s *SessionManager) CreateUserSession(userID string, ip, userAgent string, duration time.Duration) (*Session, error) {
	// Check if a session with the same IP and UserAgent exists
	session, err := s.HasSessionWithIPAndUserAgent(userID, ip, userAgent)
	// If a session with the same IP and UserAgent exists, return that session
	if session != nil && err == nil {
		// refresh session
		if err := s.RefreshSession(userID, session.ID, duration); err != nil {
			return nil, err
		}
		return session, nil
	}

	// Generate session ID
	sessionID, err := GenerateBase62String(10) // Using userID for isolation, 10 base62 characters is enough
	if err != nil {
		return nil, err
	}

	// Create session record
	now := time.Now()
	session = &Session{
		ID:        sessionID,
		UserID:    userID,
		IP:        ip,
		UserAgent: userAgent,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Save to Redis
	if err := s.CreateSession(userID, session); err != nil {
		return nil, err
	}

	return session, nil
}

// Check if session is valid
func (s *SessionManager) IsSessionValid(userID, sessionID string) bool {
	_, err := s.GetSession(userID, sessionID)
	return err == nil
}

// Get all active sessions for a user
func (s *SessionManager) GetUserSessions(userID string) ([]*Session, error) {
	sessionIDs, err := s.redis.GetUserSessionList(userID)
	if err != nil {
		return nil, err
	}

	return s.redis.GetSessionsData(userID, sessionIDs)
}

// Delete all sessions for a user (e.g., when a user changes password or logs out of all devices)
func (s *SessionManager) DeleteUserSessions(userID string) ([]string, error) {
	// Get all sessions for the user
	sessions, err := s.GetUserSessions(userID)
	if err != nil {
		return nil, err
	}

	// Deletion count
	// deletedCount := 0
	var deletedSessionIDs []string
	// Delete each session
	for _, session := range sessions {
		if err := s.DeleteSession(userID, session.ID); err == nil {
			// deletedCount++
			deletedSessionIDs = append(deletedSessionIDs, session.ID)
		}
	}

	// Delete user session list
	if err := s.redis.RemoveUserSessionList(userID, deletedSessionIDs); err != nil {
		return deletedSessionIDs, err
	}

	return deletedSessionIDs, nil
}

// Session statistics
type SessionStats struct {
	TotalSessions  int      // Total number of sessions
	ActiveSessions int      // Active sessions (within 24 hours)
	UserCount      int      // Number of unique users
	UserIDs        []string // List of user IDs
}

// Get active session statistics
func (s *SessionManager) GetSessionStats() (*SessionStats, error) {
	// Use pattern matching to get all session keys
	pattern := "session:*"
	keys, err := s.redis.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys: %w", err)
	}

	stats := &SessionStats{
		TotalSessions: len(keys),
	}

	// Store unique user IDs
	userIDMap := make(map[string]bool)

	// Time point 24 hours ago
	activeTime := time.Now().Add(-24 * time.Hour)

	// Iterate through all session keys
	for _, key := range keys {
		// Get session data
		data, err := s.redis.client.Get(context.Background(), key).Bytes()
		if err != nil {
			// Ignore non-existent keys
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, fmt.Errorf("failed to get session data: %w", err)
		}

		// Parse session data
		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			// Ignore unparseable session data
			continue
		}

		// Record unique users
		userIDMap[session.UserID] = true

		// Check if it's an active session (within 24 hours)
		if session.UpdatedAt.After(activeTime) {
			stats.ActiveSessions++
		}
	}

	// Convert user ID map to array
	stats.UserCount = len(userIDMap)
	stats.UserIDs = make([]string, 0, stats.UserCount)
	for userID := range userIDMap {
		stats.UserIDs = append(stats.UserIDs, userID)
	}

	return stats, nil
}

// Check if a session with the specified IP and UserAgent exists (to prevent session fixation attacks)
func (s *SessionManager) HasSessionWithIPAndUserAgent(userId, ip, userAgent string) (*Session, error) {
	// Use pattern matching to get all session keys
	// pattern := "session:*"
	// keys, err := s.redis.client.Keys(context.Background(), pattern).Result()
	// if err != nil {
	// 	return false, fmt.Errorf("failed to get session keys: %w", err)
	// }

	keys, err := s.redis.GetUserSessionList(userId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user session list: %w", err)
	}

	sessions, err := s.redis.GetSessionsData(userId, keys)
	if err != nil {
		return nil, err
	}

	// Iterate through all session keys
	for _, session := range sessions {
		// Check if IP and UserAgent match
		if session.IP == ip && session.UserAgent == userAgent {
			return session, nil
		}
	}

	return nil, nil
}

// Get session timeout
func (s *SessionManager) GetSessionTTL(sessionID string) (time.Duration, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	ttl, err := s.redis.client.TTL(context.Background(), sessionKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get session timeout: %w", err)
	}

	if ttl < 0 {
		// -1 means the key has no expiration time, -2 means the key does not exist
		if ttl == -2 {
			return 0, ErrInvalidSession
		}
		return 0, fmt.Errorf("session has no expiration time set")
	}

	return ttl, nil
}

// Session expiration cleaner (called by scheduled task)
// Clean up sessions that are about to expire (e.g., notify users 24 hours in advance)
func (s *SessionManager) NotifyExpiringSessionsToUsers() ([]string, error) {
	pattern := "session:*"
	var cursor uint64
	var notifiedUserIDs []string
	notifiedMap := make(map[string]bool)
	ctx := context.Background()

	// Set critical value, e.g., sessions expiring within 48 hours
	thresholdTime := time.Hour * 48

	// Use the SCAN command to scan all session keys
	for {
		var keys []string
		var err error
		keys, cursor, err = s.redis.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan session keys: %w", err)
		}

		// For each key, check its TTL
		for _, key := range keys {
			ttl, err := s.redis.client.TTL(ctx, key).Result()
			if err != nil {
				continue
			}

			// If TTL is less than the threshold, the session is about to expire
			if ttl > 0 && ttl < thresholdTime {
				// Get session data
				data, err := s.redis.client.Get(ctx, key).Bytes()
				if err != nil {
					continue
				}

				var session Session
				if err := json.Unmarshal(data, &session); err != nil {
					continue
				}

				// Record users that need to be notified
				if !notifiedMap[session.UserID] {
					notifiedMap[session.UserID] = true
					notifiedUserIDs = append(notifiedUserIDs, session.UserID)
				}
			}
		}

		// If cursor is 0, the scan is complete
		if cursor == 0 {
			break
		}
	}

	return notifiedUserIDs, nil
}

// Health check method
func (s *SessionManager) HealthCheck() error {
	// Check if Redis connection is normal
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.redis.client.Ping(ctx).Err()
	if err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	return nil
}

// Session initialization, automatically clean up expired connection information
func (s *SessionManager) Init() error {
	// Redis automatically cleans up expired keys, only do connection testing here
	return s.HealthCheck()
}
