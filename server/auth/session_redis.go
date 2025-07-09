/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"kcaitech.com/kcauth/server/common"
)

const (
	RedisPrefixSession = common.RedisKeySession
)

// SessionRedisStore Session-related Redis storage service
type SessionRedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewSessionRedisStore Create a new session Redis storage service
func NewSessionRedisStore(client *redis.Client) *SessionRedisStore {
	return &SessionRedisStore{
		client: client,
		ctx:    context.Background(),
	}
}

// StoreSession Store session information
func (rs *SessionRedisStore) StoreSession(userID string, sessionID string, session *Session, expiry time.Duration) error {
	key := fmt.Sprintf("%s%s:%s", RedisPrefixSession, userID, sessionID)
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to serialize session data: %w", err)
	}

	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// GetUserSessionList Get user session list
func (rs *SessionRedisStore) GetUserSessionList(userID string) ([]string, error) {
	keys, err := rs.client.Keys(rs.ctx, fmt.Sprintf("%s%s:*", RedisPrefixSession, userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys: %w", err)
	}
	sessionIDs := make([]string, len(keys))
	for i, key := range keys {
		sessionIDs[i] = strings.TrimPrefix(key, fmt.Sprintf("%s%s:", RedisPrefixSession, userID))
	}
	return sessionIDs, nil
}

// GetSession Get session information
func (rs *SessionRedisStore) GetSession(userID, sessionID string) (*Session, error) {
	key := fmt.Sprintf("%s%s:%s", RedisPrefixSession, userID, sessionID)
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrInvalidSession
		}
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	return &session, nil
}

// DeleteSession Delete session information
func (rs *SessionRedisStore) DeleteSession(userID, sessionID string) error {
	key := fmt.Sprintf("%s%s:%s", RedisPrefixSession, userID, sessionID)
	return rs.client.Del(rs.ctx, key).Err()
}

// GetSessionTTL Get session expiration time
func (rs *SessionRedisStore) GetSessionTTL(userID, sessionID string) (time.Duration, error) {
	key := fmt.Sprintf("%s%s:%s", RedisPrefixSession, userID, sessionID)
	return rs.client.TTL(rs.ctx, key).Result()
}

// ExtendSession Extend session expiration time
func (rs *SessionRedisStore) ExtendSession(userID, sessionID string, expiry time.Duration) error {
	key := fmt.Sprintf("%s%s:%s", RedisPrefixSession, userID, sessionID)
	return rs.client.Expire(rs.ctx, key, expiry).Err()
}

// Pipeline Get pipeline to execute batch operations
func (rs *SessionRedisStore) Pipeline() redis.Pipeliner {
	return rs.client.Pipeline()
}

// ExecutePipeline Execute commands in the pipeline
func (rs *SessionRedisStore) ExecutePipeline(pipe redis.Pipeliner) ([]redis.Cmder, error) {
	return pipe.Exec(rs.ctx)
}

// GetSessionsData Get data for multiple sessions
func (rs *SessionRedisStore) GetSessionsData(userID string, sessionIDs []string) ([]*Session, error) {
	if len(sessionIDs) == 0 {
		return []*Session{}, nil
	}

	pipe := rs.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(sessionIDs))

	for i, id := range sessionIDs {
		key := fmt.Sprintf("%s%s:%s", RedisPrefixSession, userID, id)
		cmds[i] = pipe.Get(rs.ctx, key)
	}

	_, err := pipe.Exec(rs.ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to batch get sessions: %w", err)
	}

	var sessions []*Session
	for _, cmd := range cmds {
		data, err := cmd.Bytes()
		if err != nil {
			continue
		}

		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		sessions = append(sessions, &session)
	}

	return sessions, nil
}
