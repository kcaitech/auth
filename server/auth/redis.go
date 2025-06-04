/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
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

// prefix
const (
	PrefixSession         = "session:"
	PrefixUser            = "user:"
	PrefixToken           = "token:"
	PrefixRateLimit       = "ratelimit:"
	PrefixLoginAttempts   = "login_attempts:"
	PrefixGoogleState     = "google_oauth_state:"
	PrefixWeixinState     = "weixin_oauth_state:"
	PrefixEmailState      = "email_state:"
	PrefixEmailVerifyCode = "email_verify_code:"
)

// RedisStore Redis storage service (general functionality)
type RedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisStore Create a new Redis storage service
func NewRedisStore(addr, password string, db int) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStore{
		client: client,
		ctx:    ctx,
	}, nil
}

// NewRedisStoreFromClient Create Redis storage service from existing client
func NewRedisStoreFromClient(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
		ctx:    context.Background(),
	}
}

// Set Store general data
func (rs *RedisStore) Set(key string, value interface{}, expiry time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to serialize data: %w", err)
	}

	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// Get Retrieve general data
func (rs *RedisStore) Get(key string, dest interface{}) error {
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

// Delete Delete general data
func (rs *RedisStore) Delete(key string) error {
	return rs.client.Del(rs.ctx, key).Err()
}

// GetClient Get Redis client
func (rs *RedisStore) GetClient() *redis.Client {
	return rs.client
}

// Close Close Redis connection
func (rs *RedisStore) Close() error {
	return rs.client.Close()
}

// SAdd Add member to set
func (rs *RedisStore) SAdd(key string, member interface{}) error {
	return rs.client.SAdd(rs.ctx, key, member).Err()
}

// SMembers Get all members of set
func (rs *RedisStore) SMembers(key string) ([]string, error) {
	return rs.client.SMembers(rs.ctx, key).Result()
}
