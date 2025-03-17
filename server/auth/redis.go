package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisStore Redis存储服务
type RedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisStore 创建新的Redis存储服务
func NewRedisStore(addr, password string, db int) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &RedisStore{
		client: client,
		ctx:    ctx,
	}, nil
}

// CacheUser 缓存用户信息
func (rs *RedisStore) CacheUser(user *User) error {
	key := fmt.Sprintf("user:%d", user.ID)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	// 设置1小时过期
	return rs.client.Set(rs.ctx, key, data, time.Hour).Err()
}

// GetCachedUser 获取缓存的用户信息
func (rs *RedisStore) GetCachedUser(userID uint) (*User, error) {
	key := fmt.Sprintf("user:%d", userID)
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user from cache: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// StoreRateLimit 存储速率限制信息
func (rs *RedisStore) StoreRateLimit(ip string, count int, window time.Duration) error {
	key := fmt.Sprintf("ratelimit:%s", ip)
	return rs.client.Set(rs.ctx, key, count, window).Err()
}

// GetRateLimit 获取速率限制信息
func (rs *RedisStore) GetRateLimit(ip string) (int, error) {
	key := fmt.Sprintf("ratelimit:%s", ip)
	count, err := rs.client.Get(rs.ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// IncrRateLimit 增加速率限制计数
func (rs *RedisStore) IncrRateLimit(ip string, window time.Duration) (int, error) {
	key := fmt.Sprintf("ratelimit:%s", ip)
	pipe := rs.client.Pipeline()
	incr := pipe.Incr(rs.ctx, key)
	pipe.Expire(rs.ctx, key, window)
	_, err := pipe.Exec(rs.ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}

// StoreSession 存储会话信息
func (rs *RedisStore) StoreSession(sessionID string, data interface{}, expiry time.Duration) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}
	
	return rs.client.Set(rs.ctx, fmt.Sprintf("session:%s", sessionID), jsonData, expiry).Err()
}

// GetSession 获取会话信息
func (rs *RedisStore) GetSession(sessionID string) ([]byte, error) {
	data, err := rs.client.Get(rs.ctx, fmt.Sprintf("session:%s", sessionID)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return data, err
}

// DeleteSession 删除会话信息
func (rs *RedisStore) DeleteSession(sessionID string) error {
	return rs.client.Del(rs.ctx, fmt.Sprintf("session:%s", sessionID)).Err()
}

// Close 关闭Redis连接
func (rs *RedisStore) Close() error {
	return rs.client.Close()
}

// Set 存储任意数据到Redis
func (rs *RedisStore) Set(key string, value interface{}, expiry time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// Get 从Redis获取数据并解析到目标结构
func (rs *RedisStore) Get(key string, dest interface{}) error {
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("failed to get data: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
} 