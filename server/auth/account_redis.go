package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// AccountRedisStore 账户相关的Redis存储服务
type AccountRedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewAccountRedisStore 创建新的账户Redis存储服务
func NewAccountRedisStore(client *redis.Client) *AccountRedisStore {
	return &AccountRedisStore{
		client: client,
		ctx:    context.Background(),
	}
}

// CacheUser 缓存用户信息
func (rs *AccountRedisStore) CacheUser(user *User) error {
	key := fmt.Sprintf("user:%s", user.UserID)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("序列化用户数据失败: %w", err)
	}

	// 设置1小时过期
	return rs.client.Set(rs.ctx, key, data, time.Hour).Err()
}

// GetCachedUser 获取缓存的用户信息
func (rs *AccountRedisStore) GetCachedUser(userID string) (*User, error) {
	key := fmt.Sprintf("user:%s", userID)
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("从缓存获取用户数据失败: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("解析用户数据失败: %w", err)
	}

	return &user, nil
}

// InvalidateUserCache 使用户缓存失效
func (rs *AccountRedisStore) InvalidateUserCache(userID string) error {
	key := fmt.Sprintf("user:%s", userID)
	return rs.client.Del(rs.ctx, key).Err()
}

// CacheLoginAttempts 缓存登录尝试次数
func (rs *AccountRedisStore) CacheLoginAttempts(userID string, ip string, count int, duration time.Duration) error {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	return rs.client.Set(rs.ctx, key, count, duration).Err()
}

// GetLoginAttempts 获取登录尝试次数
func (rs *AccountRedisStore) GetLoginAttempts(userID string, ip string) (int, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	count, err := rs.client.Get(rs.ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("获取登录尝试次数失败: %w", err)
	}
	return count, nil
}

// IncrLoginAttempts 增加登录尝试次数
func (rs *AccountRedisStore) IncrLoginAttempts(userID string, ip string, duration time.Duration) (int, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	pipe := rs.client.Pipeline()
	incr := pipe.Incr(rs.ctx, key)
	pipe.Expire(rs.ctx, key, duration)
	_, err := pipe.Exec(rs.ctx)
	if err != nil {
		return 0, fmt.Errorf("增加登录尝试次数失败: %w", err)
	}
	return int(incr.Val()), nil
}

// ResetLoginAttempts 重置登录尝试次数
func (rs *AccountRedisStore) ResetLoginAttempts(userID string, ip string) error {
	key := fmt.Sprintf("login_attempts:%s:%s", userID, ip)
	return rs.client.Del(rs.ctx, key).Err()
}

// Set 存储通用数据
func (rs *AccountRedisStore) Set(key string, value interface{}, expiry time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("序列化数据失败: %w", err)
	}

	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// Get 获取通用数据
func (rs *AccountRedisStore) Get(key string, dest interface{}) error {
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("获取数据失败: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("解析数据失败: %w", err)
	}

	return nil
}

// Delete 删除通用数据
func (rs *AccountRedisStore) Delete(key string) error {
	return rs.client.Del(rs.ctx, key).Err()
}

// StoreVerification 存储验证信息
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
		return fmt.Errorf("存储验证信息失败: %w", err)
	}

	err = rs.Set(fmt.Sprintf("verification:identifier:%s", token), identifier, expiry)
	if err != nil {
		return fmt.Errorf("存储验证信息失败2: %w", err)
	}

	return nil
}

// GetVerification 获取验证信息
func (rs *AccountRedisStore) GetVerification(verificationType VerificationType, identifier string) (*Verification, error) {
	key := fmt.Sprintf("verification:%s:%s", string(verificationType), identifier)
	var verification Verification
	err := rs.Get(key, &verification)
	if err != nil {
		return nil, err
	}

	// 验证是否过期
	if verification.ExpiresAt.After(time.Now()) {
		return nil, NewAppError(ErrCodeInvalidToken, "验证令牌已过期", nil)
	}

	return &verification, nil
}

// DeleteVerification 删除验证信息
func (rs *AccountRedisStore) DeleteVerification(verificationType VerificationType, identifier string, token string) error {
	key := fmt.Sprintf("verification:%s:%s", string(verificationType), identifier)
	err := rs.Delete(key)
	if err != nil {
		return fmt.Errorf("删除验证信息失败: %w", err)
	}
	key = fmt.Sprintf("verification:identifier:%s", token)
	err = rs.Delete(key)
	if err != nil {
		return fmt.Errorf("删除验证信息失败2: %w", err)
	}

	return nil
}

func (rs *AccountRedisStore) GetVerificationByToken(verificationType VerificationType, token string) (*Verification, error) {
	key := fmt.Sprintf("verification:identifier:%s", token)
	var identifier string
	err := rs.Get(key, &identifier)
	if err != nil {
		return nil, err
	}

	verification, err := rs.GetVerification(verificationType, identifier)
	if err != nil {
		return nil, err
	}

	// 验证下是否同一个token
	if verification.Token != token {
		return nil, NewAppError(ErrCodeInvalidToken, "验证令牌无效", nil)
	}

	return verification, nil
}
