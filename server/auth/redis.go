package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisStore Redis存储服务（通用功能）
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
		return nil, fmt.Errorf("连接Redis失败: %w", err)
	}

	return &RedisStore{
		client: client,
		ctx:    ctx,
	}, nil
}

// NewRedisStoreFromClient 从已有客户端创建Redis存储服务
func NewRedisStoreFromClient(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
		ctx:    context.Background(),
	}
}

// Set 存储通用数据
func (rs *RedisStore) Set(key string, value interface{}, expiry time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("序列化数据失败: %w", err)
	}

	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// Get 获取通用数据
func (rs *RedisStore) Get(key string, dest interface{}) error {
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
func (rs *RedisStore) Delete(key string) error {
	return rs.client.Del(rs.ctx, key).Err()
}

// GetClient 获取Redis客户端
func (rs *RedisStore) GetClient() *redis.Client {
	return rs.client
}

// Close 关闭Redis连接
func (rs *RedisStore) Close() error {
	return rs.client.Close()
}
