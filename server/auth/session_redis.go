package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// SessionRedisStore 会话相关的Redis存储服务
type SessionRedisStore struct {
	client *redis.Client
	ctx    context.Context
}

// NewSessionRedisStore 创建新的会话Redis存储服务
func NewSessionRedisStore(client *redis.Client) *SessionRedisStore {
	return &SessionRedisStore{
		client: client,
		ctx:    context.Background(),
	}
}

// StoreSession 存储会话信息
func (rs *SessionRedisStore) StoreSession(userID string, sessionID string, session *Session, expiry time.Duration) error {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("序列化会话数据失败: %w", err)
	}

	return rs.client.Set(rs.ctx, key, data, expiry).Err()
}

// StoreUserSessionList 存储用户会话列表
func (rs *SessionRedisStore) StoreUserSessionList(userID string, sessionID string) error {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return rs.client.SAdd(rs.ctx, key, sessionID).Err()
}

// GetUserSessionList 获取用户会话列表
func (rs *SessionRedisStore) GetUserSessionList(userID string) ([]string, error) {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return rs.client.SMembers(rs.ctx, key).Result()
}

// DeleteUserSessionList 删除用户会话列表
func (rs *SessionRedisStore) DeleteUserSessionList(userID string) error {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return rs.client.Del(rs.ctx, key).Err()
}

// UpdateUserSessionList 更新用户会话列表
func (rs *SessionRedisStore) RemoveUserSessionList(userID string, sessionIDs []string) error {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return rs.client.SRem(rs.ctx, key, sessionIDs).Err()
}

// GetSession 获取会话信息
func (rs *SessionRedisStore) GetSession(userID, sessionID string) (*Session, error) {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	data, err := rs.client.Get(rs.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrInvalidSession
		}
		return nil, fmt.Errorf("获取会话数据失败: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("解析会话数据失败: %w", err)
	}

	return &session, nil
}

// DeleteSession 删除会话信息
func (rs *SessionRedisStore) DeleteSession(userID, sessionID string) error {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	return rs.client.Del(rs.ctx, key).Err()
}

// ListSessionKeys 列出所有会话键
// func (rs *SessionRedisStore) ListSessionKeys() ([]string, error) {
// 	return rs.client.Keys(rs.ctx, "session:*").Result()
// }

// ScanSessions 使用扫描方式获取会话键
// func (rs *SessionRedisStore) ScanSessions(count int64) ([]string, uint64, error) {
// 	return rs.client.Scan(rs.ctx, 0, "session:*", count).Result()
// }

// GetSessionTTL 获取会话过期时间
func (rs *SessionRedisStore) GetSessionTTL(userID, sessionID string) (time.Duration, error) {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	return rs.client.TTL(rs.ctx, key).Result()
}

// ExtendSession 延长会话过期时间
func (rs *SessionRedisStore) ExtendSession(userID, sessionID string, expiry time.Duration) error {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	return rs.client.Expire(rs.ctx, key, expiry).Err()
}

// Pipeline 获取管道以执行批量操作
func (rs *SessionRedisStore) Pipeline() redis.Pipeliner {
	return rs.client.Pipeline()
}

// ExecutePipeline 执行管道中的命令
func (rs *SessionRedisStore) ExecutePipeline(pipe redis.Pipeliner) ([]redis.Cmder, error) {
	return pipe.Exec(rs.ctx)
}

// GetSessionsData 获取多个会话的数据
func (rs *SessionRedisStore) GetSessionsData(userID string, sessionIDs []string) ([]*Session, error) {
	if len(sessionIDs) == 0 {
		return []*Session{}, nil
	}

	pipe := rs.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(sessionIDs))

	for i, id := range sessionIDs {
		key := fmt.Sprintf("session:%s:%s", userID, id)
		cmds[i] = pipe.Get(rs.ctx, key)
	}

	_, err := pipe.Exec(rs.ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("批量获取会话失败: %w", err)
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
