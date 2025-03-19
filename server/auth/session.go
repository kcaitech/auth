package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// SessionManager 会话管理器
type SessionManager struct {
	redis *SessionRedisStore
	// db    *gorm.DB
}

// NewSessionManager 创建新的会话管理器
func NewSessionManager(redis *SessionRedisStore) *SessionManager {
	return &SessionManager{
		redis: redis,
		// db:    db,
	}
}

// CreateSession 创建新会话并保存到Redis
func (s *SessionManager) CreateSession(session *Session) error {
	// 计算过期时间（相对于当前时间的秒数）
	expiration := time.Until(session.ExpiresAt)
	if expiration <= 0 {
		return fmt.Errorf("会话过期时间无效")
	}

	// 保存会话到Redis
	return s.redis.StoreSession(session.ID, session, expiration)
}

// GetSession 从Redis获取会话信息
func (s *SessionManager) GetSession(sessionID string) (*Session, error) {
	return s.redis.GetSession(sessionID)
}

// DeleteSession 从Redis删除会话
func (s *SessionManager) DeleteSession(sessionID string) error {
	return s.redis.DeleteSession(sessionID)
}

// RefreshSession 刷新会话过期时间
func (s *SessionManager) RefreshSession(sessionID string, duration time.Duration) error {
	// 获取现有会话
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	// 更新过期时间
	session.ExpiresAt = time.Now().Add(duration)
	session.UpdatedAt = time.Now()

	// 重新保存到Redis
	return s.CreateSession(session)
}

// 生成会话ID
// func (s *SessionManager) GenerateSessionID() (string, error) {
// 	b := make([]byte, 32)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return "", fmt.Errorf("生成随机字节失败: %w", err)
// 	}

// 	// 使用62进制编码（数字+大小写字母）来缩短ID长度
// 	return Base62Encode(b), nil
// }

// 创建新的用户会话
func (s *SessionManager) CreateUserSession(userID string, ip, userAgent string, duration time.Duration) (*Session, error) {
	// 生成会话ID
	sessionID, err := GenerateBase62ID()
	if err != nil {
		return nil, err
	}

	// 创建会话记录
	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		IP:        ip,
		UserAgent: userAgent,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 保存到Redis
	if err := s.CreateSession(session); err != nil {
		return nil, err
	}

	return session, nil
}

// 会话是否有效
func (s *SessionManager) IsSessionValid(sessionID string) bool {
	_, err := s.GetSession(sessionID)
	return err == nil
}

// 获取用户的所有活跃会话
func (s *SessionManager) GetUserSessions(userID string) ([]*Session, error) {
	// 使用模式匹配获取所有会话键
	pattern := "session:*"
	keys, err := s.redis.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("获取会话键失败: %w", err)
	}

	// 存储匹配的会话
	sessions := make([]*Session, 0)

	// 遍历所有会话键
	for _, key := range keys {
		// 获取会话数据
		data, err := s.redis.client.Get(context.Background(), key).Bytes()
		if err != nil {
			// 忽略不存在的键（可能在我们检索键和获取数据之间过期）
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, fmt.Errorf("获取会话数据失败: %w", err)
		}

		// 解析会话数据
		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			// 忽略无法解析的会话数据
			continue
		}

		// 只收集指定用户的会话
		if session.UserID == userID {
			sessions = append(sessions, &session)
		}
	}

	return sessions, nil
}

// 删除用户的所有会话（例如，当用户更改密码或注销所有设备时）
func (s *SessionManager) DeleteUserSessions(userID string) (int, error) {
	// 获取用户的所有会话
	sessions, err := s.GetUserSessions(userID)
	if err != nil {
		return 0, err
	}

	// 删除计数
	deletedCount := 0

	// 删除每个会话
	for _, session := range sessions {
		if err := s.DeleteSession(session.ID); err == nil {
			deletedCount++
		}
	}

	return deletedCount, nil
}

// 获取会话统计
type SessionStats struct {
	TotalSessions  int      // 总会话数
	ActiveSessions int      // 活跃会话数（24小时内）
	UserCount      int      // 独立用户数
	UserIDs        []string // 用户ID列表
}

// 获取活跃会话统计
func (s *SessionManager) GetSessionStats() (*SessionStats, error) {
	// 使用模式匹配获取所有会话键
	pattern := "session:*"
	keys, err := s.redis.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("获取会话键失败: %w", err)
	}

	stats := &SessionStats{
		TotalSessions: len(keys),
	}

	// 存储唯一用户ID
	userIDMap := make(map[string]bool)

	// 24小时前的时间点
	activeTime := time.Now().Add(-24 * time.Hour)

	// 遍历所有会话键
	for _, key := range keys {
		// 获取会话数据
		data, err := s.redis.client.Get(context.Background(), key).Bytes()
		if err != nil {
			// 忽略不存在的键
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, fmt.Errorf("获取会话数据失败: %w", err)
		}

		// 解析会话数据
		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			// 忽略无法解析的会话数据
			continue
		}

		// 记录唯一用户
		userIDMap[session.UserID] = true

		// 检查是否是活跃会话（24小时内）
		if session.UpdatedAt.After(activeTime) {
			stats.ActiveSessions++
		}
	}

	// 转换用户ID映射为数组
	stats.UserCount = len(userIDMap)
	stats.UserIDs = make([]string, 0, stats.UserCount)
	for userID := range userIDMap {
		stats.UserIDs = append(stats.UserIDs, userID)
	}

	return stats, nil
}

// 检查是否存在指定IP和UserAgent的会话（防止会话固定攻击）
func (s *SessionManager) HasSessionWithIPAndUserAgent(ip, userAgent string) (bool, error) {
	// 使用模式匹配获取所有会话键
	pattern := "session:*"
	keys, err := s.redis.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return false, fmt.Errorf("获取会话键失败: %w", err)
	}

	// 遍历所有会话键
	for _, key := range keys {
		// 获取会话数据
		data, err := s.redis.client.Get(context.Background(), key).Bytes()
		if err != nil {
			// 忽略不存在的键
			if errors.Is(err, redis.Nil) {
				continue
			}
			return false, fmt.Errorf("获取会话数据失败: %w", err)
		}

		// 解析会话数据
		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			// 忽略无法解析的会话数据
			continue
		}

		// 检查IP和UserAgent是否匹配
		if session.IP == ip && session.UserAgent == userAgent {
			return true, nil
		}
	}

	return false, nil
}

// 使用Redis扫描批量获取用户会话（优化性能）
func (s *SessionManager) GetUserSessionsOptimized(userID string) ([]*Session, error) {
	ctx := context.Background()
	var cursor uint64
	var sessions []*Session
	var keys []string

	// 使用Redis的SCAN操作，避免阻塞Redis
	for {
		var scanKeys []string
		var err error
		scanKeys, cursor, err = s.redis.client.Scan(ctx, cursor, "session:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("扫描会话键失败: %w", err)
		}

		keys = append(keys, scanKeys...)

		// 如果cursor为0，表示扫描完成
		if cursor == 0 {
			break
		}
	}

	// 如果没有找到键，直接返回空结果
	if len(keys) == 0 {
		return []*Session{}, nil
	}

	// 使用管道批量获取会话数据
	pipe := s.redis.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))

	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("批量获取会话失败: %w", err)
	}

	// 处理结果
	for _, cmd := range cmds {
		data, err := cmd.Bytes()
		// 跳过不存在或错误的键
		if err != nil {
			continue
		}

		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		// 匹配用户ID
		if session.UserID == userID {
			sessions = append(sessions, &session)
		}
	}

	return sessions, nil
}

// 批量会话管理（使用Redis管道提高性能）
func (s *SessionManager) BatchRefreshSessions(sessionIDs []string, duration time.Duration) (int, error) {
	// 如果没有会话ID，直接返回
	if len(sessionIDs) == 0 {
		return 0, nil
	}

	ctx := context.Background()
	pipe := s.redis.client.Pipeline()
	getCmds := make([]*redis.StringCmd, len(sessionIDs))
	sessionKeys := make([]string, len(sessionIDs))

	// 准备所有get命令
	for i, id := range sessionIDs {
		sessionKeys[i] = fmt.Sprintf("session:%s", id)
		getCmds[i] = pipe.Get(ctx, sessionKeys[i])
	}

	// 执行所有get命令
	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("批量获取会话失败: %w", err)
	}

	// 准备所有set命令
	pipe = s.redis.client.Pipeline()
	successCount := 0

	for i, cmd := range getCmds {
		data, err := cmd.Bytes()
		if err != nil {
			continue
		}

		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		// 更新会话
		session.ExpiresAt = time.Now().Add(duration)
		session.UpdatedAt = time.Now()

		// 序列化并保存
		updatedData, err := json.Marshal(session)
		if err != nil {
			continue
		}

		expiration := time.Until(session.ExpiresAt)
		pipe.Set(ctx, sessionKeys[i], updatedData, expiration)
		successCount++
	}

	// 执行所有set命令
	if successCount > 0 {
		_, err = pipe.Exec(ctx)
		if err != nil {
			return 0, fmt.Errorf("批量更新会话失败: %w", err)
		}
	}

	return successCount, nil
}

// 获取会话超时时间
func (s *SessionManager) GetSessionTTL(sessionID string) (time.Duration, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	ttl, err := s.redis.client.TTL(context.Background(), sessionKey).Result()
	if err != nil {
		return 0, fmt.Errorf("获取会话超时时间失败: %w", err)
	}

	if ttl < 0 {
		// -1表示键没有设置过期时间，-2表示键不存在
		if ttl == -2 {
			return 0, ErrInvalidSession
		}
		return 0, fmt.Errorf("会话没有设置过期时间")
	}

	return ttl, nil
}

// 会话即将过期清理器（由定时任务调用）
// 清理即将过期的会话（例如，提前24小时通知用户）
func (s *SessionManager) NotifyExpiringSessionsToUsers() ([]string, error) {
	pattern := "session:*"
	var cursor uint64
	var notifiedUserIDs []string
	notifiedMap := make(map[string]bool)
	ctx := context.Background()

	// 设置临界值，例如48小时内过期的会话
	thresholdTime := time.Hour * 48

	// 使用SCAN命令扫描所有会话键
	for {
		var keys []string
		var err error
		keys, cursor, err = s.redis.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("扫描会话键失败: %w", err)
		}

		// 对于每个键，检查其TTL
		for _, key := range keys {
			ttl, err := s.redis.client.TTL(ctx, key).Result()
			if err != nil {
				continue
			}

			// 如果TTL小于阈值，表示会话即将过期
			if ttl > 0 && ttl < thresholdTime {
				// 获取会话数据
				data, err := s.redis.client.Get(ctx, key).Bytes()
				if err != nil {
					continue
				}

				var session Session
				if err := json.Unmarshal(data, &session); err != nil {
					continue
				}

				// 记录需要通知的用户
				if !notifiedMap[session.UserID] {
					notifiedMap[session.UserID] = true
					notifiedUserIDs = append(notifiedUserIDs, session.UserID)
				}
			}
		}

		// 如果cursor为0，表示扫描完成
		if cursor == 0 {
			break
		}
	}

	return notifiedUserIDs, nil
}

// 健康检查方法
func (s *SessionManager) HealthCheck() error {
	// 检查Redis连接是否正常
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.redis.client.Ping(ctx).Err()
	if err != nil {
		return fmt.Errorf("redis连接失败: %w", err)
	}

	return nil
}

// 会话初始化，自动清理过期的连接信息
func (s *SessionManager) Init() error {
	// Redis自动会清理过期键，这里只做连接测试
	return s.HealthCheck()
}
