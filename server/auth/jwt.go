package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
)

// JWTService JWT服务
type JWTService struct {
	redis *RedisStore
}

// 定义JWT的Claims结构
type CustomClaims struct {
	UserID    int64  `json:"user_id"`
	Email     string `json:"email"`
	SessionID string `json:"session_id"`
	KeyID     string `json:"kid"`        // 用于密钥轮换
	TokenType string `json:"token_type"` // 标识是访问令牌还是刷新令牌
	jwt.RegisteredClaims
}

// TokenPair 包含访问令牌和刷新令牌
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

const (
	jwtKeyPrefix           = "jwt:key:"         // Redis中JWT密钥的前缀
	defaultKeyTTL          = 24 * time.Hour     // 密钥默认过期时间
	tokenExpiration        = 2 * time.Hour      // Token默认过期时间
	refreshTokenExpiration = 7 * 24 * time.Hour // 刷新令牌过期时间
	AccessTokenType        = "access"           // 访问令牌类型
	RefreshTokenType       = "refresh"          // 刷新令牌类型
)

// NewJWTService 创建新的JWT服务
func NewJWTService(redis *RedisStore) *JWTService {
	return &JWTService{
		redis: redis,
	}
}

// generateKeyID 生成密钥ID
func (s *JWTService) generateKeyID(userID int64, sessionID string) string {
	data := fmt.Sprintf("%d:%s:%d", userID, sessionID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateSecretKey 生成密钥
func (s *JWTService) generateSecretKey(userID int64, sessionID string) []byte {
	data := fmt.Sprintf("%d:%s:%s", userID, sessionID, time.Now().String())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// storeKey 将密钥存储到Redis
func (s *JWTService) storeKey(keyID string, key []byte, ttl time.Duration) error {
	return s.redis.client.Set(s.redis.ctx,
		jwtKeyPrefix+keyID,
		hex.EncodeToString(key),
		ttl,
	).Err()
}

// getKey 从Redis获取密钥
func (s *JWTService) getKey(keyID string) ([]byte, error) {
	keyStr, err := s.redis.client.Get(s.redis.ctx, jwtKeyPrefix+keyID).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key not found")
		}
		return nil, err
	}

	return hex.DecodeString(keyStr)
}

// generateToken 生成指定类型的令牌
func (s *JWTService) generateToken(userID int64, email, sessionID, tokenType string, expiration time.Duration) (string, string, error) {
	// 生成新的密钥ID和密钥
	keyID := s.generateKeyID(userID, sessionID)
	secretKey := s.generateSecretKey(userID, sessionID)

	// 存储密钥到Redis，使用令牌的过期时间
	if err := s.storeKey(keyID, secretKey, expiration+time.Hour); err != nil {
		return "", "", fmt.Errorf("failed to store key: %w", err)
	}

	// 创建Claims
	claims := CustomClaims{
		UserID:    userID,
		Email:     email,
		SessionID: sessionID,
		KeyID:     keyID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "kcauth",
		},
	}

	// 创建Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID

	// 签名Token
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, keyID, nil
}

// GenerateJWT 生成JWT访问令牌
func (s *JWTService) GenerateJWT(userID int64, email, sessionID string) (string, error) {
	tokenString, _, err := s.generateToken(userID, email, sessionID, AccessTokenType, tokenExpiration)
	return tokenString, err
}

// GenerateTokenPair 生成访问令牌和刷新令牌对
func (s *JWTService) GenerateTokenPair(userID int64, email, sessionID string) (*TokenPair, error) {
	// 生成访问令牌
	accessToken, _, err := s.generateToken(userID, email, sessionID, AccessTokenType, tokenExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// 生成刷新令牌
	refreshToken, _, err := s.generateToken(userID, email, sessionID, RefreshTokenType, refreshTokenExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// ValidateJWT 验证JWT
func (s *JWTService) ValidateJWT(tokenString string) (*CustomClaims, error) {
	// 解析Token（不验证签名）以获取KeyID
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok {
		keyID := claims.KeyID

		// 从Redis获取密钥
		secretKey, err := s.getKey(keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get key: %w", err)
		}

		// 使用获取到的密钥验证Token
		token, err = jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secretKey, nil
		})

		if err != nil {
			return nil, fmt.Errorf("failed to validate token: %w", err)
		}

		if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
			return claims, nil
		}
	}

	return nil, fmt.Errorf("invalid token")
}

// RefreshJWT 使用刷新令牌获取新的令牌对
func (s *JWTService) RefreshJWT(refreshTokenString string) (*TokenPair, error) {
	// 验证刷新令牌
	claims, err := s.ValidateJWT(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// 确保是刷新令牌
	if claims.TokenType != RefreshTokenType {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// 生成新的令牌对
	return s.GenerateTokenPair(claims.UserID, claims.Email, claims.SessionID)
}

// RevokeJWT 撤销JWT
func (s *JWTService) RevokeJWT(tokenString string) error {
	claims, err := s.ValidateJWT(tokenString)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	// 从Redis删除密钥
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+claims.KeyID).Err()
}

// RevokeRefreshJWT 专门撤销刷新令牌
func (s *JWTService) RevokeRefreshJWT(refreshTokenString string) error {
	// 验证刷新令牌
	claims, err := s.ValidateJWT(refreshTokenString)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	// 确保是刷新令牌
	if claims.TokenType != RefreshTokenType {
		return fmt.Errorf("token is not a refresh token")
	}

	// 从Redis删除密钥
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+claims.KeyID).Err()
}

// RevokeTokenPair 同时撤销访问令牌和刷新令牌
func (s *JWTService) RevokeTokenPair(accessToken, refreshToken string) error {
	// 先撤销访问令牌
	if err := s.RevokeJWT(accessToken); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	// 再撤销刷新令牌
	if err := s.RevokeRefreshJWT(refreshToken); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeAllUserTokens 撤销用户的所有令牌
func (s *JWTService) RevokeAllUserTokens(sessionID string) error {
	// 使用模式匹配查找所有与该会话相关的密钥
	pattern := jwtKeyPrefix + "*" + sessionID + "*"
	keys, err := s.redis.client.Keys(s.redis.ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to find session keys: %w", err)
	}

	// 如果找到了密钥，删除它们
	if len(keys) > 0 {
		return s.redis.client.Del(s.redis.ctx, keys...).Err()
	}

	return nil
}

// GenerateToken 生成JWT令牌
func (s *JWTService) GenerateToken(userID uint, username string, role UserRole) (string, error) {
	// 将 uint 转换为 int64
	userId := int64(userID)

	// 生成唯一的会话ID
	sessionID := fmt.Sprintf("session_%d_%d", userId, time.Now().UnixNano())

	// 生成令牌
	token, _, err := s.generateToken(userId, username, sessionID, AccessTokenType, tokenExpiration)
	if err != nil {
		return "", fmt.Errorf("生成令牌失败: %w", err)
	}

	return token, nil
}
