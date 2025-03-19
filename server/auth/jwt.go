package auth

import (
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
)

type JWTConfig struct {
	Issuer string
}

// JWTService JWT服务
type JWTService struct {
	redis  *RedisStore
	config JWTConfig
}

// 定义JWT的Claims结构
type CustomClaims struct {
	UserID string `json:"user_id"`
	// Email     string `json:"email"`
	SessionID string `json:"session_id"`
	// KeyID     string `json:"kid"`        // 用于密钥轮换
	TokenType string `json:"token_type"` // 标识是访问令牌还是刷新令牌
	jwt.RegisteredClaims
}

// TokenPair 包含访问令牌和刷新令牌
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// JWTSession 表示JWT会话信息
type JWTSession struct {
	KeyID     string    `json:"key_id"`
	TokenType string    `json:"token_type"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

const (
	jwtKeyPrefix           = "jwt:key:"         // Redis中JWT密钥的前缀
	defaultKeyTTL          = 24 * time.Hour     // 密钥默认过期时间
	TokenExpiration        = 2 * time.Hour      // Token默认过期时间
	RefreshTokenExpiration = 7 * 24 * time.Hour // 刷新令牌过期时间
	AccessTokenType        = "access"           // 访问令牌类型
	RefreshTokenType       = "refresh"          // 刷新令牌类型
)

// NewJWTService 创建新的JWT服务
func NewJWTService(redis *RedisStore, config JWTConfig) *JWTService {
	return &JWTService{
		redis:  redis,
		config: config,
	}
}

// getKeyID 生成密钥ID
func (s *JWTService) getKeyID(userID string, sessionID string, tokenType string) string {
	// data := fmt.Sprintf("%s:%s:%d", userID, sessionID, time.Now().UnixNano())
	// hash := sha256.Sum256([]byte(data))
	// return hex.EncodeToString(hash[:])
	return fmt.Sprintf("%s:%s:%s", userID, sessionID, tokenType)
}

// generateSecretKey 生成密钥
// func (s *JWTService) generateSecretKey() (string, error) {
// 	b := make([]byte, 32)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return "", fmt.Errorf("生成随机字节失败: %w", err)
// 	}
// 	// 使用62进制编码（数字+大小写字母）来缩短ID长度
// 	return Base62Encode(b), nil
// }

// storeKey 将密钥存储到Redis
func (s *JWTService) storeKey(keyID string, key string, ttl time.Duration) error {
	return s.redis.client.Set(s.redis.ctx,
		jwtKeyPrefix+keyID,
		key,
		ttl,
	).Err()
}

// getKey 从Redis获取密钥
func (s *JWTService) getKey(keyID string) (string, error) {
	keyStr, err := s.redis.client.Get(s.redis.ctx, jwtKeyPrefix+keyID).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("key not found")
		}
		return "", err
	}

	return keyStr, nil
}

// generateToken 生成指定类型的令牌
func (s *JWTService) generateToken(userID string, sessionID, tokenType string, expiration time.Duration) (string, string, error) {
	// 生成新的密钥ID和密钥
	keyID := s.getKeyID(userID, sessionID, tokenType)
	secretKey, err := GenerateBase62ID()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate secret key: %w", err)
	}

	// 存储密钥到Redis，使用令牌的过期时间
	if err := s.storeKey(keyID, secretKey, expiration+time.Hour); err != nil {
		return "", "", fmt.Errorf("failed to store key: %w", err)
	}

	// 创建Claims
	claims := CustomClaims{
		UserID: userID,
		// Email:     email,
		SessionID: sessionID,
		// KeyID:     keyID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.Issuer,
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
func (s *JWTService) GenerateJWT(userID string, sessionID string) (string, error) {
	tokenString, _, err := s.generateToken(userID, sessionID, AccessTokenType, TokenExpiration)
	return tokenString, err
}

// GenerateTokenPair 生成访问令牌和刷新令牌对
func (s *JWTService) GenerateTokenPair(userID string, sessionID string) (*TokenPair, error) {
	// 生成访问令牌
	accessToken, _, err := s.generateToken(userID, sessionID, AccessTokenType, TokenExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// 生成刷新令牌
	refreshToken, _, err := s.generateToken(userID, sessionID, RefreshTokenType, RefreshTokenExpiration)
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
		keyID := s.getKeyID(claims.UserID, claims.SessionID, claims.TokenType)

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
	return s.GenerateTokenPair(claims.UserID, claims.SessionID)
}

// RevokeJWT 撤销JWT
func (s *JWTService) RevokeJWT(tokenString string) error {
	claims, err := s.ValidateJWT(tokenString)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	keyID := s.getKeyID(claims.UserID, claims.SessionID, claims.TokenType)

	// 从Redis删除密钥
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err()
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
	keyID := s.getKeyID(claims.UserID, claims.SessionID, claims.TokenType)
	// 从Redis删除密钥
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err()
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

// RevokeJWTByID 撤销指定ID的令牌
func (s *JWTService) RevokeJWTByID(userID string, sessionID string, tokenType string) error {
	keyID := s.getKeyID(userID, sessionID, tokenType)
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err()
}

// RevokeAllUserTokens 撤销用户的所有令牌
// func (s *JWTService) RevokeAllUserTokens(sessionID string) error {
// 	// 使用模式匹配查找所有与该会话相关的密钥
// 	pattern := jwtKeyPrefix + "*" + sessionID + "*"
// 	keys, err := s.redis.client.Keys(s.redis.ctx, pattern).Result()
// 	if err != nil {
// 		return fmt.Errorf("failed to find session keys: %w", err)
// 	}

// 	// 如果找到了密钥，删除它们
// 	if len(keys) > 0 {
// 		return s.redis.client.Del(s.redis.ctx, keys...).Err()
// 	}

// 	return nil
// }
