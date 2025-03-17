package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/go-redis/redis/v8"
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
	KeyID     string `json:"kid"`      // 用于密钥轮换
	jwt.RegisteredClaims
}

const (
	jwtKeyPrefix    = "jwt:key:"      // Redis中JWT密钥的前缀
	defaultKeyTTL   = 24 * time.Hour  // 密钥默认过期时间
	tokenExpiration = 2 * time.Hour   // Token默认过期时间
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
func (s *JWTService) storeKey(keyID string, key []byte) error {
	return s.redis.client.Set(s.redis.ctx, 
		jwtKeyPrefix+keyID, 
		hex.EncodeToString(key), 
		defaultKeyTTL,
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

// GenerateJWT 生成JWT
func (s *JWTService) GenerateJWT(userID int64, email, sessionID string) (string, error) {
	// 生成新的密钥ID和密钥
	keyID := s.generateKeyID(userID, sessionID)
	secretKey := s.generateSecretKey(userID, sessionID)

	// 存储密钥到Redis
	if err := s.storeKey(keyID, secretKey); err != nil {
		return "", fmt.Errorf("failed to store key: %w", err)
	}

	// 创建Claims
	claims := CustomClaims{
		UserID:    userID,
		Email:     email,
		SessionID: sessionID,
		KeyID:     keyID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiration)),
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
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
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

// RefreshJWT 刷新JWT
func (s *JWTService) RefreshJWT(oldTokenString string) (string, error) {
	// 验证旧Token
	claims, err := s.ValidateJWT(oldTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid old token: %w", err)
	}

	// 生成新Token
	return s.GenerateJWT(claims.UserID, claims.Email, claims.SessionID)
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

// test
// func main() {
// 	// 生成JWT
// 	token, err := GenerateJWT(123, "user@example.com")
// 	if err != nil {
// 		fmt.Println("Error generating token:", err)
// 		return
// 	}
// 	fmt.Println("Generated Token:", token)

// 	// 验证JWT
// 	claims, err := ValidateJWT(token)
// 	if err != nil {
// 		fmt.Println("Error validating token:", err)
// 		return
// 	}
// 	fmt.Printf("Valid Token Claims: %+v\n", claims)
// }