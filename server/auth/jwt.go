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

// JWT Service
type JWTService struct {
	redis  *RedisStore
	config JWTConfig
}

// Define JWT Claims structure
type CustomClaims struct {
	UserID string `json:"user_id"`
	// Email     string `json:"email"`
	SessionID string `json:"session_id"`
	// KeyID     string `json:"kid"`        // For key rotation
	TokenType string `json:"token_type"` // Identifies whether it's an access token or refresh token
	jwt.RegisteredClaims
}

// TokenPair contains access token and refresh token
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// JWTSession represents JWT session information
type JWTSession struct {
	KeyID     string    `json:"key_id"`
	TokenType string    `json:"token_type"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

const (
	jwtKeyPrefix           = "jwt:key:"         // Prefix for JWT keys in Redis
	defaultKeyTTL          = 24 * time.Hour     // Default key expiration time
	TokenExpiration        = 2 * time.Hour      // Default token expiration time
	RefreshTokenExpiration = 7 * 24 * time.Hour // Refresh token expiration time
	AccessTokenType        = "access"           // Access token type
	RefreshTokenType       = "refresh"          // Refresh token type
)

// NewJWTService Create new JWT service
func NewJWTService(redis *RedisStore, config JWTConfig) *JWTService {
	return &JWTService{
		redis:  redis,
		config: config,
	}
}

// getKeyID Generate key ID
func (s *JWTService) getKeyID(userID string, sessionID string, tokenType string) string {
	// data := fmt.Sprintf("%s:%s:%d", userID, sessionID, time.Now().UnixNano())
	// hash := sha256.Sum256([]byte(data))
	// return hex.EncodeToString(hash[:])
	return fmt.Sprintf("%s:%s:%s", userID, sessionID, tokenType)
}

// generateSecretKey Generate secret key
// func (s *JWTService) generateSecretKey() (string, error) {
// 	b := make([]byte, 32)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate random bytes: %w", err)
// 	}
// 	// Use base62 encoding (numbers + uppercase and lowercase letters) to shorten ID length
// 	return Base62Encode(b), nil
// }

// storeKey Store key to Redis
func (s *JWTService) storeKey(keyID string, key []byte, ttl time.Duration) error {
	return s.redis.client.Set(s.redis.ctx,
		jwtKeyPrefix+keyID,
		key,
		ttl,
	).Err()
}

// getKey Get key from Redis
func (s *JWTService) getKey(keyID string) ([]byte, error) {
	keyStr, err := s.redis.client.Get(s.redis.ctx, jwtKeyPrefix+keyID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key not found")
		}
		return nil, err
	}

	return keyStr, nil
}

// generateToken Generate specified type of token
func (s *JWTService) generateToken(userID string, sessionID, tokenType string, expiration time.Duration) (string, string, error) {
	// Generate new key ID and key
	keyID := s.getKeyID(userID, sessionID, tokenType)
	secretKey, err := GenerateByteID()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate secret key: %w", err)
	}

	now := time.Now()
	// Store key in Redis, using token's expiration time
	if err := s.storeKey(keyID, secretKey, expiration+time.Hour); err != nil {
		return "", "", fmt.Errorf("failed to store key: %w", err)
	}
	// Create Claims
	claims := CustomClaims{
		UserID: userID,
		// Email:     email,
		SessionID: sessionID,
		// KeyID:     keyID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.config.Issuer,
		},
	}

	// Create Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// token.Header["kid"] = keyID

	// Sign Token
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, keyID, nil
}

// GenerateJWT Generate JWT access token
func (s *JWTService) GenerateJWT(userID string, sessionID string) (string, error) {
	tokenString, _, err := s.generateToken(userID, sessionID, AccessTokenType, TokenExpiration)
	return tokenString, err
}

// GenerateTokenPair Generate access token and refresh token pair
func (s *JWTService) GenerateTokenPair(userID string, sessionID string) (*TokenPair, error) {
	// Generate access token
	accessToken, _, err := s.generateToken(userID, sessionID, AccessTokenType, TokenExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, _, err := s.generateToken(userID, sessionID, RefreshTokenType, RefreshTokenExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// ValidateJWT Validate JWT
func (s *JWTService) ValidateJWT(tokenString string) (*CustomClaims, error) {
	// Parse token (without validating signature) to get KeyID
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok {
		// 判断是否超时
		now := time.Now()
		if now.After(claims.ExpiresAt.Time) {
			return nil, fmt.Errorf("token expired")
		}
		keyID := s.getKeyID(claims.UserID, claims.SessionID, claims.TokenType)

		// Get key from Redis
		secretKey, err := s.getKey(keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get key: %w", err)
		}

		// Validate token using retrieved key
		token, err = jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secretKey, nil
		})

		if err != nil {
			return nil, fmt.Errorf("failed to validate token: %w, %s", err, tokenString)
		}

		if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
			return claims, nil
		}
	}

	return nil, fmt.Errorf("invalid token")
}

// RefreshJWT Get new token pair using refresh token
func (s *JWTService) RefreshJWT(refreshTokenString string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := s.ValidateJWT(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure it's a refresh token
	if claims.TokenType != RefreshTokenType {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// Generate new token pair
	return s.GenerateTokenPair(claims.UserID, claims.SessionID)
}

// RevokeJWT Revoke JWT
func (s *JWTService) RevokeJWT(tokenString string) error {
	claims, err := s.ValidateJWT(tokenString)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	keyID := s.getKeyID(claims.UserID, claims.SessionID, claims.TokenType)

	// Delete key from Redis
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err()
}

// RevokeRefreshJWT Specifically revoke refresh token
func (s *JWTService) RevokeRefreshJWT(refreshTokenString string) error {
	// Validate refresh token
	claims, err := s.ValidateJWT(refreshTokenString)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure it's a refresh token
	if claims.TokenType != RefreshTokenType {
		return fmt.Errorf("token is not a refresh token")
	}
	keyID := s.getKeyID(claims.UserID, claims.SessionID, claims.TokenType)
	// Delete key from Redis
	return s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err()
}

// RevokeTokenPair Revoke both access token and refresh token
func (s *JWTService) RevokeTokenPair(accessToken, refreshToken string) error {
	// Revoke access token first
	if err := s.RevokeJWT(accessToken); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	// Then revoke refresh token
	if err := s.RevokeRefreshJWT(refreshToken); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeJWTByID Revoke token with specified ID
func (s *JWTService) RevokeJWTByID(userID string, sessionID string) error {
	keyID := s.getKeyID(userID, sessionID, RefreshTokenType)
	if err := s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err(); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	keyID = s.getKeyID(userID, sessionID, AccessTokenType)
	if err := s.redis.client.Del(s.redis.ctx, jwtKeyPrefix+keyID).Err(); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}
	return nil
}

// RevokeAllUserTokens Revoke all tokens for a user
// func (s *JWTService) RevokeAllUserTokens(sessionID string) error {
// 	// Use pattern matching to find all keys related to this session
// 	pattern := jwtKeyPrefix + "*" + sessionID + "*"
// 	keys, err := s.redis.client.Keys(s.redis.ctx, pattern).Result()
// 	if err != nil {
// 		return fmt.Errorf("failed to find session keys: %w", err)
// 	}

// 	// If keys are found, delete them
// 	if len(keys) > 0 {
// 		return s.redis.client.Del(s.redis.ctx, keys...).Err()
// 	}

// 	return nil
// }
