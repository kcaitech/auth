package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 测试用的密钥
var testSecretKey = []byte("test-secret-key-for-jwt-testing")

// 创建测试用的 JWTService
// func setupJWTService() *JWTService {
// 	// 创建模拟的 RedisStore
// 	mockRedis := &RedisStore{
// 		client: redis.NewClient(&redis.Options{
// 			Addr: "localhost:6379", // 使用本地Redis或模拟
// 		}),
// 		ctx: context.Background(),
// 	}

// 	return NewJWTService(mockRedis, JWTConfig{
// 		Issuer: "kcauth-test",
// 	})
// }

// 为测试创建一个简化版的 GenerateJWT 函数
func testGenerateJWT(userID string) (string, error) {
	// 创建Claims
	claims := CustomClaims{
		UserID: userID,
		// Email:     email,
		SessionID: "test-session",
		// KeyID:     "test-key-id",
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "kcauth-test",
		},
	}

	// 创建Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// token.Header["kid"] = claims.KeyID

	// 签名Token
	return token.SignedString(testSecretKey)
}

// 为测试创建一个简化版的 ValidateJWT 函数
func testValidateJWT(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return testSecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

func TestGenerateAndValidateJWT(t *testing.T) {
	// 测试数据
	userID := "123"
	// email := "test@example.com"

	// 测试生成JWT
	token, err := testGenerateJWT(userID)
	if err != nil {
		t.Errorf("生成JWT失败: %v", err)
	}
	if token == "" {
		t.Error("生成的token不能为空")
	}

	// 测试验证JWT
	claims, err := testValidateJWT(token)
	if err != nil {
		t.Errorf("验证JWT失败: %v", err)
	}

	// 验证claims中的数据是否正确
	if claims.UserID != userID {
		t.Errorf("userID不匹配, 期望: %d, 实际: %d", userID, claims.UserID)
	}
	// if claims.Email != email {
	// 	t.Errorf("Email不匹配, 期望: %s, 实际: %s", email, claims.Email)
	// }
}

func TestInvalidToken(t *testing.T) {
	// 测试无效的token
	invalidToken := "invalid.token.string"
	_, err := testValidateJWT(invalidToken)
	if err == nil {
		t.Error("期望无效token返回错误，但是没有")
	}
}

func TestExpiredToken(t *testing.T) {
	// 创建一个已过期的token
	claims := CustomClaims{
		UserID: "123",
		// Email:     "test@example.com",
		SessionID: "test-session",
		// KeyID:     "test-key-id",
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)), // 过期时间设置为24小时前
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			Issuer:    "kcauth-test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testSecretKey)

	// 验证过期的token
	_, err := testValidateJWT(tokenString)
	if err == nil {
		t.Error("期望过期token返回错误，但是没有")
	}
}
