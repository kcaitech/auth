package auth

import (
	"testing"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidateJWT(t *testing.T) {
	// 测试数据
	userID := int64(123)
	email := "test@example.com"

	// 测试生成JWT
	token, err := GenerateJWT(userID, email)
	if err != nil {
		t.Errorf("生成JWT失败: %v", err)
	}
	if token == "" {
		t.Error("生成的token不能为空")
	}

	// 测试验证JWT
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Errorf("验证JWT失败: %v", err)
	}

	// 验证claims中的数据是否正确
	if claims.UserID != userID {
		t.Errorf("UserID不匹配, 期望: %d, 实际: %d", userID, claims.UserID)
	}
	if claims.Email != email {
		t.Errorf("Email不匹配, 期望: %s, 实际: %s", email, claims.Email)
	}
}

func TestInvalidToken(t *testing.T) {
	// 测试无效的token
	invalidToken := "invalid.token.string"
	_, err := ValidateJWT(invalidToken)
	if err == nil {
		t.Error("期望无效token返回错误，但是没有")
	}
}

func TestExpiredToken(t *testing.T) {
	// 创建一个已过期的token
	claims := CustomClaims{
		UserID: 123,
		Email:  "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)), // 过期时间设置为24小时前
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			Issuer:    "my_app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtKey)

	// 验证过期的token
	_, err := ValidateJWT(tokenString)
	if err == nil {
		t.Error("期望过期token返回错误，但是没有")
	}
}