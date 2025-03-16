package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 定义JWT的Claims结构
type CustomClaims struct {
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// 密钥（用于签名和验证JWT）
var jwtKey = []byte("my_secret_key")

// 生成JWT
func GenerateJWT(userID int64, email string) (string, error) {
	// 设置Token的过期时间
	expirationTime := time.Now().Add(24 * time.Hour)

	// 创建Claims
	claims := CustomClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),    // 签发时间
			Issuer:    "my_app",                          // 签发者
		},
	}

	// 创建Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 签名Token
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// 验证JWT
func ValidateJWT(tokenString string) (*CustomClaims, error) {
	// 解析Token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	// 验证Claims
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
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