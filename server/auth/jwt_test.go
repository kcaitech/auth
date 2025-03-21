package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Test secret key
var testSecretKey = []byte("test-secret-key-for-jwt-testing")

// Create JWTService for testing
// func setupJWTService() *JWTService {
// 	// Create mock RedisStore
// 	mockRedis := &RedisStore{
// 		client: redis.NewClient(&redis.Options{
// 			Addr: "localhost:6379", // Use local Redis or mock
// 		}),
// 		ctx: context.Background(),
// 	}

// 	return NewJWTService(mockRedis, JWTConfig{
// 		Issuer: "kcauth-test",
// 	})
// }

// Create a simplified GenerateJWT function for testing
func testGenerateJWT(userID string) (string, error) {
	// Create Claims
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

	// Create Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// token.Header["kid"] = claims.KeyID

	// Sign Token
	return token.SignedString(testSecretKey)
}

// Create a simplified ValidateJWT function for testing
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
	// Test data
	userID := "123"
	// email := "test@example.com"

	// Test generating JWT
	token, err := testGenerateJWT(userID)
	if err != nil {
		t.Errorf("Failed to generate JWT: %v", err)
	}
	if token == "" {
		t.Error("Generated token cannot be empty")
	}

	// Test validating JWT
	claims, err := testValidateJWT(token)
	if err != nil {
		t.Errorf("Failed to validate JWT: %v", err)
	}

	// Verify that the data in claims is correct
	if claims.UserID != userID {
		t.Errorf("userID does not match, expected: %s, actual: %s", userID, claims.UserID)
	}
	// if claims.Email != email {
	// 	t.Errorf("Email does not match, expected: %s, actual: %s", email, claims.Email)
	// }
}

func TestInvalidToken(t *testing.T) {
	// Test invalid token
	invalidToken := "invalid.token.string"
	_, err := testValidateJWT(invalidToken)
	if err == nil {
		t.Error("Expected error for invalid token, but did not get one")
	}
}

func TestExpiredToken(t *testing.T) {
	// Create an expired token
	claims := CustomClaims{
		UserID: "123",
		// Email:     "test@example.com",
		SessionID: "test-session",
		// KeyID:     "test-key-id",
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)), // Set expiration time to 24 hours ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			Issuer:    "kcauth-test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testSecretKey)

	// Validate expired token
	_, err := testValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for expired token, but did not get one")
	}
}
