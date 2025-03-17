package auth

import (
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin"
)

// ErrorCode 错误码类型
type ErrorCode int

const (
	// 通用错误码 (1000-1999)
	ErrCodeInternal ErrorCode = 1000 + iota
	ErrCodeInvalidRequest
	ErrCodeUnauthorized
	ErrCodeForbidden
	ErrCodeNotFound
	ErrCodeConflict
	ErrCodeTooManyRequests

	// 认证相关错误码 (2000-2999)
	ErrCodeInvalidCredentials ErrorCode = 2000 + iota
	ErrCodeInvalidToken
	ErrCodeTokenExpired
	ErrCodeInvalidSession
	ErrCodeUserNotFound
	ErrCodeUserDisabled
	ErrCodeWeakPassword
	ErrCodeDuplicateUser
	ErrCodeInvalidOAuthState
	ErrCodeOAuthFailed
	ErrCodeInvalidPassword
	ErrCodeUsernameTaken
	ErrCodeEmailTaken
	ErrCodeInvalidUsername
	ErrCodeInvalidEmail
	ErrCodeTooManyAttempts
	
	// 第三方登录相关错误码 (3000-3999)
	ErrCodeInvalidConfig ErrorCode = 3000 + iota
	ErrCodeInvalidCode
	ErrCodeAPIRequest
)

// AppError 应用错误类型
type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
	Err     error    `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// NewAppError 创建新的应用错误
func NewAppError(code ErrorCode, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// ErrorResponse 错误响应结构
type ErrorResponse struct {
	Error struct {
		Code    ErrorCode `json:"code"`
		Message string    `json:"message"`
		Details string    `json:"details,omitempty"`
	} `json:"error"`
}

// GetHTTPStatus 获取对应的HTTP状态码
func (e *AppError) GetHTTPStatus() int {
	switch e.Code {
	case ErrCodeInvalidRequest:
		return http.StatusBadRequest
	case ErrCodeUnauthorized, ErrCodeInvalidCredentials, ErrCodeInvalidToken, ErrCodeTokenExpired:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeNotFound, ErrCodeUserNotFound:
		return http.StatusNotFound
	case ErrCodeConflict, ErrCodeDuplicateUser:
		return http.StatusConflict
	case ErrCodeTooManyRequests:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// ErrorHandler 统一错误处理中间件
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// 检查是否有错误
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			var appErr *AppError
			if e, ok := err.(*AppError); ok {
				appErr = e
			} else {
				// 将普通错误转换为应用错误
				appErr = NewAppError(ErrCodeInternal, "Internal server error", err)
			}

			response := ErrorResponse{}
			response.Error.Code = appErr.Code
			response.Error.Message = appErr.Message
			if appErr.Details != "" {
				response.Error.Details = appErr.Details
			}

			c.JSON(appErr.GetHTTPStatus(), response)
			c.Abort()
		}
	}
}

// 错误创建辅助函数
func ErrInvalidCredentials(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidCredentials,
		Message: "Invalid credentials",
		Details: details,
	}
}

func ErrInvalidToken(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidToken,
		Message: "Invalid token",
		Details: details,
	}
}

func ErrUserNotFound(details string) error {
	return &AppError{
		Code:    ErrCodeUserNotFound,
		Message: "User not found",
		Details: details,
	}
}

func ErrWeakPassword(details string) error {
	return &AppError{
		Code:    ErrCodeWeakPassword,
		Message: "Password does not meet security requirements",
		Details: details,
	}
}

func ErrDuplicateUser(details string) error {
	return &AppError{
		Code:    ErrCodeDuplicateUser,
		Message: "User already exists",
		Details: details,
	}
}

func ErrTooManyRequests(details string) error {
	return &AppError{
		Code:    ErrCodeTooManyRequests,
		Message: "Too many requests",
		Details: details,
	}
}

// ErrInvalidToken 无效的令牌
// func ErrInvalidToken() error {
// 	return NewAppError(ErrCodeInvalidToken, "Invalid token", nil)
// }

// ErrWeakPassword 密码太弱
// func ErrWeakPassword() error {
// 	return NewAppError(ErrCodeWeakPassword, "Password is too weak", nil)
// }

// ErrDuplicateUser 用户已存在
// func ErrDuplicateUser() error {
// 	return NewAppError(ErrCodeDuplicateUser, "User already exists", nil)
// }

// ErrInvalidPassword 密码错误
func ErrInvalidPassword(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidPassword,
		Message: "Invalid password",
		Details: details,
	}
}

// ErrInvalidOAuthState 无效的OAuth状态
func ErrInvalidOAuthState(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidOAuthState,
		Message: "Invalid OAuth state",
		Details: details,
	}
}

// ErrOAuthFailed OAuth失败
func ErrOAuthFailed(details string) error {
	return &AppError{
		Code:    ErrCodeOAuthFailed,
		Message: "OAuth failed",
		Details: details,
	}
}

// ErrUsernameTaken 用户名已存在
func ErrUsernameTaken(details string) error {
	return &AppError{
		Code:    ErrCodeUsernameTaken,
		Message: "Username already taken",
		Details: details,
	}
}

// ErrEmailTaken 邮箱已存在
func ErrEmailTaken(details string) error {
	return &AppError{
		Code:    ErrCodeEmailTaken,
		Message: "Email already taken",
		Details: details,
	}
}

// ErrInvalidConfig 返回无效配置错误
func ErrInvalidConfig(details string) error {
	return NewAppError(ErrCodeInvalidConfig, "无效的配置", fmt.Errorf(details))
}

// ErrInvalidCode 返回无效授权码错误
func ErrInvalidCode(details string) error {
	return NewAppError(ErrCodeInvalidCode, "无效的授权码", fmt.Errorf(details))
}

// ErrAPIRequest 返回API请求错误
func ErrAPIRequest(details string) error {
	return NewAppError(ErrCodeAPIRequest, "API请求失败", fmt.Errorf(details))
}

