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
	ErrCodeInvalidInput

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
	ErrCodeInvalidUsername
	ErrCodeTooManyAttempts
	ErrCodeEmailNotVerified
	ErrCodeExpiredToken
	ErrCodePermissionDenied
	ErrCodeUserIDTaken  // 用户ID已被占用
	ErrCodeInvalidLogin // 登录凭证无效
	ErrCodeUserLocked   // 用户账号已被锁定

	// 第三方登录相关错误码 (3000-3999)
	ErrCodeInvalidConfig ErrorCode = 3000 + iota
	ErrCodeEmailTaken              // 邮箱已被占用
	ErrCodeInvalidEmail
	ErrCodeUnverifiedEmail
	ErrCodeInvalidCode
	ErrCodeAPIRequest
)

// AppError 应用错误类型
type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
	Err     error     `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap 支持error unwrapping
func (e *AppError) Unwrap() error {
	return e.Err
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

// ErrUsernameTaken 用户名已被占用错误
func ErrUsernameTaken(msg string) error {
	return NewAppError(ErrCodeUsernameTaken, msg, nil)
}

// ErrUserIDTaken 用户ID已被占用错误
func ErrUserIDTaken(msg string) error {
	return NewAppError(ErrCodeUsernameTaken, msg, nil)
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
	return NewAppError(ErrCodeInvalidConfig, "无效的配置", fmt.Errorf("%s", details))
}

// ErrInvalidCode 返回无效授权码错误
func ErrInvalidCode(details string) error {
	return NewAppError(ErrCodeInvalidCode, "无效的授权码", fmt.Errorf("%s", details))
}

// ErrAPIRequest 返回API请求错误
func ErrAPIRequest(details string) error {
	return NewAppError(ErrCodeAPIRequest, "API请求失败", fmt.Errorf("%s", details))
}

// ErrInvalidInput 返回无效输入错误
func ErrInvalidInput(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidInput,
		Message: "无效的输入参数",
		Details: details,
	}
}

// ErrEmailNotVerified 返回邮箱未验证错误
func ErrEmailNotVerified(details string) error {
	return &AppError{
		Code:    ErrCodeEmailNotVerified,
		Message: "邮箱未验证",
		Details: details,
	}
}

var ErrInvalidSession = NewAppError(ErrCodeInvalidSession, "无效的会话", nil)

// 预定义错误变量
var (

	// ErrInvalidLogin 登录凭证无效
	ErrInvalidLogin = NewAppError(ErrCodeInvalidLogin, "登录凭证无效", nil)

	// ErrUserLocked 用户账号已被锁定
	ErrUserLocked = NewAppError(ErrCodeUserLocked, "账号已被锁定，请稍后再试或联系管理员", nil)

	// ErrUnverifiedEmail 邮箱未验证
	ErrUnverifiedEmail = NewAppError(ErrCodeUnverifiedEmail, "邮箱未验证，请先验证邮箱", nil)

	// ErrExpiredToken 令牌已过期
	ErrExpiredToken = NewAppError(ErrCodeExpiredToken, "令牌已过期", nil)

	// ErrPermissionDenied 权限不足
	ErrPermissionDenied = NewAppError(ErrCodePermissionDenied, "权限不足", nil)

	// ErrServerError 服务器错误
	// ErrServerError = NewAppError(ErrCodeServerError, "服务器内部错误", nil)
)

// 常用错误构造函数 - 保持向后兼容
// 注意：这些函数将在未来版本中被移除，请使用预定义的错误变量

// ErrInvalidInput 输入数据无效错误
func NewInvalidInputError(details string) error {
	return NewAppError(ErrCodeInvalidInput, details, nil)
}

// ErrWeakPassword 密码强度不足错误
func NewWeakPasswordError(details string) error {
	return NewAppError(ErrCodeWeakPassword, details, nil)
}

// ErrUsernameTaken 用户名已被占用错误
func NewUsernameTakenError(details string) error {
	return NewAppError(ErrCodeUsernameTaken, details, nil)
}

// ErrUserIDTaken 用户ID已被占用错误
func NewUserIDTakenError(details string) error {
	return NewAppError(ErrCodeUserIDTaken, details, nil)
}

// ErrEmailTaken 邮箱已被占用错误
func NewEmailTakenError(details string) error {
	return NewAppError(ErrCodeEmailTaken, details, nil)
}

// ErrUserNotFound 用户不存在错误
func NewUserNotFoundError(details string) error {
	return NewAppError(ErrCodeUserNotFound, details, nil)
}

// ErrInvalidLogin 登录凭证无效错误
func NewInvalidLoginError(details string) error {
	return NewAppError(ErrCodeInvalidLogin, details, nil)
}

// ErrUserLocked 用户账号已被锁定错误
func NewUserLockedError(details string) error {
	return NewAppError(ErrCodeUserLocked, details, nil)
}

// ErrUnverifiedEmail 邮箱未验证错误
func NewUnverifiedEmailError(details string) error {
	return NewAppError(ErrCodeUnverifiedEmail, details, nil)
}

// ErrInvalidToken 令牌无效错误
func NewInvalidTokenError(details string) error {
	return NewAppError(ErrCodeInvalidToken, details, nil)
}

// ErrExpiredToken 令牌已过期错误
func NewExpiredTokenError(details string) error {
	return NewAppError(ErrCodeExpiredToken, details, nil)
}

// ErrPermissionDenied 权限不足错误
func NewPermissionDeniedError(details string) error {
	return NewAppError(ErrCodePermissionDenied, details, nil)
}

// ErrDuplicateUser 用户已存在错误
func NewDuplicateUserError(details string) error {
	return NewAppError(ErrCodeDuplicateUser, details, nil)
}

// ErrServerError 服务器错误
// func NewServerError(details string, err error) error {
// 	return NewAppError(ErrCodeServerError, details, err)
// }
