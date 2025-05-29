/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorCode Error code type
type ErrorCode int

const (
	// Common error codes (1000-1999)
	ErrCodeInternal ErrorCode = 1000 + iota
	ErrCodeInvalidRequest
	ErrCodeUnauthorized
	ErrCodeForbidden
	ErrCodeNotFound
	ErrCodeConflict
	ErrCodeTooManyRequests
	ErrCodeInvalidInput

	// Authentication related error codes (2000-2999)
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
	ErrCodeUserIDTaken  // User ID is already taken
	ErrCodeInvalidLogin // Invalid login credentials
	ErrCodeUserLocked   // User account is locked

	// Third-party login related error codes (3000-3999)
	ErrCodeInvalidConfig ErrorCode = 3000 + iota
	ErrCodeEmailTaken              // Email is already taken
	ErrCodeInvalidEmail
	ErrCodeUnverifiedEmail
	ErrCodeInvalidCode
	ErrCodeAPIRequest
	ErrCodePhoneTaken         // Phone number is already taken
	ErrCodeInvalidPhoneFormat // Invalid phone number format
)

// AppError Application error type
type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
	Err     error     `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s:%s: %v", e.Message, e.Details, e.Err)
	}
	return fmt.Sprintf("%s:%s", e.Message, e.Details)
}

// Unwrap Support error unwrapping
func (e *AppError) Unwrap() error {
	return e.Err
}

// NewAppError Create a new application error
func NewAppError(code ErrorCode, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// ErrorResponse Error response structure
type ErrorResponse struct {
	Error struct {
		Code    ErrorCode `json:"code"`
		Message string    `json:"message"`
		Details string    `json:"details,omitempty"`
	} `json:"error"`
}

// GetHTTPStatus Get corresponding HTTP status code
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

// ErrorHandler Unified error handling middleware
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are errors
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			var appErr *AppError
			if e, ok := err.(*AppError); ok {
				appErr = e
			} else {
				// Convert regular error to application error
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

// Error creation helper functions
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

// ErrInvalidToken Invalid token
// func ErrInvalidToken() error {
// 	return NewAppError(ErrCodeInvalidToken, "Invalid token", nil)
// }

// ErrWeakPassword Password is too weak
// func ErrWeakPassword() error {
// 	return NewAppError(ErrCodeWeakPassword, "Password is too weak", nil)
// }

// ErrDuplicateUser User already exists
// func ErrDuplicateUser() error {
// 	return NewAppError(ErrCodeDuplicateUser, "User already exists", nil)
// }

// ErrInvalidPassword Invalid password
func ErrInvalidPassword(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidPassword,
		Message: "Invalid password",
		Details: details,
	}
}

// ErrInvalidOAuthState Invalid OAuth state
func ErrInvalidOAuthState(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidOAuthState,
		Message: "Invalid OAuth state",
		Details: details,
	}
}

// ErrOAuthFailed OAuth failed
func ErrOAuthFailed(details string) error {
	return &AppError{
		Code:    ErrCodeOAuthFailed,
		Message: "OAuth failed",
		Details: details,
	}
}

// ErrUsernameTaken Username is already taken error
func ErrUsernameTaken(msg string) error {
	return NewAppError(ErrCodeUsernameTaken, msg, nil)
}

// ErrUserIDTaken User ID is already taken error
func ErrUserIDTaken(msg string) error {
	return NewAppError(ErrCodeUsernameTaken, msg, nil)
}

// ErrEmailTaken Email already exists
func ErrEmailTaken(details string) error {
	return &AppError{
		Code:    ErrCodeEmailTaken,
		Message: "Email already taken",
		Details: details,
	}
}

// ErrInvalidConfig Return invalid configuration error
func ErrInvalidConfig(details string) error {
	return NewAppError(ErrCodeInvalidConfig, "Invalid configuration", errors.New(details))
}

// ErrInvalidCode Return invalid authorization code error
func ErrInvalidCode(details string) error {
	return NewAppError(ErrCodeInvalidCode, "Invalid authorization code", errors.New(details))
}

// ErrAPIRequest Return API request error
func ErrAPIRequest(details string) error {
	return NewAppError(ErrCodeAPIRequest, "API request failed", errors.New(details))
}

// ErrInvalidInput Return invalid input error
func ErrInvalidInput(details string) error {
	return &AppError{
		Code:    ErrCodeInvalidInput,
		Message: "Invalid input parameters",
		Details: details,
	}
}

// ErrEmailNotVerified Return email not verified error
func ErrEmailNotVerified(details string) error {
	return &AppError{
		Code:    ErrCodeEmailNotVerified,
		Message: "Email not verified",
		Details: details,
	}
}

var ErrInvalidSession = NewAppError(ErrCodeInvalidSession, "Invalid session", nil)

// Predefined error variables
var (

	// ErrInvalidLogin Invalid login credentials
	ErrInvalidLogin = NewAppError(ErrCodeInvalidLogin, "Invalid login credentials", nil)

	// ErrUserLocked User account is locked
	ErrUserLocked = NewAppError(ErrCodeUserLocked, "Account is locked, please try again later or contact administrator", nil)

	// ErrUnverifiedEmail Email not verified
	ErrUnverifiedEmail = NewAppError(ErrCodeUnverifiedEmail, "Email not verified, please verify your email first", nil)

	// ErrExpiredToken Token has expired
	ErrExpiredToken = NewAppError(ErrCodeExpiredToken, "Token has expired", nil)

	// ErrPermissionDenied Insufficient permissions
	ErrPermissionDenied = NewAppError(ErrCodePermissionDenied, "Insufficient permissions", nil)

	// ErrServerError Server error
	// ErrServerError = NewAppError(ErrCodeServerError, "Internal server error", nil)
)

// Common error constructor functions - maintain backward compatibility
// Note: These functions will be removed in future versions, please use predefined error variables

// ErrInvalidInput Invalid input data error
func NewInvalidInputError(details string) error {
	return NewAppError(ErrCodeInvalidInput, details, nil)
}

// ErrWeakPassword Password strength insufficient error
func NewWeakPasswordError(details string) error {
	return NewAppError(ErrCodeWeakPassword, details, nil)
}

// ErrUsernameTaken Username is already taken error
func NewUsernameTakenError(details string) error {
	return NewAppError(ErrCodeUsernameTaken, details, nil)
}

// ErrUserIDTaken User ID is already taken error
func NewUserIDTakenError(details string) error {
	return NewAppError(ErrCodeUserIDTaken, details, nil)
}

// ErrEmailTaken Email is already taken error
func NewEmailTakenError(details string) error {
	return NewAppError(ErrCodeEmailTaken, details, nil)
}

// ErrUserNotFound User does not exist error
func NewUserNotFoundError(details string) error {
	return NewAppError(ErrCodeUserNotFound, details, nil)
}

// ErrInvalidLogin Invalid login credentials error
func NewInvalidLoginError(details string) error {
	return NewAppError(ErrCodeInvalidLogin, details, nil)
}

// ErrUserLocked User account is locked error
func NewUserLockedError(details string) error {
	return NewAppError(ErrCodeUserLocked, details, nil)
}

// ErrUnverifiedEmail Email not verified error
func NewUnverifiedEmailError(details string) error {
	return NewAppError(ErrCodeUnverifiedEmail, details, nil)
}

// ErrInvalidToken Invalid token error
func NewInvalidTokenError(details string) error {
	return NewAppError(ErrCodeInvalidToken, details, nil)
}

// ErrExpiredToken Token has expired error
func NewExpiredTokenError(details string) error {
	return NewAppError(ErrCodeExpiredToken, details, nil)
}

// ErrPermissionDenied Insufficient permissions error
func NewPermissionDeniedError(details string) error {
	return NewAppError(ErrCodePermissionDenied, details, nil)
}

// ErrDuplicateUser User already exists error
func NewDuplicateUserError(details string) error {
	return NewAppError(ErrCodeDuplicateUser, details, nil)
}

// ErrServerError Server error
// func NewServerError(details string, err error) error {
// 	return NewAppError(ErrCodeServerError, details, err)
// }

// ErrPhoneTaken Create phone number is already taken error
func ErrPhoneTaken(details string) error {
	return NewAppError(ErrCodePhoneTaken, "Phone number already taken", errors.New(details))
}

// ErrInvalidPhoneFormat Create invalid phone number format error
func ErrInvalidPhoneFormat(details string) error {
	return NewAppError(ErrCodeInvalidPhoneFormat, "Invalid phone number format", errors.New(details))
}
