package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// TokenResponse 认证服务返回的令牌响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// JWTClient JWT客户端
type JWTClient struct {
	AuthServerURL string        // 认证服务URL
	HTTPClient    *http.Client  // HTTP客户端
	Timeout       time.Duration // 请求超时时间
}

// NewJWTClient 创建新的JWT客户端
func NewJWTClient(authServerURL string) *JWTClient {
	return &JWTClient{
		AuthServerURL: authServerURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

// Login 用户登录
func (c *JWTClient) Login(email, password string) (*TokenResponse, error) {
	// 构建请求体
	reqBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return nil, err
	}

	// 创建请求
	req, err := http.NewRequest("POST", c.AuthServerURL+"/auth/login", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("登录失败: %d", resp.StatusCode)
		}
		return nil, errors.New(errResp.Error)
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// RefreshToken 刷新令牌
func (c *JWTClient) RefreshToken(refreshToken string) (*TokenResponse, error) {
	// 创建请求
	req, err := http.NewRequest("POST", c.AuthServerURL+"/auth/refresh", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+refreshToken)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("刷新令牌失败: %d", resp.StatusCode)
		}
		return nil, errors.New(errResp.Error)
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// Logout 用户登出
func (c *JWTClient) Logout(accessToken string) error {
	// 创建请求
	req, err := http.NewRequest("POST", c.AuthServerURL+"/auth/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("登出失败: %d", resp.StatusCode)
		}
		return errors.New(errResp.Error)
	}

	return nil
}

// ValidateToken 验证令牌
func (c *JWTClient) ValidateToken(accessToken string) (bool, error) {
	// 创建请求
	req, err := http.NewRequest("GET", c.AuthServerURL+"/auth/validate", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	// 令牌无效
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil
	}

	// 其他错误
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return false, fmt.Errorf("验证令牌失败: %d", resp.StatusCode)
	}
	return false, errors.New(errResp.Error)
} 