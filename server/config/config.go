/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"kcaitech.com/kcauth/server/auth/storage"
)

// Config Main configuration structure
type Config struct {
	Server         ServerConfig        `json:"server"`
	Auth           AuthConfig          `json:"auth"`
	Database       DatabaseConfig      `json:"database"`
	Redis          RedisConfig         `json:"redis"`
	Admin          AdminConfig         `json:"admin"`
	Storage        storage.StorageConf `json:"storage"`
	TrustedClients []TrustedClient     `json:"trusted_clients"` // 受信任的第三方客户端配置
	StorageUrl     StorageUrlConfig    `json:"storage_url"`     // 存储URL配置
}

type StorageUrlConfig struct {
	Attatch string `json:"attatch"`
}

// ServerConfig Server configuration
type ServerConfig struct {
	Port         int    `json:"port"`
	ReadTimeout  string `json:"read_timeout"`  // Using string format like "15s", "5m"
	WriteTimeout string `json:"write_timeout"` // Using string format like "15s", "5m"
}

type JWTConfig struct {
	Issuer string `json:"issuer"`
}

// AuthConfig Authentication configuration
type AuthConfig struct {
	EnabledProviders []string        `json:"enabled_providers"` // "account", "email", "weixin", "google", "phone"
	JWT              JWTConfig       `json:"jwt"`
	Google           GoogleConfig    `json:"google"`
	Weixin           WeixinConfig    `json:"weixin"`
	TwoFactor        TwoFactorConfig `json:"two_factor"`
	Smtp             SmtpConfig      `json:"smtp"`
	SMS              SMSConfig       `json:"sms"` // New: SMS configuration
}

// JWTConfig JWT configuration
// type JWTConfig struct {
// 	SecretKey string        `json:"secret_key"`
// 	ExpireIn  time.Duration `json:"expire_in"`
// }

// GoogleConfig Google OAuth configuration
type GoogleConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// WeixinConfig WeChat login configuration
type WeixinConfig struct {
	AppID             string `json:"app_id"`
	AppSecret         string `json:"app_secret"`
	RedirectURL       string `json:"redirect_url"`
	DomainVerifyToken string `json:"domain_verify_token"`
}

// SMSConfig SMS configuration
type SMSConfig struct {
	Provider   string `json:"provider"`    // SMS service provider, such as "aliyun", "tencent", etc.
	AccessKey  string `json:"access_key"`  // Access key
	SecretKey  string `json:"secret_key"`  // Secret key
	SignName   string `json:"sign_name"`   // SMS signature
	TemplateID string `json:"template_id"` // Template ID
	Region     string `json:"region"`      // Region
}

// TwoFactorConfig Two-factor authentication configuration
type TwoFactorConfig struct {
	Enabled    bool   `json:"enabled"`
	Issuer     string `json:"issuer"`
	Period     uint   `json:"period"`
	Digits     uint   `json:"digits"`
	SecretSize uint   `json:"secret_size"`
}

// AdminConfig Administrator configuration
type AdminConfig struct {
	Enabled      bool      `json:"enabled"`       // Whether to enable admin page
	Port         int       `json:"port"`          // Admin page listening port, separate from main service
	SecretKey    string    `json:"secret_key"`    // Admin page session key
	Accounts     []Account `json:"accounts"`      // Admin account list
	AllowedIPs   []string  `json:"allowed_ips"`   // List of allowed IP addresses
	RequireTLS   bool      `json:"require_tls"`   // Whether to force TLS usage
	SessionTTL   int       `json:"session_ttl"`   // Session validity period (minutes)
	LoginTimeout int       `json:"login_timeout"` // Login timeout (seconds)
}

// Account Administrator account
type Account struct {
	Username string   `json:"username"` // Username
	Password string   `json:"password"` // Password (encrypted storage)
	Roles    []string `json:"roles"`    // Role list
}

// DatabaseConfig Database configuration
type DatabaseConfig struct {
	Driver   string `json:"driver"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	Charset  string `json:"charset"`
}

// RedisConfig Redis configuration
type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// SmtpConfig Email configuration
type SmtpConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	// BaseURL  string `json:"base_url"` // Used to generate verification links
}

// TrustedClient 受信任的第三方客户端配置
type TrustedClient struct {
	ClientID     string   `json:"client_id"`     // 客户端ID
	ClientSecret string   `json:"client_secret"` // 客户端密钥
	AllowedIPs   []string `json:"allowed_ips"`   // 允许的IP地址列表
	Scopes       []string `json:"scopes"`        // 允许的权限范围
}

func (c *TrustedClient) HasScope(_scope string) bool {
	for _, scope := range c.Scopes {
		if scope == _scope {
			return true
		}
	}
	return false
}

// LoadConfig Load configuration from file
func LoadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := json.Unmarshal(file, config); err != nil {
		return nil, err
	}

	return config, nil
}

// GetDSN Get database connection string
func (dc *DatabaseConfig) GetDSN() string {
	return dc.Username + ":" + dc.Password + "@tcp(" + dc.Host + ":" + fmt.Sprintf("%d", dc.Port) + ")/" + dc.Database + "?charset=" + dc.Charset + "&parseTime=True&loc=Local"
}

// GetRedisAddr Get Redis connection address
func (rc *RedisConfig) GetRedisAddr() string {
	return rc.Host + ":" + fmt.Sprintf("%d", rc.Port)
}

// GetReadTimeout Convert string format read timeout to time.Duration
func (sc *ServerConfig) GetReadTimeout() (time.Duration, error) {
	return time.ParseDuration(sc.ReadTimeout)
}

// GetWriteTimeout Convert string format write timeout to time.Duration
func (sc *ServerConfig) GetWriteTimeout() (time.Duration, error) {
	return time.ParseDuration(sc.WriteTimeout)
}
