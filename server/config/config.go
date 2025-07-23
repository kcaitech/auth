/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"kcaitech.com/kcauth/server/auth/storage"
)

// Config Main configuration structure
type Config struct {
	// Server         ServerConfig        `json:"server" yaml:"server"`
	Auth           AuthConfig       `json:"auth" yaml:"auth"`
	Database       DatabaseConfig   `json:"db" yaml:"db"`
	Redis          RedisConfig      `json:"redis" yaml:"redis"`
	Admin          AdminConfig      `json:"auth_admin" yaml:"auth_admin"`
	Storage        storage.Config   `json:"storage" yaml:"storage"`
	TrustedClients []TrustedClient  `json:"auth_trusted_clients" yaml:"auth_trusted_clients"` // 受信任的第三方客户端配置
	StorageUrl     StorageUrlConfig `json:"storage_public_url" yaml:"storage_public_url"`     // 存储URL配置
}

type StorageUrlConfig struct {
	Attatch string `json:"attatch" yaml:"attatch"`
}

// ServerConfig Server configuration
// type ServerConfig struct {
// 	Port         int    `json:"port" yaml:"port"`
// 	ReadTimeout  string `json:"read_timeout" yaml:"read_timeout"`   // Using string format like "15s", "5m"
// 	WriteTimeout string `json:"write_timeout" yaml:"write_timeout"` // Using string format like "15s", "5m"
// }

type JWTConfig struct {
	Issuer string `json:"issuer" yaml:"issuer"`
}

// AuthConfig Authentication configuration
type AuthConfig struct {
	EnabledProviders []string         `json:"enabled_providers" yaml:"enabled_providers"` // "account", "email", "weixin", "google", "phone"
	JWT              JWTConfig        `json:"jwt" yaml:"jwt"`
	Google           GoogleConfig     `json:"google" yaml:"google"`
	Weixin           WeixinConfig     `json:"weixin" yaml:"weixin"`
	WeixinMini       WeixinMiniConfig `json:"weixin_mini" yaml:"weixin_mini"`
	TwoFactor        TwoFactorConfig  `json:"two_factor" yaml:"two_factor"`
	Smtp             SmtpConfig       `json:"smtp" yaml:"smtp"`
	SMS              SMSConfig        `json:"sms" yaml:"sms"` // New: SMS configuration
}

// JWTConfig JWT configuration
// type JWTConfig struct {
// 	SecretKey string        `json:"secret_key"`
// 	ExpireIn  time.Duration `json:"expire_in"`
// }

// GoogleConfig Google OAuth configuration
type GoogleConfig struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
}

// WeixinConfig WeChat login configuration
type WeixinConfig struct {
	AppID             string `json:"app_id" yaml:"app_id"`
	AppSecret         string `json:"app_secret" yaml:"app_secret"`
	RedirectURL       string `json:"redirect_url" yaml:"redirect_url"`
	DomainVerifyToken string `json:"domain_verify_token" yaml:"domain_verify_token"`
}

// WeixinMiniConfig WeChat mini login configuration
type WeixinMiniConfig struct {
	AppID     string `json:"app_id" yaml:"app_id"`
	AppSecret string `json:"app_secret" yaml:"app_secret"`
	GrantType string `json:"grant_type" yaml:"grant_type"`
}

// SMSConfig SMS configuration
type SMSConfig struct {
	Provider   string `json:"provider" yaml:"provider"`       // SMS service provider, such as "aliyun", "tencent", etc.
	AccessKey  string `json:"access_key" yaml:"access_key"`   // Access key
	SecretKey  string `json:"secret_key" yaml:"secret_key"`   // Secret key
	SignName   string `json:"sign_name" yaml:"sign_name"`     // SMS signature
	TemplateID string `json:"template_id" yaml:"template_id"` // Template ID
	Region     string `json:"region" yaml:"region"`           // Region
}

// TwoFactorConfig Two-factor authentication configuration
type TwoFactorConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Issuer     string `json:"issuer" yaml:"issuer"`
	Period     uint   `json:"period" yaml:"period"`
	Digits     uint   `json:"digits" yaml:"digits"`
	SecretSize uint   `json:"secret_size" yaml:"secret_size"`
}

// AdminConfig Administrator configuration
type AdminConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"` // Whether to enable admin page
	// Port         int       `json:"port" yaml:"port"`                   // Admin page listening port, separate from main service
	SecretKey    string    `json:"secret_key" yaml:"secret_key"`       // Admin page session key
	Accounts     []Account `json:"accounts" yaml:"accounts"`           // Admin account list
	AllowedIPs   []string  `json:"allowed_ips" yaml:"allowed_ips"`     // List of allowed IP addresses
	RequireTLS   bool      `json:"require_tls" yaml:"require_tls"`     // Whether to force TLS usage
	SessionTTL   int       `json:"session_ttl" yaml:"session_ttl"`     // Session validity period (minutes)
	LoginTimeout int       `json:"login_timeout" yaml:"login_timeout"` // Login timeout (seconds)
}

// Account Administrator account
type Account struct {
	Username string   `json:"username" yaml:"username"` // Username
	Password string   `json:"password" yaml:"password"` // Password (encrypted storage)
	Roles    []string `json:"roles" yaml:"roles"`       // Role list
}

// DatabaseConfig Database configuration
type DatabaseConfig struct {
	// Driver   string `json:"driver" yaml:"driver"`
	Username string `json:"user" yaml:"user"`
	Password string `json:"password" yaml:"password"`
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Database string `json:"database" yaml:"database"`
	Charset  string `json:"charset" yaml:"charset"`
}

// RedisConfig Redis configuration
type RedisConfig struct {
	Host string `json:"addr" yaml:"addr"`
	// Port     int    `json:"port" yaml:"port"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
}

// SmtpConfig Email configuration
type SmtpConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	From     string `json:"from" yaml:"from"`
	// BaseURL  string `json:"base_url"` // Used to generate verification links
}

// TrustedClient 受信任的第三方客户端配置
type TrustedClient struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`         // 客户端ID
	ClientSecret string   `json:"client_secret" yaml:"client_secret"` // 客户端密钥
	AllowedIPs   []string `json:"allowed_ips" yaml:"allowed_ips"`     // 允许的IP地址列表
	Scopes       []string `json:"scopes" yaml:"scopes"`               // 允许的权限范围
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
	if err := yaml.Unmarshal(file, config); err != nil {
		return nil, err
	}
	confirmConfig(config)

	return config, nil
}

// GetDSN Get database connection string
func (dc *DatabaseConfig) GetDSN() string {
	return dc.Username + ":" + dc.Password + "@tcp(" + dc.Host + ":" + fmt.Sprintf("%d", dc.Port) + ")/" + dc.Database + "?charset=" + dc.Charset + "&parseTime=True&loc=Local"
}

// GetRedisAddr Get Redis connection address
func (rc *RedisConfig) GetRedisAddr() string {
	return rc.Host
}
