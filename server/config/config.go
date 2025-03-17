package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config 主配置结构体
type Config struct {
	Server   ServerConfig   `json:"server"`
	Auth     AuthConfig     `json:"auth"`
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	EnabledProviders []string      `json:"enabled_providers"` // "account", "google", "weixin"
	// JWT             JWTConfig      `json:"jwt"`
	Google          GoogleConfig   `json:"google"`
	Weixin          WeixinConfig   `json:"weixin"`
	TwoFactor       TwoFactorConfig `json:"two_factor"`
}

// JWTConfig JWT配置
// type JWTConfig struct {
// 	SecretKey string        `json:"secret_key"`
// 	ExpireIn  time.Duration `json:"expire_in"`
// }

// GoogleConfig Google OAuth配置
type GoogleConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// WeixinConfig 微信登录配置
type WeixinConfig struct {
	AppID       string `json:"app_id"`
	AppSecret   string `json:"app_secret"`
	RedirectURL string `json:"redirect_url"`
}

// TwoFactorConfig 双因素认证配置
type TwoFactorConfig struct {
	Enabled    bool   `json:"enabled"`
	Issuer     string `json:"issuer"`
	Period     uint   `json:"period"`
	Digits     uint   `json:"digits"`
	SecretSize uint   `json:"secret_size"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Driver   string `json:"driver"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	Charset  string `json:"charset"`
}

// RedisConfig Redis配置
type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// LoadConfig 从文件加载配置
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

// GetDSN 获取数据库连接字符串
func (dc *DatabaseConfig) GetDSN() string {
	return dc.Username + ":" + dc.Password + "@tcp(" + dc.Host + ":" + string(dc.Port) + ")/" + dc.Database + "?charset=" + dc.Charset + "&parseTime=True&loc=Local"
}

// GetRedisAddr 获取Redis连接地址
func (rc *RedisConfig) GetRedisAddr() string {
	return rc.Host + ":" + string(rc.Port)
} 