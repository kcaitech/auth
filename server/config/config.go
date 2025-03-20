package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config 主配置结构体
type Config struct {
	Server   ServerConfig   `json:"server"`
	Auth     AuthConfig     `json:"auth"`
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	Admin    AdminConfig    `json:"admin"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port         int    `json:"port"`
	ReadTimeout  string `json:"read_timeout"`  // 使用字符串格式如 "15s", "5m"
	WriteTimeout string `json:"write_timeout"` // 使用字符串格式如 "15s", "5m"
}

type JWTConfig struct {
	Issuer string `json:"issuer"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	EnabledProviders []string        `json:"enabled_providers"` // "account", "email", "google", "weixin"
	JWT              JWTConfig       `json:"jwt"`
	Google           GoogleConfig    `json:"google"`
	Weixin           WeixinConfig    `json:"weixin"`
	TwoFactor        TwoFactorConfig `json:"two_factor"`
	Smtp             SmtpConfig      `json:"smtp"`
	SMS              SMSConfig       `json:"sms"` // 新增：短信配置
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

// SMSConfig 短信配置
type SMSConfig struct {
	Provider   string `json:"provider"`    // 短信服务提供商，如 "aliyun", "tencent" 等
	AccessKey  string `json:"access_key"`  // 访问密钥
	SecretKey  string `json:"secret_key"`  // 密钥
	SignName   string `json:"sign_name"`   // 短信签名
	TemplateID string `json:"template_id"` // 模板ID
	Region     string `json:"region"`      // 区域
}

// TwoFactorConfig 双因素认证配置
type TwoFactorConfig struct {
	Enabled    bool   `json:"enabled"`
	Issuer     string `json:"issuer"`
	Period     uint   `json:"period"`
	Digits     uint   `json:"digits"`
	SecretSize uint   `json:"secret_size"`
}

// AdminConfig 管理员配置
type AdminConfig struct {
	Enabled      bool      `json:"enabled"`       // 是否启用管理页面
	Port         int       `json:"port"`          // 管理页面监听端口，与主服务分离
	SecretKey    string    `json:"secret_key"`    // 管理页面会话密钥
	Accounts     []Account `json:"accounts"`      // 管理员账号列表
	AllowedIPs   []string  `json:"allowed_ips"`   // 允许访问的IP列表
	RequireTLS   bool      `json:"require_tls"`   // 是否强制使用TLS
	SessionTTL   int       `json:"session_ttl"`   // 会话有效期（分钟）
	LoginTimeout int       `json:"login_timeout"` // 登录超时（秒）
}

// Account 管理员账号
type Account struct {
	Username string   `json:"username"` // 用户名
	Password string   `json:"password"` // 密码（加密存储）
	Roles    []string `json:"roles"`    // 角色列表
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

// SmtpConfig 邮件配置
type SmtpConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	BaseURL  string `json:"base_url"` // 用于生成验证链接
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
	return dc.Username + ":" + dc.Password + "@tcp(" + dc.Host + ":" + fmt.Sprintf("%d", dc.Port) + ")/" + dc.Database + "?charset=" + dc.Charset + "&parseTime=True&loc=Local"
}

// GetRedisAddr 获取Redis连接地址
func (rc *RedisConfig) GetRedisAddr() string {
	return rc.Host + ":" + fmt.Sprintf("%d", rc.Port)
}

// GetReadTimeout 将字符串格式的读取超时转换为time.Duration
func (sc *ServerConfig) GetReadTimeout() (time.Duration, error) {
	return time.ParseDuration(sc.ReadTimeout)
}

// GetWriteTimeout 将字符串格式的写入超时转换为time.Duration
func (sc *ServerConfig) GetWriteTimeout() (time.Duration, error) {
	return time.ParseDuration(sc.WriteTimeout)
}
