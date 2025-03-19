package auth

import "time"

// UserStatus 用户状态
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"   // 活跃
	UserStatusInactive UserStatus = "inactive" // 未激活
	UserStatusLocked   UserStatus = "locked"   // 锁定
	UserStatusBanned   UserStatus = "banned"   // 封禁
)

// UserProfile 用户档案
type UserProfile struct {
	Nickname  string `json:"nickname" gorm:"size:50"`   // 昵称
	Avatar    string `json:"avatar" gorm:"size:255"`    // 头像URL
	Bio       string `json:"bio" gorm:"size:500"`       // 个人简介
	Location  string `json:"location" gorm:"size:100"`  // 地理位置
	Website   string `json:"website" gorm:"size:200"`   // 个人网站
	Birthday  string `json:"birthday" gorm:"size:10"`   // 生日
	Gender    string `json:"gender" gorm:"size:10"`     // 性别
	Phone     string `json:"phone" gorm:"size:20"`      // 电话号码
	Company   string `json:"company" gorm:"size:100"`   // 公司
	Position  string `json:"position" gorm:"size:100"`  // 职位
	Education string `json:"education" gorm:"size:100"` // 教育背景
	Language  string `json:"language" gorm:"size:20"`   // 首选语言
	Timezone  string `json:"timezone" gorm:"size:50"`   // 时区
}

// 验证记录
type Verification struct {
	UserID    string           `gorm:"primarykey"`
	Type      VerificationType `gorm:"size:20"`
	Token     string           `gorm:"size:100;index"`
	ExpiresAt time.Time
	CreatedAt time.Time
}

// 用户角色关联
type UserRoleMapping struct {
	UserID    uint   `gorm:"primarykey"`
	Role      string `gorm:"primarykey;size:20"`
	CreatedAt time.Time
}

// Session 会话信息
type Session struct {
	ID        string    `json:"id" gorm:"primarykey;size:64"` // 会话ID
	UserID    string    `json:"user_id" gorm:"index"`         // 用户ID
	IP        string    `json:"ip" gorm:"size:45"`            // IP地址
	UserAgent string    `json:"user_agent" gorm:"size:255"`   // 用户代理
	ExpiresAt time.Time `json:"expires_at" gorm:"index"`      // 过期时间
	CreatedAt time.Time `json:"created_at"`                   // 创建时间
	UpdatedAt time.Time `json:"updated_at"`                   // 更新时间
}

// ErrInvalidSession 无效会话错误
// var ErrInvalidSession = NewAppError(ErrCodeInvalidSession, "无效的会话", nil)
