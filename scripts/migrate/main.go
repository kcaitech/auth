package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// 配置结构体
type Config struct {
	SourceDB SourceDBConfig `yaml:"source_db"`
	TargetDB TargetDBConfig `yaml:"target_db"`
}

// 源数据库配置
type SourceDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

// 目标数据库配置
type TargetDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

// 旧数据库用户模型
type OldUser struct {
	ID          uint `gorm:"primarykey"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
	Nickname    string `gorm:"size:64"`
	Avatar      string `gorm:"size:256"`
	Uid         string `gorm:"unique;size:64"`
	IsActivated bool   `gorm:"default:false"`

	// 微信开放平台网页应用
	WxOpenId                 string     `gorm:"index;uniqueIndex:wx_openid_unique;size:64"`
	WxAccessToken            string     `gorm:"size:255"`
	WxAccessTokenCreateTime  *time.Time `gorm:"type:datetime(6)"`
	WxRefreshToken           string     `gorm:"size:255"`
	WxRefreshTokenCreateTime *time.Time `gorm:"type:datetime(6)"`
	WxLoginCode              string     `gorm:"size:64"`

	// 微信小程序
	WxMpOpenId               string     `gorm:"index;uniqueIndex:wx_openid_unique;size:64"`
	WxMpSessionKey           string     `gorm:"size:255"`
	WxMpSessionKeyCreateTime *time.Time `gorm:"type:datetime(6)"`
	WxMpLoginCode            string     `gorm:"size:64"`

	// 微信开放平台UnionId
	WxUnionId string `gorm:"unique;uniqueIndex:wx_union_id;size:64"`
}

func (u *OldUser) TableName() string {
	return "user"
}

type UserStatus string

// 新数据库用户模型
type User struct { // Automatically generated ID
	UserID        string     `json:"user_id" gorm:"primarykey"` // Login identifier, for normal accounts this is the login account, for email accounts it's automatically generated
	Password      string     `json:"-" gorm:"not null"`
	Status        UserStatus `json:"status" gorm:"not null;default:'active'"`
	Nickname      string     `json:"nickname" gorm:"size:50"` // Nickname
	Avatar        string     `json:"avatar" gorm:"size:255"`  // Avatar URL
	LastLogin     *time.Time `json:"last_login"`
	LoginAttempts int        `json:"login_attempts" gorm:"default:0"`
	LastAttempt   *time.Time `json:"last_attempt"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// WeixinUserInfo WeChat user information
type WeixinUserInfo struct {
	OpenID     string `json:"openid" gorm:"unique"`
	Nickname   string `json:"nickname"`
	Sex        int    `json:"sex"`
	Province   string `json:"province"`
	City       string `json:"city"`
	Country    string `json:"country"`
	HeadImgURL string `json:"headimgurl"`
	UnionID    string `json:"unionid" gorm:"unique"`
}

// WeixinErrorResponse WeChat error response
type WeixinErrorResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type WeixinUser struct {
	UserID string `json:"user_id" gorm:"primarykey"`
	WeixinUserInfo
	CreatedAt time.Time
	UpdatedAt time.Time
}

// 加载配置文件
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return &config, nil
}

// 连接数据库
func connectDB(config interface{}) (*gorm.DB, error) {
	var dsn string
	switch c := config.(type) {
	case SourceDBConfig:
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.User, c.Password, c.Host, c.Port, c.Database)
	case TargetDBConfig:
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.User, c.Password, c.Host, c.Port, c.Database)
	default:
		return nil, fmt.Errorf("不支持的配置类型")
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func main() {
	// 加载配置文件
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 连接源数据库
	sourceDB, err := connectDB(config.SourceDB)
	if err != nil {
		log.Fatalf("连接源数据库失败: %v", err)
	}

	// 连接目标数据库
	targetDB, err := connectDB(config.TargetDB)
	if err != nil {
		log.Fatalf("连接目标数据库失败: %v", err)
	}

	// 从源数据库读取用户数据
	var oldUsers []OldUser
	if err := sourceDB.Find(&oldUsers).Error; err != nil {
		log.Fatalf("读取源数据库用户失败: %v", err)
	}

	// 开始事务
	tx := targetDB.Begin()
	if tx.Error != nil {
		log.Fatalf("开始事务失败: %v", tx.Error)
	}

	// 编译正则表达式，用于检查是否为纯数字字符串
	numericRegex := regexp.MustCompile(`^[0-9]+$`)

	// 更新旧用户的userId
	for _, oldUser := range oldUsers {
		if oldUser.WxUnionId == "" {
			log.Printf("用户%s没有unionid", oldUser.Uid)
			continue
		}

		randomPassword := make([]byte, 16)
		if _, err := rand.Read(randomPassword); err != nil {
			tx.Rollback()
			log.Fatalf("failed to generate random password: %v", err)
		}
		hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
		if err != nil {
			tx.Rollback()
			log.Fatalf("failed to encrypt password: %v", err)
		}

		wxuser := WeixinUser{}
		targetDB.Model(&WeixinUser{}).Where("union_id = ?", oldUser.WxUnionId).First(&wxuser)
		if wxuser.UserID == "" { // 如果微信用户不存在，则创建用户
			// 生成新的用户ID
			newUserID, err := GenerateUserID()
			if err != nil {
				tx.Rollback()
				log.Fatalf("生成用户ID失败: %v", err)
			}

			user := User{}
			user.UserID = newUserID
			user.Password = string(hashedPassword)
			user.Status = "active"
			user.Nickname = oldUser.Nickname
			user.Avatar = oldUser.Avatar
			user.LastLogin = oldUser.WxRefreshTokenCreateTime
			user.CreatedAt = oldUser.CreatedAt

			if err := tx.Save(&user).Error; err != nil {
				tx.Rollback()
				log.Fatalf("保存用户数据失败: %v", err)
			}

			// 创建微信用户
			wxuser.UserID = user.UserID
			wxuser.OpenID = oldUser.WxOpenId
			wxuser.Nickname = oldUser.Nickname
			// wxuser.Sex = oldUser.Sex
			// wxuser.Province = oldUser.Province
			// wxuser.City = oldUser.City
			// wxuser.Country = oldUser.Country
			// wxuser.HeadImgURL = oldUser.Avatar
			wxuser.UnionID = oldUser.WxUnionId
			wxuser.CreatedAt = oldUser.CreatedAt
			wxuser.UpdatedAt = oldUser.UpdatedAt

			if err := tx.Save(&wxuser).Error; err != nil {
				tx.Rollback()
				log.Fatalf("保存微信用户数据失败: %v", err)
			}

		} else {
			// 判断wxuser.UserID是否是数字字符串，使用正则表达式能处理任意大小的数字
			if numericRegex.MatchString(wxuser.UserID) {
				// 是数字字符串，则更新用户ID
				newUserID, err := GenerateUserID()
				if err != nil {
					tx.Rollback()
					log.Fatalf("生成用户ID失败: %v", err)
				}

				user := User{}
				user.UserID = newUserID
				user.Password = string(hashedPassword)
				user.Status = "active"
				user.Nickname = oldUser.Nickname
				// user.Avatar = oldUser.Avatar
				// user.LastLogin = oldUser.WxRefreshTokenCreateTime
				user.CreatedAt = oldUser.CreatedAt

				if err := tx.Save(&user).Error; err != nil {
					tx.Rollback()
					log.Fatalf("保存用户数据失败: %v", err)
				}

				// 更新微信用户ID
				wxuser.UserID = user.UserID
				if err := tx.Save(&wxuser).Error; err != nil {
					tx.Rollback()
					log.Fatalf("保存微信用户数据失败: %v", err)
				}
			}
		}
	}

	// // 删除用户id为纯数字的用户
	// tx.Model(&User{}).Where("user_id REGEXP ?", "^[0-9]+$").Delete(&User{})

	// // 删除微信用户里unionid为空的用户
	// tx.Model(&WeixinUser{}).Where("user_id REGEXP ?", "^[0-9]+$").Delete(&WeixinUser{})
	// tx.Model(&WeixinUser{}).Where("union_id = ?", "").Delete(&WeixinUser{})

	// // 删除user里有，wxuser里没有的用户
	// var existingWxUserIDs []string
	// tx.Model(&WeixinUser{}).Select("user_id").Find(&existingWxUserIDs)
	// if len(existingWxUserIDs) > 0 {
	// 	tx.Model(&User{}).Where("user_id NOT IN ?", existingWxUserIDs).Delete(&User{})
	// } else {
	// 	// 如果没有微信用户，删除所有用户
	// 	// tx.Model(&User{}).Delete(&User{})
	// }

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		log.Fatalf("提交事务失败: %v", err)
	}

	log.Printf("成功迁移 %d 个用户", len(oldUsers))
}
