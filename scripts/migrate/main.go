package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
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

// 新数据库用户模型
type NewUser struct {
	UserID        string     `json:"user_id" gorm:"primarykey"`
	Password      string     `json:"password" gorm:"not null"`
	Status        string     `json:"status" gorm:"not null;default:'active'"`
	Nickname      string     `json:"nickname" gorm:"size:50"`
	Avatar        string     `json:"avatar" gorm:"size:255"`
	LastLogin     *time.Time `json:"last_login"`
	LoginAttempts int        `json:"login_attempts" gorm:"default:0"`
	LastAttempt   *time.Time `json:"last_attempt"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// 新数据库微信用户模型
type NewWeixinUser struct {
	UserID     string    `json:"user_id" gorm:"primarykey"`
	OpenID     string    `json:"open_id" gorm:"unique"`
	Nickname   string    `json:"nickname"`
	Sex        int       `json:"sex"`
	Province   string    `json:"province"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	HeadImgURL string    `json:"head_img_url"`
	UnionID    string    `json:"union_id" gorm:"unique"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
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
	defer sourceDB.Close()

	// 连接目标数据库
	targetDB, err := connectDB(config.TargetDB)
	if err != nil {
		log.Fatalf("连接目标数据库失败: %v", err)
	}
	defer targetDB.Close()

	// 从源数据库读取用户数据
	users, err := readUsers(sourceDB)
	if err != nil {
		log.Fatalf("Failed to read users from source database: %v", err)
	}
	// 迁移用户数据到目标数据库
	if err := migrateUsers(targetDB, users); err != nil {
		log.Fatalf("Failed to migrate users: %v", err)
	}

	log.Printf("Successfully migrated %d users", len(users))
}

// 连接数据库
func connectDB(config interface{}) (*sql.DB, error) {
	var dsn string
	switch c := config.(type) {
	case SourceDBConfig:
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.User, c.Password, c.Host, c.Port, c.Database)
	case TargetDBConfig:
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.User, c.Password, c.Host, c.Port, c.Database)
	default:
		return nil, fmt.Errorf("unsupported config type")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

// 从源数据库读取用户数据
func readUsers(db *sql.DB) ([]OldUser, error) {
	// 读取用户信息
	query := `SELECT * FROM user`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []OldUser
	for rows.Next() {
		var user OldUser
		err := rows.Scan(
			&user.ID,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.DeletedAt,
			&user.Nickname,
			&user.Avatar,
			&user.Uid,
			&user.IsActivated,
			&user.WxOpenId,
			&user.WxAccessToken,
			&user.WxAccessTokenCreateTime,
			&user.WxRefreshToken,
			&user.WxRefreshTokenCreateTime,
			&user.WxLoginCode,
			&user.WxMpOpenId,
			&user.WxMpSessionKey,
			&user.WxMpSessionKeyCreateTime,
			&user.WxMpLoginCode,
			&user.WxUnionId,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// 迁移用户数据到目标数据库
func migrateUsers(db *sql.DB, oldUsers []OldUser) error {
	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 准备用户更新语句
	userStmt, err := tx.Prepare(`
		UPDATE users SET 
			password = ?,
			status = ?,
			nickname = ?,
			avatar = ?,
			last_login = ?,
			login_attempts = ?,
			last_attempt = ?,
			created_at = ?,
			updated_at = ?
		WHERE user_id = ?
	`)
	if err != nil {
		return err
	}
	defer userStmt.Close()

	// 准备微信用户更新语句
	weixinStmt, err := tx.Prepare(`
		UPDATE weixin_users SET 
			open_id = ?,
			nickname = ?,
			sex = ?,
			province = ?,
			city = ?,
			country = ?,
			head_img_url = ?,
			union_id = ?,
			created_at = ?,
			updated_at = ?
		WHERE user_id = ?
	`)
	if err != nil {
		return err
	}
	defer weixinStmt.Close()

	// 准备用户插入语句
	userInsertStmt, err := tx.Prepare(`
		INSERT INTO users (
			user_id, password, status, nickname, avatar, 
			last_login, login_attempts, last_attempt, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer userInsertStmt.Close()

	// 准备微信用户插入语句
	weixinInsertStmt, err := tx.Prepare(`
		INSERT INTO weixin_users (
			user_id, open_id, nickname, sex, province, 
			city, country, head_img_url, union_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer weixinInsertStmt.Close()

	// 先查询新数据库中的用户数据
	newUsers, err := getNewUsers(db)
	if err != nil {
		return err
	}

	// 先查询新数据库中的微信用户数据
	newWeixinUsers, err := getNewWeixinUsers(db)
	if err != nil {
		return err
	}

	// 创建UnionID到NewWeixinUser的映射
	unionIDMap := make(map[string]NewWeixinUser)
	for _, wu := range newWeixinUsers {
		if wu.UnionID != "" {
			unionIDMap[wu.UnionID] = wu
		}
	}

	// 创建UserID到NewUser的映射
	userIDMap := make(map[string]NewUser)
	for _, u := range newUsers {
		userIDMap[u.UserID] = u
	}

	// 更新用户数据
	for _, oldUser := range oldUsers {
		// 准备用户数据
		nickname := oldUser.Nickname
		avatar := oldUser.Avatar
		status := "active"
		password := "123456"
		last_login := oldUser.WxRefreshTokenCreateTime
		newUserId := ""

		// 检查是否需要从NewWeixinUser更新数据
		if oldUser.WxUnionId != "" {
			if newWeixinUser, exists := unionIDMap[oldUser.WxUnionId]; exists {
				if nickname == "" {
					nickname = newWeixinUser.Nickname
				}
				if avatar == "" {
					avatar = newWeixinUser.HeadImgURL
				}
				newUserId = newWeixinUser.UserID

				// 如果NewWeixinUser的UserID对应的NewUser存在，也更新数据
				if newUser, exists := userIDMap[newWeixinUser.UserID]; exists {
					if nickname == "" {
						nickname = newUser.Nickname
					}
					if avatar == "" {
						avatar = newUser.Avatar
					}
					status = newUser.Status
					password = newUser.Password
					last_login = newUser.LastLogin
				}

				// 更新基本用户信息
				_, err = userStmt.Exec(
					password,
					status,
					nickname,
					avatar,
					last_login,
					0,
					nil,
					oldUser.CreatedAt,
					time.Now(),
					newUserId,
				)
				if err != nil {
					return err
				}

				// 如果有微信信息，更新微信用户表
				if oldUser.WxOpenId != "" || oldUser.WxMpOpenId != "" || oldUser.WxUnionId != "" {
					// 优先使用开放平台的OpenId，如果没有则使用小程序的OpenId
					openId := oldUser.WxOpenId
					if openId == "" {
						openId = oldUser.WxMpOpenId
					}

					// 准备微信用户数据
					weixinNickname := nickname
					weixinHeadImgURL := avatar
					sex := 0
					province := ""
					city := ""
					country := ""

					// 检查是否需要从NewWeixinUser更新数据
					if weixinNickname == "" {
						weixinNickname = newWeixinUser.Nickname
					}
					if weixinHeadImgURL == "" {
						weixinHeadImgURL = newWeixinUser.HeadImgURL
					}
					sex = newWeixinUser.Sex
					province = newWeixinUser.Province
					city = newWeixinUser.City
					country = newWeixinUser.Country

					if newUserId != "" {
						_, err = weixinStmt.Exec(
							openId,
							weixinNickname,
							sex,
							province,
							city,
							country,
							weixinHeadImgURL,
							oldUser.WxUnionId,
							oldUser.CreatedAt,
							time.Now(),
							newUserId,
						)
						if err != nil {
							return err
						}
					}
				}
			} else {
				// 没有匹配到UnionID，执行插入操作
				_, err = userInsertStmt.Exec(
					oldUser.ID,
					password,
					status,
					nickname,
					avatar,
					last_login,
					0,
					nil,
					time.Now(),
					time.Now(),
				)
				if err != nil {
					return err
				}

				// 如果有微信信息，插入微信用户表
				if oldUser.WxOpenId != "" || oldUser.WxMpOpenId != "" || oldUser.WxUnionId != "" {
					openId := oldUser.WxOpenId
					if openId == "" {
						openId = oldUser.WxMpOpenId
					}

					_, err = weixinInsertStmt.Exec(
						oldUser.ID,
						openId,
						nickname,
						0,
						"",
						"",
						"",
						avatar,
						oldUser.WxUnionId,
						time.Now(),
						time.Now(),
					)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// 提交事务
	return tx.Commit()
}

// 获取新数据库中的用户数据
func getNewUsers(db *sql.DB) ([]NewUser, error) {
	query := `SELECT user_id, password, status, nickname, avatar, last_login, 
	login_attempts, last_attempt, created_at, updated_at FROM users`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []NewUser
	for rows.Next() {
		var user NewUser
		err := rows.Scan(
			&user.UserID,
			&user.Password,
			&user.Status,
			&user.Nickname,
			&user.Avatar,
			&user.LastLogin,
			&user.LoginAttempts,
			&user.LastAttempt,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// 获取新数据库中的微信用户数据
func getNewWeixinUsers(db *sql.DB) ([]NewWeixinUser, error) {
	query := `SELECT * FROM weixin_users`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []NewWeixinUser
	for rows.Next() {
		var user NewWeixinUser
		err := rows.Scan(
			&user.UserID,
			&user.OpenID,
			&user.Nickname,
			&user.Sex,
			&user.Province,
			&user.City,
			&user.Country,
			&user.HeadImgURL,
			&user.UnionID,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// 获取整数环境变量，如果不存在则返回默认值
func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}
