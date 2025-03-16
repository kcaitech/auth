package auth

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Username  string    `json:"username" gorm:"uniqueIndex;not null"`
	Password  string    `json:"-" gorm:"not null"`
	Email     string    `json:"email" gorm:"uniqueIndex;not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AccountAuth struct {
	db *gorm.DB
}

func NewAccountAuth(db *gorm.DB) *AccountAuth {
	// 自动迁移表结构
	db.AutoMigrate(&User{})
	return &AccountAuth{db: db}
}

func (a *AccountAuth) Register(username, password, email string) error {
	// 检查用户名是否已存在
	var count int64
	if err := a.db.Model(&User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return errors.New("username already exists")
	}

	// 检查邮箱是否已存在
	if err := a.db.Model(&User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return errors.New("email already exists")
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 创建新用户
	user := User{
		Username: username,
		Password: string(hashedPassword),
		Email:    email,
	}
	return a.db.Create(&user).Error
}

func (a *AccountAuth) Login(username, password string) (*User, error) {
	var user User

	// 查询用户
	if err := a.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	return &user, nil
}

func (a *AccountAuth) GetUserByID(id uint) (*User, error) {
	var user User

	if err := a.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}