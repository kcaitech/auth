package auth

type User struct {
    ID        uint      `json:"id" gorm:"primaryKey"`
    Username  string    `json:"username" gorm:"unique"`
    Password  string    `json:"-"`
    Email     string    `json:"email" gorm:"unique"`
    Provider  string    `json:"provider"` // local, google, wechat
    SocialID  string    `json:"social_id"`
}