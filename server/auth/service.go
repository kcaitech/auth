package auth

type AuthService interface {
    Register(username, password, email string) (*User, error)
    Login(username, password string) (string, error)
    GoogleLogin(token string) (string, error)
    WechatLogin(code string) (string, error)
}