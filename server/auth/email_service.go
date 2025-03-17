package auth

import (
    "bytes"
    "fmt"
    "html/template"
    "net/smtp"
    "time"
)

// EmailConfig 邮件配置
type EmailConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
    BaseURL  string // 用于生成验证链接
}

// EmailService 邮件服务实现
type EmailServiceImpl struct {
    config EmailConfig
}

// NewEmailService 创建邮件服务实例
func NewEmailService(config EmailConfig) EmailService {
    return &EmailServiceImpl{
        config: config,
    }
}

// 邮件模板
const (
    verificationEmailTpl = `
    <h2>邮箱验证</h2>
    <p>您好，请点击以下链接验证您的邮箱：</p>
    <p><a href="{{.BaseURL}}/auth/verify-email?token={{.Token}}">验证邮箱</a></p>
    <p>如果链接无法点击，请复制以下地址到浏览器打开：</p>
    <p>{{.BaseURL}}/auth/verify-email?token={{.Token}}</p>
    <p>此链接将在24小时后过期。</p>
    `

    passwordResetEmailTpl = `
    <h2>密码重置</h2>
    <p>您好，请点击以下链接重置您的密码：</p>
    <p><a href="{{.BaseURL}}/auth/reset-password?token={{.Token}}">重置密码</a></p>
    <p>如果链接无法点击，请复制以下地址到浏览器打开：</p>
    <p>{{.BaseURL}}/auth/reset-password?token={{.Token}}</p>
    <p>此链接将在24小时后过期。如果您没有请求重置密码，请忽略此邮件。</p>
    `

    loginNotificationEmailTpl = `
    <h2>登录通知</h2>
    <p>您好，您的账号刚刚在新设备上登录：</p>
    <p>IP地址：{{.IP}}</p>
    <p>时间：{{.Time}}</p>
    <p>如果这不是您本人的操作，请立即修改密码。</p>
    `
)

// SendVerificationEmail 发送验证邮件
func (s *EmailServiceImpl) SendVerificationEmail(email, token string) error {
    data := struct {
        BaseURL string
        Token   string
    }{
        BaseURL: s.config.BaseURL,
        Token:   token,
    }
    return s.sendEmail(email, "邮箱验证", verificationEmailTpl, data)
}

// SendPasswordResetEmail 发送密码重置邮件
func (s *EmailServiceImpl) SendPasswordResetEmail(email, token string) error {
    data := struct {
        BaseURL string
        Token   string
    }{
        BaseURL: s.config.BaseURL,
        Token:   token,
    }
    return s.sendEmail(email, "密码重置", passwordResetEmailTpl, data)
}

// SendLoginNotificationEmail 发送登录通知邮件
func (s *EmailServiceImpl) SendLoginNotificationEmail(email, ip string) error {
    data := struct {
        IP   string
        Time string
    }{
        IP:   ip,
        Time: time.Now().Format("2006-01-02 15:04:05"),
    }
    return s.sendEmail(email, "登录通知", loginNotificationEmailTpl, data)
}

// sendEmail 发送邮件通用方法
func (s *EmailServiceImpl) sendEmail(to, subject, tplStr string, data interface{}) error {
    // 解析模板
    tpl, err := template.New("email").Parse(tplStr)
    if err != nil {
        return err
    }

    // 渲染模板
    var body bytes.Buffer
    if err := tpl.Execute(&body, data); err != nil {
        return err
    }

    // 构建邮件内容
    msg := []byte(fmt.Sprintf("To: %s\r\n"+
        "From: %s\r\n"+
        "Subject: %s\r\n"+
        "Content-Type: text/html; charset=UTF-8\r\n"+
        "\r\n%s", to, s.config.From, subject, body.String()))

    // 发送邮件
    auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
    addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
    return smtp.SendMail(addr, auth, s.config.From, []string{to}, msg)
} 