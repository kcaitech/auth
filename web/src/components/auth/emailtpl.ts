
const baseURL = location.origin

export const verificationEmailTpl = `
  <h2>邮箱验证</h2>
  <p>您好，请点击以下链接验证您的邮箱：</p>
  <p><a href="${baseURL}/auth/verify-email?token={{.Token}}">验证邮箱</a></p>
  <p>如果链接无法点击，请复制以下地址到浏览器打开：</p>
  <p>${baseURL}/auth/verify-email?token={{.Token}}</p>
  <p>此链接将在24小时后过期。</p>
  `

export const passwordResetEmailTpl = `
  <h2>密码重置</h2>
  <p>您好，请点击以下链接重置您的密码：</p>
  <p><a href="${baseURL}/auth/reset-password?token={{.Token}}">重置密码</a></p>
  <p>如果链接无法点击，请复制以下地址到浏览器打开：</p>
  <p>${baseURL}/auth/reset-password?token={{.Token}}</p>
  <p>此链接将在24小时后过期。如果您没有请求重置密码，请忽略此邮件。</p>
  `

export const loginNotificationEmailTpl = `
  <h2>登录通知</h2>
  <p>您好，您的账号刚刚在新设备上登录：</p>
  <p>IP地址：{{.Ip}}</p>
  <p>时间：{{.Time}}</p>
  <p>如果这不是您本人的操作，请立即修改密码。</p>
  `
