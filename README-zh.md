# KCAuth - 统一认证服务

 Golang 实现的简单账号系统，支持多种登录方式，支持单点登录。提供完整的用户认证和授权解决方案

## 🚀 功能特性

### 认证方式
- **账号密码登录** - 传统用户名/密码认证
- **邮箱登录** - 邮箱验证码登录
- **手机号登录** - 短信验证码登录
- **第三方登录**
  - Google OAuth2.0
  - 微信登录
  - 微信小程序登录
- **JWT令牌** - 支持访问令牌和刷新令牌
- **会话管理** - Redis存储的会话系统

### 核心功能
- 📱 短信/邮箱验证码
- 🖼️ 头像上传和管理
- 👥 用户管理后台
- 📊 实时数据统计
- 🌐 多语言支持
- 🔒 安全防护（限流、IP白名单等）
- 📈 监控指标（Prometheus）

### 技术栈
- **后端**: Go 1.23+ / Gin / GORM / Redis / MySQL
- **前端**: Vue 3 / TypeScript / Vite
- **存储**: MinIO / AWS S3 / 阿里云OSS
- **部署**: Docker / Docker Compose

## 📦 项目结构

```
kcauth/
├── server/           # 后端服务 (Go)
├── web/             # 前端用户界面 (Vue)
├── admin-web/       # 管理后台 (Vue)
├── client/          # Go客户端库
├── quickstart/      # 快速启动配置
└── tools/           # 工具脚本
```

## 🚀 快速开始

```bash
cd quickstart
docker-compose up -d
```

3. **访问服务**
- 用户界面: http://localhost:8080
- 管理后台: http://localhost:8081
- MinIO控制台: http://localhost:9001


## ⚙️ 配置说明

### 数据库配置
```yaml
db:
  user: "root"
  password: "password"
  host: "localhost"
  port: 3306
  database: "kcauth"
  charset: "utf8mb4"
```

### Redis配置
```yaml
redis:
  addr: "localhost:6379"
  password: ""
  db: 0
```

### 存储配置
支持多种存储提供商：
- **MinIO** (本地对象存储)
- **AWS S3** (亚马逊云存储)
- **阿里云OSS** (阿里云对象存储)

```yaml
storage:
  provider: "minio"  # minio, s3, oss
  endpoint: "localhost:9000"
  region: "zhuhai-1"
  accessKeyID: "your-access-key"
  secretAccessKey: "your-secret-key"
  attatchBucket: "attatch"
```

### 认证提供商配置

#### Google OAuth2.0
```yaml
auth:
  google:
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
    redirect_url: "http://localhost:8080/auth/google/callback"
    scopes:
      - "https://www.googleapis.com/auth/userinfo.email"
      - "https://www.googleapis.com/auth/userinfo.profile"
```

#### 微信登录
```yaml
auth:
  weixin:
    app_id: "your-wechat-app-id"
    app_secret: "your-wechat-app-secret"
    redirect_url: "http://localhost:8080/wechat/callback"
    domain_verify_token: "your-domain-verify-token"
```

#### 短信服务
```yaml
auth:
  sms:
    provider: "aliyun"  # aliyun, tencent
    access_key: "your-access-key"
    secret_key: "your-secret-key"
    sign_name: "验证码"
    template_id: "SMS_123456789"
    region: "cn-hangzhou"
```

#### 邮件服务
```yaml
auth:
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "noreply@example.com"
    password: "your-password"
    from: "KCAuth <noreply@example.com>"
```

### 管理后台配置
- password由tools目录工具生成
```yaml
auth_admin:
  enabled: true
  secret_key: "change-this-to-a-secure-random-string"
  accounts:
    - username: "admin"
      password: "$2a$10$hashed-password"
      roles:
        - "super_admin"
  allowed_ips:
    - "127.0.0.1"
    - "::1"
  require_tls: false
  session_ttl: 30
  login_timeout: 60
```

### 可信client
- 可信client一般是后端部署的自己的业务端
- 可信client支持批量获取用户信息等
- client_secret由tools目录工具生成
```yaml
auth_trusted_clients:
  - client_id: "kcserver"
    client_secret: "YOUR_TRUSTED_CLIENT_SECRET"
    allowed_ips:
      - "*"
    scopes:
      - "read:users" 
```

## 🔧 客户端集成

### Go 客户端

```go
import "kcaitech.com/kcauth/client/auth"

// 创建JWT客户端
jwtClient := auth.NewJWTClient("http://auth-service:8080")

// 创建JWT中间件
jwtMiddleware := auth.NewJWTMiddleware(jwtClient)

// 在Gin中使用
r := gin.Default()
protected := r.Group("/api")
protected.Use(jwtMiddleware.AuthRequired())
{
    protected.GET("/profile", func(c *gin.Context) {
        // 处理受保护的资源
    })
}
```

## 🔒 安全特性

- **JWT令牌** - 安全的无状态认证
- **令牌刷新** - 自动刷新过期令牌
- **限流保护** - 防止暴力破解
- **IP白名单** - 管理后台访问控制
- **CORS配置** - 跨域请求控制
- **HTTPS支持** - 生产环境加密传输

## 🌍 国际化

支持多语言界面：
- 中文 (zh-CN)
- 英文 (en-US)

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE.txt) 文件了解详情。

