# KCAuth Docker部署指南

本项目包含三个主要部分：
- 后端服务器（Golang）- `/server` 目录
- 前端页面（Vue+TS）- `/web` 目录
- 管理后台（Vue+TS）- `/admin-web` 目录

这些组件被打包在一个Docker镜像中，便于部署和管理。

## 构建Docker镜像

使用提供的构建脚本来构建Docker镜像：

```bash
./build.sh [标签] [push] [仓库地址]
```

参数说明：
- `标签`: 可选，Docker镜像标签。默认为`latest`
- `push`: 可选，如果指定为"push"，则会将镜像推送到远程仓库
- `仓库地址`: 可选，远程仓库地址。默认为`docker.io/username`

示例：
```bash
# 构建标签为v1.0.0的镜像
./build.sh v1.0.0

# 构建并推送到默认仓库
./build.sh v1.0.0 push

# 构建并推送到指定仓库
./build.sh v1.0.0 push myregistry.com/myproject
```

## 运行容器

### 使用默认配置运行

```bash
docker run -d --name kcauth -p 8080:8080 -p 8081:8081 kcauth:latest
```

### 使用自定义配置文件运行

```bash
docker run -d --name kcauth \
  -p 8080:8080 -p 8081:8081 \
  -v /path/to/config.json:/app/server/config/config.json \
  kcauth:latest
```

### 使用环境变量覆盖配置

```bash
docker run -d --name kcauth \
  -p 8080:8080 -p 8081:8081 \
  -e DB_HOST=your-db-host \
  -e DB_PORT=3306 \
  -e DB_USER=your-db-user \
  -e DB_PASSWORD=your-db-password \
  -e DB_NAME=kcauth \
  -e REDIS_HOST=your-redis-host \
  -e REDIS_PORT=6379 \
  -e REDIS_PASSWORD=your-redis-password \
  kcauth:latest
```

## 支持的环境变量

| 环境变量 | 说明 | 默认值 |
|---------|------|-------|
| DB_HOST | 数据库主机 | localhost |
| DB_PORT | 数据库端口 | 3306 |
| DB_USER | 数据库用户名 | root |
| DB_PASSWORD | 数据库密码 | password |
| DB_NAME | 数据库名称 | kcauth |
| REDIS_HOST | Redis主机 | localhost |
| REDIS_PORT | Redis端口 | 6379 |
| REDIS_PASSWORD | Redis密码 | (空) |
| SERVER_PORT | 主服务器端口 | 8080 |
| ADMIN_PORT | 管理服务器端口 | 8081 |

## 访问服务

- 主要前端界面：`http://your-host:8080`
- 管理后台：`http://your-host:8081/admin`

## 注意事项

1. 确保数据库和Redis服务器可从Docker容器访问
2. 如果将服务暴露到公网，建议使用反向代理（如Nginx）并配置SSL
3. 默认配置中的密钥应在生产环境中更改为强密钥
4. 容器中的日志存储在`/app/logs`目录，如需持久化可挂载外部卷