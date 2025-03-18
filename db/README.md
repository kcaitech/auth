# KCAuth 项目

## 环境要求

- Docker
- Docker Compose
- Go 1.18+

## 快速开始

### 1. 启动数据库服务

使用Docker Compose启动MySQL和Redis服务：

```bash
docker-compose up -d
```

这将启动：
- MySQL 数据库 (端口: 3306)
- Redis 服务 (端口: 6379)

### 2. 修改配置文件

如果需要，可以修改 `server/config/config.json` 文件中的数据库和Redis配置：

```json
{
    "database": {
        "host": "localhost",  // 如果在Docker中运行应用，可能需要改为"mysql"
        "port": 3306,
        "username": "root",
        "password": "password",
        "database": "kcauth"
    },
    "redis": {
        "host": "localhost",  // 如果在Docker中运行应用，可能需要改为"redis"
        "port": 6379
    }
}
```

### 3. 运行服务器

```bash
cd server
go run main.go
```

## 数据持久化

MySQL和Redis的数据将被持久化到Docker卷中：
- `mysql_data`: MySQL数据
- `redis_data`: Redis数据

## 停止服务

```bash
docker-compose down
```

如果需要同时删除持久化的数据：

```bash
docker-compose down -v
``` 