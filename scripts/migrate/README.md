# 用户数据迁移工具(moss.design->vextra.cn)

这个工具用于将用户数据从一个数据库迁移到另一个数据库。

## 环境要求

- Go 1.21 或更高版本
- MySQL 数据库

## 配置

通过 `config.yaml` 配置源数据库和目标数据库的连接信息：

在项目根目录创建 `config.yaml` 文件，内容如下：

```yaml
source_db:
  host: localhost
  port: 3806
  user: root
  password: kKEIjksvnOOIjdZ6rtzE
  database: kcserver

target_db:
  host: localhost
  port: 3306
  user: root
  password: password
  database: kcauth
```

请根据实际环境修改配置文件中的数据库连接信息。

## 运行迁移

```bash
cd server/scripts/migrate
go mod tidy
go build
./migrate
```

## 注意事项

1. 在运行迁移之前，请确保：
   - 源数据库和目标数据库都已创建
   - 目标数据库中的表结构已经存在
   - 有足够的权限访问两个数据库

2. 工具会自动：
   - 将明文密码转换为 bcrypt 加密格式
   - 保持用户 ID、昵称、头像等信息不变
   - 使用事务确保数据一致性

3. 如果源数据库的表结构与工具中的默认结构不同，请修改 `readUsers` 函数中的 SQL 查询语句。

## 错误处理

如果遇到错误，工具会输出详细的错误信息。常见错误包括：
- 数据库连接失败
- 表结构不匹配
- 权限不足
- 数据格式错误