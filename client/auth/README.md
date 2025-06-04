# KCAuth 认证服务客户端

这是一个用于与KCAuth认证服务进行交互的Go客户端库。

## 认证相关API

### 1. 令牌验证
- **路由**: `/api/token/validate`
- **方法**: POST
- **请求头**:
  - `Authorization: Bearer <access_token>`
- **响应**:
  - 成功: 200 OK
  - 失败: 401 Unauthorized

### 2. 令牌刷新
- **路由**: `/api/token/refresh`
- **方法**: POST
- **请求头**:
  - Cookie: `refreshToken=<refresh_token>`
- **响应**:
  - 成功: 200 OK
  ```json
  {
    "token": "新的访问令牌"
  }
  ```
  - 失败: 401 Unauthorized

## 用户信息相关API

### 1. 获取当前用户信息
- **路由**: `/api/user`
- **方法**: GET
- **请求头**:
  - `Authorization: Bearer <access_token>`
  - `X-Client-ID: <client_id>`
  - `X-Client-Secret: <client_secret>`
- **响应**:
  ```json
  {
    "user_id": "用户ID",
    "nickname": "用户昵称",
    "avatar": "头像URL"
  }
  ```

### 2. 获取指定用户信息
- **路由**: `/api/user/{user_id}`
- **方法**: GET
- **请求头**:
  - `Authorization: Bearer <access_token>`
  - `X-Client-ID: <client_id>`
  - `X-Client-Secret: <client_secret>`
- **响应**: 同上

### 3. 更新用户信息
- **路由**: `/api/user`
- **方法**: PUT
- **请求头**:
  - `Authorization: Bearer <access_token>`
  - `Content-Type: application/json`
- **请求体**:
  ```json
  {
    "user_id": "用户ID",
    "nickname": "新昵称",
    "avatar": "新头像URL"
  }
  ```
- **响应**:
  - 成功: 200 OK
  - 失败: 401 Unauthorized

### 4. 批量获取用户信息
- **路由**: `/api/users`
- **方法**: POST
- **请求头**:
  - `Authorization: Bearer <access_token>`
  - `Content-Type: application/json`
  - `X-Client-ID: <client_id>`
  - `X-Client-Secret: <client_secret>`
- **请求体**:
  ```json
  {
    "user_ids": ["用户ID1", "用户ID2", ...]
  }
  ```
- **响应**:
  ```json
  {
    "users": [
      {
        "user_id": "用户ID1",
        "nickname": "昵称1",
        "avatar": "头像URL1"
      },
      {
        "user_id": "用户ID2",
        "nickname": "昵称2",
        "avatar": "头像URL2"
      }
    ]
  }
  ```

## 头像相关API

### 1. 上传头像
- **路由**: `/api/avatar/upload`
- **方法**: POST
- **请求头**:
  - `Authorization: Bearer <access_token>`
  - `Content-Type: multipart/form-data`
- **请求体**:
  - 文件字段名: `avatar`
- **响应**:
  ```json
  {
    "url": "头像URL"
  }
  ```

### 2. 删除头像
- **路由**: `/api/avatar`
- **方法**: DELETE
- **请求头**:
  - `Authorization: Bearer <access_token>`
- **响应**:
  - 成功: 200 OK
  - 失败: 401 Unauthorized

## 错误响应格式
所有API在发生错误时都会返回以下格式：
```json
{
  "error": "错误信息"
}
```

## 注意事项
1. 所有需要认证的接口都需要在请求头中携带有效的访问令牌
2. 客户端认证需要在请求头中提供 `X-Client-ID` 和 `X-Client-Secret`
3. 令牌验证失败会返回401状态码
4. 文件上传接口支持multipart/form-data格式 