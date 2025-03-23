FROM node:18-alpine AS web-builder

WORKDIR /app/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM node:18-alpine AS admin-builder

WORKDIR /app/admin-web
COPY admin-web/package*.json ./
RUN npm install
COPY admin-web/ ./
RUN npm run build

FROM golang:1.20-alpine AS server-builder

WORKDIR /app/server
COPY server/ ./
RUN go mod download
RUN go build -o kcauth-server .

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 复制前端构建结果
COPY --from=web-builder /app/web/dist /app/web/dist
# 复制管理后台构建结果
COPY --from=admin-builder /app/admin-web/dist /app/admin-web/dist
# 复制后端构建结果
COPY --from=server-builder /app/server/kcauth-server /app/server/kcauth-server
# 复制服务器配置
COPY server/config /app/server/config
# 复制入口点脚本
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 默认环境变量
ENV GIN_MODE=release
# 创建必要的目录
RUN mkdir -p /app/logs

EXPOSE 8080
EXPOSE 8081

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/server/kcauth-server", "--config", "/app/server/config/config.json"] 