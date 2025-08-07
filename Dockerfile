FROM golang:1.23-alpine3.20 AS builder
# FROM kcserver-builder_image:latest as builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=https://goproxy.cn,direct

RUN set -ex \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk --update add tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && apk --no-cache add ca-certificates

WORKDIR /app
COPY server .
RUN go mod download && go mod tidy -v && go build -ldflags "-s -w" -o kcauth ./main.go


# Node.js 构建阶段
FROM node:22-alpine AS web-builder

# 配置 npm 使用公共镜像源，避免认证问题
RUN npm config set registry https://registry.npmjs.org/ && \
    npm config set fetch-retries 3 && \
    npm config set fetch-retry-mintimeout 5000 && \
    npm config set fetch-retry-maxtimeout 60000

WORKDIR /app

# 构建 web 项目
COPY web ./web/
WORKDIR /app/web
RUN npm ci --no-audit --no-fund && npm run build

# 构建 admin-web 项目
WORKDIR /app
COPY admin-web ./admin-web/
WORKDIR /app/admin-web
RUN npm ci --no-audit --no-fund && npm run build


FROM golang:1.23-alpine3.20
WORKDIR /app

ENV TZ=Asia/Shanghai
RUN set -ex \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    && apk upgrade --no-cache --available \
    && apk add --no-cache fontconfig

COPY --from=builder /app/kcauth /app/
COPY --from=builder /usr/share/zoneinfo/Asia/Shanghai /usr/share/zoneinfo/Asia/Shanghai

# 从web-builder阶段复制构建好的前端资源
COPY --from=web-builder /app/web/dist /app/web/
COPY --from=web-builder /app/admin-web/dist /app/admin-web/

EXPOSE 80 81
ENTRYPOINT [ "/app/kcauth" ]
