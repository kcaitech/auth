#!/bin/bash
set -e

# 显示构建信息
echo "开始构建 kcauth 应用..."

# 定义镜像名称和标签
IMAGE_NAME="kcauth"
TAG=${1:-latest}  # 如果没有提供标签参数，使用latest

# 构建Docker镜像
echo "正在构建 Docker 镜像 ${IMAGE_NAME}:${TAG}..."
docker build -t ${IMAGE_NAME}:${TAG} .

echo "镜像构建完成: ${IMAGE_NAME}:${TAG}"

# 可选：推送到Docker仓库
if [ "$2" = "push" ]; then
  REGISTRY=${3:-"docker.io/username"}  # 如果没有提供仓库参数，使用默认值
  REMOTE_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"
  
  echo "正在标记镜像为 ${REMOTE_IMAGE}..."
  docker tag ${IMAGE_NAME}:${TAG} ${REMOTE_IMAGE}
  
  echo "正在推送镜像到 ${REMOTE_IMAGE}..."
  docker push ${REMOTE_IMAGE}
  
  echo "镜像已推送到 ${REMOTE_IMAGE}"
fi

# 显示运行指南
echo ""
echo "=== 运行指南 ==="
echo "要在本地运行镜像，请执行:"
echo "docker run -d --name kcauth -p 8080:8080 -p 8081:8081 ${IMAGE_NAME}:${TAG}"
echo ""
echo "要使用自定义配置运行，请执行:"
echo "docker run -d --name kcauth -p 8080:8080 -p 8081:8081 -v /path/to/config.json:/app/server/config/config.json ${IMAGE_NAME}:${TAG}"
echo ""
echo "要使用环境变量覆盖数据库和Redis配置，请执行:"
echo "docker run -d --name kcauth \\"
echo "  -p 8080:8080 -p 8081:8081 \\"
echo "  -e DB_HOST=your-db-host \\"
echo "  -e DB_PORT=3306 \\"
echo "  -e DB_USER=your-db-user \\"
echo "  -e DB_PASSWORD=your-db-password \\"
echo "  -e DB_NAME=kcauth \\"
echo "  -e REDIS_HOST=your-redis-host \\"
echo "  -e REDIS_PORT=6379 \\"
echo "  -e REDIS_PASSWORD=your-redis-password \\"
echo "  ${IMAGE_NAME}:${TAG}"
echo ""