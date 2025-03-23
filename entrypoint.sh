#!/bin/sh
set -e

CONFIG_FILE="/app/server/config/config.json"

# 更新配置文件中的数据库配置
if [ -n "$DB_HOST" ]; then
  sed -i "s/\"host\": \"localhost\"/\"host\": \"$DB_HOST\"/" $CONFIG_FILE
fi

if [ -n "$DB_PORT" ]; then
  sed -i "s/\"port\": 3306/\"port\": $DB_PORT/" $CONFIG_FILE
fi

if [ -n "$DB_USER" ]; then
  sed -i "s/\"username\": \"root\"/\"username\": \"$DB_USER\"/" $CONFIG_FILE
fi

if [ -n "$DB_PASSWORD" ]; then
  sed -i "s/\"password\": \"password\"/\"password\": \"$DB_PASSWORD\"/" $CONFIG_FILE
fi

if [ -n "$DB_NAME" ]; then
  sed -i "s/\"database\": \"kcauth\"/\"database\": \"$DB_NAME\"/" $CONFIG_FILE
fi

# 更新配置文件中的Redis配置
if [ -n "$REDIS_HOST" ]; then
  sed -i "s/\"host\": \"localhost\"/\"host\": \"$REDIS_HOST\"/" $CONFIG_FILE
fi

if [ -n "$REDIS_PORT" ]; then
  sed -i "s/\"port\": 6379/\"port\": $REDIS_PORT/" $CONFIG_FILE
fi

if [ -n "$REDIS_PASSWORD" ]; then
  sed -i "s/\"password\": \"\"/\"password\": \"$REDIS_PASSWORD\"/" $CONFIG_FILE
fi

# 检查是否需要覆盖服务器端口
if [ -n "$SERVER_PORT" ]; then
  sed -i "s/\"port\": 8080/\"port\": $SERVER_PORT/" $CONFIG_FILE
fi

if [ -n "$ADMIN_PORT" ]; then
  sed -i "s/\"port\": 8081/\"port\": $ADMIN_PORT/" $CONFIG_FILE
fi

# 执行主程序
exec "$@" 