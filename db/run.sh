#!/bin/sh

PRJ_NAME=kcauth

# 判断参数‘up’或‘down’
if [ "$1" = "up" ]; then
    docker compose -f docker-compose.yml -p $PRJ_NAME up -d
elif [ "$1" = "down" ]; then
    docker-compose  -p $PRJ_NAME down
else
    echo "Usage: $0 {up|down}"
    exit 1
fi

