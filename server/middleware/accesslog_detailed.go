/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func AccessDetailedLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		method := c.Request.Method
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		var logEntry string
		// 检查是否为二进制文件类型或文件上传
		contentType := c.Request.Header.Get("Content-Type")
		isBinary := strings.Contains(contentType, "image/") ||
			strings.Contains(contentType, "video/") ||
			strings.Contains(contentType, "audio/") ||
			strings.Contains(contentType, "application/octet-stream") ||
			strings.Contains(contentType, "multipart/form-data")

		// 读取请求体
		if c.Request.Body != nil && !isBinary {
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				fmt.Println("Error reading request body:", err)
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			// 将请求体还原为原始状态
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
			logEntry = fmt.Sprintf("<-- %s - %s %s?%s - Body: %s",
				startTime.Format("2006/01/02 15:04:05"),
				method,
				path,
				query,
				string(body),
			)
		} else {
			if isBinary {
				logEntry = fmt.Sprintf("<-- %s - %s %s?%s - [Binary Content]",
					startTime.Format("2006/01/02 15:04:05"),
					method,
					path,
					query,
				)
			} else {
				logEntry = fmt.Sprintf("<-- %s - %s %s?%s",
					startTime.Format("2006/01/02 15:04:05"),
					method,
					path,
					query,
				)
			}
		}

		fmt.Println(logEntry)

		c.Next()

		latencyTime := time.Since(startTime)
		statusCode := c.Writer.Status()

		logEntry = fmt.Sprintf("--> %s - %s %s?%s %d - %v",
			startTime.Format("2006/01/02 15:04:05"),
			method,
			path,
			query,
			statusCode,
			latencyTime,
		)
		fmt.Println(logEntry)
	}
}
