package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

func AccessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		method := c.Request.Method
		path := c.Request.URL.Path
		// clientIP := c.ClientIP()
		// userAgent := c.Request.UserAgent()

		logEntry := fmt.Sprintf("<-- %s - %s %s",
			startTime.Format("2006/01/02 15:04:05"),
			// clientIP,
			method,
			path,
		)
		fmt.Println(logEntry)

		c.Next()

		latencyTime := time.Since(startTime)
		statusCode := c.Writer.Status()

		logEntry = fmt.Sprintf("--> %s - %s %s %d - %v",
			startTime.Format("2006/01/02 15:04:05"),
			method,
			path,
			statusCode,
			latencyTime,
		)
		fmt.Println(logEntry)
	}
}
