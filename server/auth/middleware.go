package auth

import (
    "net/http"
    "sync"
    "log"
    "github.com/gin-gonic/gin"
    "github.com/robfig/cron/v3"
)

// 权限检查中间件
type AuthMiddleware struct {
    auth *AccountAuth
    rolePermissions map[UserRole][]Permission
    mu sync.RWMutex
}

// NewAuthMiddleware 创建权限中间件
func NewAuthMiddleware(auth *AccountAuth) *AuthMiddleware {
    m := &AuthMiddleware{
        auth: auth,
        rolePermissions: make(map[UserRole][]Permission),
    }

    // 初始化默认权限
    m.SetRolePermissions(RoleAdmin, []Permission{
        PermReadBasic, PermReadAdmin,
        PermWriteBasic, PermWriteAdmin,
        PermDeleteBasic, PermDeleteAdmin,
    })

    m.SetRolePermissions(RoleUser, []Permission{
        PermReadBasic,
        PermWriteBasic,
        PermDeleteBasic,
    })

    m.SetRolePermissions(RoleGuest, []Permission{
        PermReadBasic,
    })

    return m
}

// SetRolePermissions 设置角色权限
func (m *AuthMiddleware) SetRolePermissions(role UserRole, permissions []Permission) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.rolePermissions[role] = permissions
}

// GetRolePermissions 获取角色权限
func (m *AuthMiddleware) GetRolePermissions(role UserRole) []Permission {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.rolePermissions[role]
}

// HasPermission 检查用户是否有指定权限
func (m *AuthMiddleware) HasPermission(roles []UserRole, requiredPerm Permission) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()

    for _, role := range roles {
        perms := m.rolePermissions[role]
        for _, perm := range perms {
            if perm == requiredPerm {
                return true
            }
        }
    }
    return false
}

// RequirePermission 需要特定权限的中间件
func (m *AuthMiddleware) RequirePermission(permission Permission) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 从上下文获取用户ID
        userID, exists := c.Get("user_id")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            c.Abort()
            return
        }

        // 获取用户角色
        roles, err := m.auth.GetUserRoles(userID.(uint))
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user roles"})
            c.Abort()
            return
        }

        // 检查权限
        if !m.HasPermission(roles, permission) {
            c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// RequireRole 需要特定角色的中间件
func (m *AuthMiddleware) RequireRole(role UserRole) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID, exists := c.Get("user_id")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            c.Abort()
            return
        }

        roles, err := m.auth.GetUserRoles(userID.(uint))
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user roles"})
            c.Abort()
            return
        }

        hasRole := false
        for _, r := range roles {
            if r == role {
                hasRole = true
                break
            }
        }

        if !hasRole {
            c.JSON(http.StatusForbidden, gin.H{"error": "role required"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// CleanupScheduler 清理调度器
type CleanupScheduler struct {
    auth *AccountAuth
    cron *cron.Cron
}

// NewCleanupScheduler 创建清理调度器
func NewCleanupScheduler(auth *AccountAuth) *CleanupScheduler {
    return &CleanupScheduler{
        auth: auth,
        cron: cron.New(),
    }
}

// Start 启动定时任务
func (s *CleanupScheduler) Start() error {
    // 每小时清理过期会话
    if _, err := s.cron.AddFunc("@hourly", func() {
        if err := s.auth.CleanExpiredSessions(); err != nil {
            log.Printf("Failed to clean expired sessions: %v", err)
        }
    }); err != nil {
        return err
    }

    // 每天清理过期验证记录
    if _, err := s.cron.AddFunc("@daily", func() {
        if err := s.auth.CleanExpiredVerifications(); err != nil {
            log.Printf("Failed to clean expired verifications: %v", err)
        }
    }); err != nil {
        return err
    }

    // 每周清理旧的登录尝试记录
    if _, err := s.cron.AddFunc("@weekly", func() {
        if err := s.auth.CleanOldLoginAttempts(); err != nil {
            log.Printf("Failed to clean old login attempts: %v", err)
        }
    }); err != nil {
        return err
    }

    s.cron.Start()
    return nil
}

// Stop 停止定时任务
func (s *CleanupScheduler) Stop() {
    s.cron.Stop()
} 