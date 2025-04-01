package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"kcaitech.com/kcauth/server/auth"
)

type AvatarHandler struct {
	avatarService *auth.AvatarService
	accountAuth   *auth.AccountAuth
}

func NewAvatarHandler(accountAuth *auth.AccountAuth, avatarService *auth.AvatarService) *AvatarHandler {
	return &AvatarHandler{
		accountAuth:   accountAuth,
		avatarService: avatarService,
	}
}

// UploadAvatar 上传头像
func (h *AvatarHandler) UploadAvatar(c *gin.Context) {
	// 获取用户ID
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}

	// 获取上传的文件
	file, err := c.FormFile("avatar")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "获取上传文件失败"})
		return
	}

	// 上传头像
	fileName, err := h.avatarService.UploadAvatar(userID, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 将fileName更新到用户信息
	// Prepare update data
	updates := make(map[string]interface{})
	updates["profile.avatar"] = fileName
	if err := h.accountAuth.UpdateProfile(userID, updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 获取可访问的URL
	url, err := h.avatarService.GetAvatarURL(fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取头像URL失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"url": url,
	})
}

// DeleteAvatar 删除头像
func (h *AvatarHandler) DeleteAvatar(c *gin.Context) {
	// 获取用户ID
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}

	// 获取当前头像文件名
	// fileName := c.Query("file")
	// if fileName == "" {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "未指定要删除的头像"})
	// 	return
	// }
	user, err := h.accountAuth.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if user.Profile.Avatar != "" {
		// 删除头像
		err = h.avatarService.DeleteAvatar(user.Profile.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "删除头像失败"})
			return
		}
		// update profile
		updates := make(map[string]interface{})
		updates["profile.avatar"] = ""
		if err := h.accountAuth.UpdateProfile(userID, updates); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}
