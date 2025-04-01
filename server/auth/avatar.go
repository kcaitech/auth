package auth

import (
	"bytes"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"

	// "image/webp"
	"mime/multipart"

	"github.com/google/uuid"
	"github.com/nfnt/resize"
	"github.com/pkg/errors"
	"kcaitech.com/kcauth/server/auth/storage"
)

const (
	AvatarMaxSize = 20 * 1024 * 1024 // 20MB
	AvatarWidth   = 200
	AvatarHeight  = 200
)

type AvatarService struct {
	storage storage.Bucket
}

func NewAvatarService(storage storage.Bucket) *AvatarService {
	return &AvatarService{
		storage: storage,
	}
}

// UploadAvatar 上传用户头像
func (s *AvatarService) UploadAvatar(userID string, file *multipart.FileHeader) (string, error) {
	// 检查文件大小
	if file.Size > AvatarMaxSize {
		return "", errors.New("头像文件大小不能超过20MB")
	}

	// 检查文件类型
	// ext := strings.ToLower(filepath.Ext(file.Filename))
	// if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" && ext != ".webp" {
	// 	return "", errors.New("只支持jpg、png、gif和webp格式的图片")
	// }

	// 打开文件
	src, err := file.Open()
	if err != nil {
		return "", errors.Wrap(err, "打开文件失败")
	}
	defer src.Close()

	// 解码图片
	img, format, err := image.Decode(src)
	if err != nil {
		return "", errors.Wrap(err, "解码图片失败")
	}

	// 调整图片大小
	resized := resize.Resize(AvatarWidth, AvatarHeight, img, resize.Lanczos3)

	// 编码图片
	var buf bytes.Buffer
	switch format {
	case "jpeg":
		err = jpeg.Encode(&buf, resized, &jpeg.Options{Quality: 85})
	case "png":
		err = png.Encode(&buf, resized)
	case "gif":
		err = gif.Encode(&buf, resized, nil)
	// case "webp":
	// 	err = webp.Encode(&buf, resized, &webp.Options{Lossless: false, Quality: 85})
	default:
		return "", errors.New("不支持的图片格式")
	}
	if err != nil {
		return "", errors.Wrap(err, "编码图片失败")
	}

	// 生成文件名
	fileName := fmt.Sprintf("avatars/%s/%s%s", userID, uuid.New().String(), format)

	// 上传到OSS
	_, err = s.storage.PutObject(&storage.PutObjectInput{
		ObjectName:  fileName,
		Reader:      &buf,
		ObjectSize:  int64(buf.Len()),
		ContentType: fmt.Sprintf("image/%s", format),
	})
	if err != nil {
		return "", errors.Wrap(err, "上传头像失败")
	}

	// 返回可访问的URL
	return fileName, nil
}

// GetAvatarURL 获取头像URL
func (s *AvatarService) GetAvatarURL(fileName string) (string, error) {
	if fileName == "" {
		return "", nil
	}

	// 生成临时访问URL
	accessKey, err := s.storage.GenerateAccessKey(fileName, storage.AuthOpGetObject, 3600, "avatar-access")
	if err != nil {
		return "", errors.Wrap(err, "生成访问URL失败")
	}

	return accessKey.AccessKey, nil
}

// DeleteAvatar 删除头像
func (s *AvatarService) DeleteAvatar(fileName string) error {
	if fileName == "" {
		return nil
	}

	// 检查文件是否存在
	_, err := s.storage.GetObjectInfo(fileName)
	if err != nil {
		return errors.Wrap(err, "获取头像信息失败")
	}

	// 删除文件
	err = s.storage.DeleteObject(fileName)
	if err != nil {
		return errors.Wrap(err, "删除头像失败")
	}

	return nil
}
