/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type MinioClient struct {
	config *ClientConfig
	client *minio.Client
}

func NewMinioClient(config *ClientConfig) (Client, error) {
	c, err := minio.New(config.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Region: config.Region,
		Secure: false,
	})
	if err != nil {
		return nil, err
	}
	return &MinioClient{
		config: config,
		client: c,
	}, nil
}

type MinioBucket struct {
	DefaultBucket
	config *BucketConfig
	client *MinioClient
}

func (that *MinioClient) NewBucket(config *BucketConfig) Bucket {
	instance := &MinioBucket{
		config: config,
		client: that,
	}
	instance.That = instance
	return instance
}

func (that *MinioBucket) GetConfig() *Config {
	return &Config{
		ClientConfig: *that.client.config,
		BucketConfig: *that.config,
	}
}

func (that *MinioBucket) PutObject(putObjectInput *PutObjectInput) (*UploadInfo, error) {
	if putObjectInput.ContentType == "" {
		putObjectInput.ContentType = "application/octet-stream"
		splitRes := strings.Split(putObjectInput.ObjectName, ".")
		if len(splitRes) > 1 {
			switch splitRes[len(splitRes)-1] {
			case "json":
				putObjectInput.ContentType = "application/json"
			}
		}
	}
	result, err := that.client.client.PutObject(
		context.Background(),
		that.config.BucketName,
		putObjectInput.ObjectName,
		putObjectInput.Reader,
		putObjectInput.ObjectSize,
		minio.PutObjectOptions{
			ContentType: putObjectInput.ContentType,
		},
	)
	if err != nil {
		return nil, err
	}
	return &UploadInfo{
		VersionID: result.VersionID,
	}, nil
}

func (that *MinioBucket) GetObjectInfo(objectName string) (*ObjectInfo, error) {
	objectInfo, err := that.client.client.StatObject(
		context.Background(),
		that.config.BucketName,
		objectName,
		minio.StatObjectOptions{},
	)
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		VersionID: objectInfo.VersionID,
	}, nil
}

func (that *MinioBucket) GetObject(objectName string) ([]byte, error) {
	object, err := that.client.client.GetObject(
		context.Background(),
		that.config.BucketName,
		objectName,
		minio.GetObjectOptions{},
	)
	if err != nil {
		return nil, err
	}
	defer object.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(object)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var minioAuthOpMap = map[int]string{
	AuthOpGetObject:  "s3:GetObject",
	AuthOpPutObject:  "s3:PutObject",
	AuthOpDelObject:  "s3:DeleteObject",
	AuthOpListObject: "s3:ListBucket",
}

func (that *MinioBucket) GenerateAccessKey(authPath string, authOp int, expires int, roleSessionName string) (*AccessKeyValue, error) {
	authPath = strings.TrimLeft(authPath, "/")
	authOpList := make([]string, 0, strconv.IntSize)
	authOpListDistinct := make(map[int]struct{}, strconv.IntSize)
	for i := 0; i < strconv.IntSize; i++ {
		authOpValue := 1 << i
		if _, ok := authOpListDistinct[authOpValue]; ok {
			continue
		}
		if authOp&(authOpValue) > 0 {
			authOpList = append(authOpList, minioAuthOpMap[authOpValue])
			authOpListDistinct[authOpValue] = struct{}{}
		}
	}
	policy, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Action": authOpList,
				"Effect": "Allow",
				"Resource": []string{
					"arn:aws:s3:::" + that.config.BucketName + "/" + authPath,
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	roleArn := ""
	stsAssumeRole, err := credentials.NewSTSAssumeRole("http://"+that.client.config.Endpoint, credentials.STSAssumeRoleOptions{
		AccessKey:       that.client.config.StsAccessKeyID,
		SecretKey:       that.client.config.StsSecretAccessKey,
		Policy:          string(policy),
		Location:        that.client.config.Region,
		DurationSeconds: expires,
		RoleARN:         roleArn,
		RoleSessionName: roleSessionName,
	})
	if err != nil {
		return nil, err
	}
	v, err := stsAssumeRole.Get()
	if err != nil {
		return nil, err
	}
	value := AccessKeyValue{
		AccessKey:       v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		SessionToken:    v.SessionToken,
		SignerType:      int(v.SignerType),
	}
	return &value, err
}

func (that *MinioBucket) CopyObject(srcPath string, destPath string) (*UploadInfo, error) {
	_, err := that.client.client.CopyObject(
		context.Background(),
		minio.CopyDestOptions{
			Bucket: that.config.BucketName,
			Object: destPath,
		},
		minio.CopySrcOptions{
			Bucket: that.config.BucketName,
			Object: srcPath,
		},
	)
	if err != nil {
		return nil, err
	}
	return &UploadInfo{}, nil
}

func (that *MinioBucket) CopyDirectory(srcDirPath string, destDirPath string) (*UploadInfo, error) {
	if srcDirPath == "" || srcDirPath == "/" || destDirPath == "" || destDirPath == "/" {
		return nil, errors.New("路径不能为空")
	}
	for objectInfo := range that.client.client.ListObjects(context.Background(), that.config.BucketName, minio.ListObjectsOptions{
		Prefix:    srcDirPath,
		Recursive: true,
	}) {
		if objectInfo.Err != nil {
			log.Println("ListObjects异常：", objectInfo.Err)
			continue
		}
		_, _ = that.CopyObject(objectInfo.Key, strings.Replace(objectInfo.Key, srcDirPath, destDirPath, 1))
	}
	return &UploadInfo{}, nil
}

// DeleteObject 删除对象
func (that *MinioBucket) DeleteObject(objectName string) error {
	err := that.client.client.RemoveObject(
		context.Background(),
		that.config.BucketName,
		objectName,
		minio.RemoveObjectOptions{},
	)
	if err != nil {
		return err
	}
	return nil
}
