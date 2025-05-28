/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sts"
)

type S3Client struct {
	config *ClientConfig
	sess   *session.Session
	client *s3.S3
}

func NewS3Client(config *ClientConfig) (Client, error) {
	sess, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(config.Endpoint),
		Region:           aws.String(config.Region),
		Credentials:      credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, ""),
		DisableSSL:       aws.Bool(true),
		S3ForcePathStyle: aws.Bool(false), // oss需要为false，minio需要为true
	})
	if err != nil {
		return nil, err
	}
	return &S3Client{
		config: config,
		sess:   sess,
		client: s3.New(sess),
	}, nil
}

type S3Bucket struct {
	DefaultBucket
	config *BucketConfig
	client *S3Client
}

func (that *S3Client) NewBucket(config *BucketConfig) Bucket {
	instance := &S3Bucket{
		config: config,
		client: that,
	}
	instance.That = instance
	return instance
}

func (that *S3Bucket) GetConfig() *Config {
	return &Config{
		ClientConfig: *that.client.config,
		BucketConfig: *that.config,
	}
}

func (that *S3Bucket) PutObject(putObjectInput *PutObjectInput) (*UploadInfo, error) {
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
	uploader := s3manager.NewUploader(that.client.sess)
	result, err := uploader.Upload(&s3manager.UploadInput{
		Bucket:      aws.String(that.config.BucketName),
		Key:         aws.String(putObjectInput.ObjectName),
		Body:        putObjectInput.Reader,
		ContentType: aws.String(putObjectInput.ContentType),
	})
	if err != nil {
		return nil, err
	}
	versionID := ""
	if result.VersionID != nil {
		versionID = *result.VersionID
	}
	return &UploadInfo{
		VersionID: versionID,
	}, nil
}

func (that *S3Bucket) GetObjectInfo(objectName string) (*ObjectInfo, error) {
	result, err := that.client.client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(that.config.BucketName),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		VersionID: *result.VersionId,
	}, nil
}

func (that *S3Bucket) GetObject(objectName string) ([]byte, error) {
	result, err := that.client.client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(that.config.BucketName),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(result.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var s3authOpMap = map[int]string{
	AuthOpGetObject:  "s3:GetObject",
	AuthOpPutObject:  "s3:PutObject",
	AuthOpDelObject:  "s3:DeleteObject",
	AuthOpListObject: "s3:ListBucket",
}

func (that *S3Bucket) GenerateAccessKey(authPath string, authOp int, expires int, roleSessionName string) (*AccessKeyValue, error) {
	authPath = strings.TrimLeft(authPath, "/")
	authOpList := make([]string, 0, strconv.IntSize)
	authOpListDistinct := make(map[int]struct{}, strconv.IntSize)
	for i := 0; i < strconv.IntSize; i++ {
		authOpValue := 1 << i
		if _, ok := authOpListDistinct[authOpValue]; ok {
			continue
		}
		if authOp&(authOpValue) > 0 {
			authOpList = append(authOpList, s3authOpMap[authOpValue])
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
	stsSvc := sts.New(that.client.sess)
	roleArn := "acs:aws:iam::" + that.client.config.AccountId + ":role/" + that.client.config.RoleName
	result, err := stsSvc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		Policy:          aws.String(string(policy)),
		DurationSeconds: aws.Int64(int64(expires)),
	})
	if err != nil {
		return nil, err
	}
	value := AccessKeyValue{
		AccessKey:       *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
	}
	return &value, err
}

func (that *S3Bucket) CopyObject(srcPath string, destPath string) (*UploadInfo, error) {
	_, err := that.client.client.CopyObject(&s3.CopyObjectInput{
		CopySource: aws.String(that.config.BucketName + "/" + srcPath),
		Bucket:     aws.String(that.config.BucketName),
		Key:        aws.String(destPath),
	})
	if err != nil {
		return nil, err
	}
	return &UploadInfo{}, nil
}

func (that *S3Bucket) CopyDirectory(srcDirPath string, destDirPath string) (*UploadInfo, error) {
	if srcDirPath == "" || srcDirPath == "/" || destDirPath == "" || destDirPath == "/" {
		return nil, errors.New("路径不能为空")
	}
	if err := that.client.client.ListObjectsV2Pages(&s3.ListObjectsV2Input{
		Bucket:    aws.String(that.config.BucketName),
		Prefix:    aws.String(srcDirPath),
		Delimiter: nil,
	}, func(result *s3.ListObjectsV2Output, b bool) bool {
		for _, objectInfo := range result.Contents {
			_, _ = that.CopyObject(*objectInfo.Key, strings.Replace(*objectInfo.Key, srcDirPath, destDirPath, 1))
		}
		return true
	}); err != nil {
		return nil, err
	}
	return &UploadInfo{}, nil
}

// DeleteObject 删除对象
func (that *S3Bucket) DeleteObject(objectName string) error {
	_, err := that.client.client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(that.config.BucketName),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return err
	}
	return nil
}
