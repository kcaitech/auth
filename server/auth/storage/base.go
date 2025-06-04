/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package storage

import (
	"bytes"
	"errors"
	"io"
)

type Provider string

const (
	MINIO Provider = "minio"
	S3    Provider = "s3"
	OSS   Provider = "oss"
)

type Client interface {
	NewBucket(config *BucketConfig) Bucket
}

type ClientConfig struct {
	Provider        Provider `yaml:"provider" json:"provider"`
	Endpoint        string   `yaml:"endpoint" json:"endpoint"`
	Region          string   `yaml:"region" json:"region"`
	AccessKeyID     string   `yaml:"accessKeyID" json:"accessKeyID"`
	SecretAccessKey string   `yaml:"secretAccessKey" json:"secretAccessKey"`

	// minio sts
	StsAccessKeyID     string `yaml:"stsAccessKeyID" json:"stsAccessKeyID"`
	StsSecretAccessKey string `yaml:"stsSecretAccessKey" json:"stsSecretAccessKey"`

	// s3/oss sts
	StsEndpoint string `yaml:"stsEndpoint" json:"stsEndpoint"`
	AccountId   string `yaml:"accountId" json:"accountId"`
	RoleName    string `yaml:"roleName" json:"roleName"`
}

type PutObjectInput struct {
	ObjectName  string
	Reader      io.Reader
	ObjectSize  int64
	ContentType string
}

type Bucket interface {
	GetConfig() *Config
	PutObject(putObjectInput *PutObjectInput) (*UploadInfo, error)
	PutObjectByte(objectName string, content []byte) (*UploadInfo, error)
	// PutObjectList(putObjectInputList []*PutObjectInput) ([]*UploadInfo, []error)
	GenerateAccessKey(authPath string, authOp int, expires int, roleSessionName string) (*AccessKeyValue, error)
	CopyObject(srcPath string, destPath string) (*UploadInfo, error)
	CopyDirectory(srcDirPath string, destDirPath string) (*UploadInfo, error)
	GetObjectInfo(objectName string) (*ObjectInfo, error)
	GetObject(objectName string) ([]byte, error)
	DeleteObject(objectName string) error
}

type BucketConfig struct {
	BucketName string `yaml:"bucketName" json:"bucketName"`
	// AttatchBucketName string `yaml:"attatchBucketName" json:"attatchBucketName"`
}

type Config struct {
	ClientConfig `yaml:",inline" json:",inline"`
	BucketConfig `yaml:",inline" json:",inline"`
}

type UploadInfo struct {
	VersionID string `json:"versionId"`
}

type ObjectInfo struct {
	VersionID string `json:"versionId"`
}

type DefaultBucket struct {
	That Bucket
}

func (that *DefaultBucket) GetConfig() (*Config, error) {
	return nil, errors.New("GetConfig方法未实现")
}

func (that *DefaultBucket) PubObject(putObjectInput *PutObjectInput) (*UploadInfo, error) {
	return nil, errors.New("PubObject方法未实现")
}

func (that *DefaultBucket) PutObjectByte(objectName string, content []byte) (*UploadInfo, error) {
	return that.That.PutObject(&PutObjectInput{
		ObjectName:  objectName,
		Reader:      bytes.NewReader(content),
		ObjectSize:  int64(len(content)),
		ContentType: "",
	})
}

// func (that *DefaultBucket) PutObjectList(putObjectInputList []*PutObjectInput) ([]*UploadInfo, []error) {
// 	uploadInfoMap := my_map.NewSyncMap[int, *UploadInfo]()
// 	errorMap := my_map.NewSyncMap[int, error]()
// 	uploadWaitGroup := sync.WaitGroup{}
// 	for index, putObjectInput := range putObjectInputList {
// 		uploadWaitGroup.Add(1)
// 		go func(index int, putObjectInput *PutObjectInput) {
// 			defer uploadWaitGroup.Done()
// 			result, err := that.That.PutObject(putObjectInput)
// 			uploadInfoMap.Set(index, result)
// 			errorMap.Set(index, err)
// 		}(index, putObjectInput)
// 	}
// 	uploadWaitGroup.Wait()
// 	uploadInfoList := make([]*UploadInfo, 0, len(putObjectInputList))
// 	errorList := make([]error, 0, len(putObjectInputList))
// 	for index := 0; index < len(putObjectInputList); index++ {
// 		uploadInfo, _ := uploadInfoMap.Get(index)
// 		err, _ := errorMap.Get(index)
// 		uploadInfoList = append(uploadInfoList, uploadInfo)
// 		errorList = append(errorList, err)
// 	}
// 	return uploadInfoList, errorList
// }

func (that *DefaultBucket) CopyObject(srcPath string, destPath string) (*UploadInfo, error) {
	return nil, errors.New("CopyObject方法未实现")
}

func (that *DefaultBucket) CopyDirectory(srcDirPath string, destDirPath string) (*UploadInfo, error) {
	return nil, errors.New("CopyDirectory方法未实现")
}

type AccessKeyValue struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	SignerType      int    `json:"signer_type"`
}

const (
	AuthOpGetObject  = 1 << 0
	AuthOpPutObject  = 1 << 1
	AuthOpDelObject  = 1 << 2
	AuthOpListObject = 1 << 3
	AuthOpAll        = AuthOpGetObject | AuthOpPutObject | AuthOpDelObject | AuthOpListObject
)

func (that *DefaultBucket) GenerateAccessKey(authPath string, authOp int, expires int, roleSessionName string) (*AccessKeyValue, error) {
	return nil, errors.New("generateAccessKey方法未实现")
}

func (that *DefaultBucket) DeleteObject(objectName string) error {
	return errors.New("DeleteObject方法未实现")
}

// type StorageConf struct {
// 	Provider Provider `yaml:"provider" json:"provider"`
// 	Minio    Config   `yaml:"minio" json:"minio"`
// 	S3       Config   `yaml:"s3" json:"s3"`
// 	Oss      Config   `yaml:"oss" json:"oss"`
// }
