/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"log"
)

// SMS Configuration
type SMSConfig struct {
	Provider   string // SMS service provider, such as "aliyun", "tencent", etc.
	AccessKey  string // Access key
	SecretKey  string // Secret key
	SignName   string // SMS signature
	TemplateID string // Template ID
	Region     string // Region
}

// Default SMS Service implementation
type DefaultSMSService struct {
	config SMSConfig
}

// Create a new SMS service
func NewSMSService(config SMSConfig) SMSService {
	return &DefaultSMSService{
		config: config,
	}
}

// Send verification code SMS
func (s *DefaultSMSService) SendVerificationSMS(phone, code string) error {
	// In a real project, this should call the SMS API to send a message
	// Example implementation, only logs
	log.Printf("Sending verification code SMS to %s, code: %s", phone, code)

	// Can be integrated with different SMS providers
	switch s.config.Provider {
	case "aliyun":
		// Call Aliyun SMS API
		return s.sendAliyunSMS(phone, code, "Verification Code")
	case "tencent":
		// Call Tencent Cloud SMS API
		return s.sendTencentSMS(phone, code, "Verification Code")
	default:
		// Default to log
		log.Printf("[SMS Service] Verification SMS: Phone=%s, Code=%s", phone, code)
		return nil
	}
}

// Send password reset SMS
func (s *DefaultSMSService) SendPasswordResetSMS(phone, code string) error {
	// Example implementation, only logs
	log.Printf("Sending password reset SMS to %s, code: %s", phone, code)

	switch s.config.Provider {
	case "aliyun":
		// Call Aliyun SMS API
		return s.sendAliyunSMS(phone, code, "Password Reset")
	case "tencent":
		// Call Tencent Cloud SMS API
		return s.sendTencentSMS(phone, code, "Password Reset")
	default:
		// Default to log
		log.Printf("[SMS Service] Password reset SMS: Phone=%s, Code=%s", phone, code)
		return nil
	}
}

// Send login notification SMS
func (s *DefaultSMSService) SendLoginNotificationSMS(phone, ip string) error {
	// Example implementation, only logs
	log.Printf("Sending login notification SMS to %s, IP: %s", phone, ip)

	switch s.config.Provider {
	case "aliyun":
		// Call Aliyun SMS API
		return s.sendAliyunSMS(phone, ip, "Login Notification")
	case "tencent":
		// Call Tencent Cloud SMS API
		return s.sendTencentSMS(phone, ip, "Login Notification")
	default:
		// Default to log
		log.Printf("[SMS Service] Login notification SMS: Phone=%s, IP=%s", phone, ip)
		return nil
	}
}

// Aliyun SMS API integration example
func (s *DefaultSMSService) sendAliyunSMS(phone, content, smsType string) error {
	// In a real project, this should integrate the Aliyun SMS SDK
	// This is just a placeholder example
	log.Printf("[Aliyun SMS] Sending %s SMS to %s: %s", smsType, phone, content)

	// Actual implementation code example:
	/*
		client, err := dysmsapi.NewClientWithAccessKey(s.config.Region, s.config.AccessKey, s.config.SecretKey)
		if err != nil {
			return err
		}

		request := dysmsapi.CreateSendSmsRequest()
		request.Scheme = "https"
		request.PhoneNumbers = phone
		request.SignName = s.config.SignName
		request.TemplateCode = s.config.TemplateID
		request.TemplateParam = fmt.Sprintf(`{"code":"%s"}`, content)

		response, err := client.SendSms(request)
		if err != nil {
			return err
		}

		if response.Code != "OK" {
			return fmt.Errorf("Failed to send SMS: %s", response.Message)
		}
	*/

	return nil
}

// Tencent Cloud SMS API integration example
func (s *DefaultSMSService) sendTencentSMS(phone, content, smsType string) error {
	// In a real project, this should integrate the Tencent Cloud SMS SDK
	// This is just a placeholder example
	log.Printf("[Tencent Cloud SMS] Sending %s SMS to %s: %s", smsType, phone, content)

	// Actual implementation code example:
	/*
		credential := common.NewCredential(s.config.AccessKey, s.config.SecretKey)
		client, err := sms.NewClient(credential, s.config.Region, clientProfile)
		if err != nil {
			return err
		}

		request := sms.NewSendSmsRequest()
		request.PhoneNumberSet = []*string{&phone}
		request.TemplateID = &s.config.TemplateID
		request.SmsSdkAppId = &s.config.SdkAppID
		request.SignName = &s.config.SignName
		request.TemplateParamSet = []*string{&content}

		response, err := client.SendSms(request)
		if err != nil {
			return err
		}

		if response.Response.SendStatusSet[0].Code != "Ok" {
			return fmt.Errorf("Failed to send SMS: %s", *response.Response.SendStatusSet[0].Message)
		}
	*/

	return nil
}
