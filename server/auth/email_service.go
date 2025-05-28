/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"
)

// SmtpConfig Email Configuration
type SmtpConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// BaseURL  string // Used to generate verification links
}

// EmailServiceImpl Email service implementation
type EmailServiceImpl struct {
	config SmtpConfig
}

// NewEmailService Create a new email service instance
func NewEmailService(config SmtpConfig) EmailService {
	return &EmailServiceImpl{
		config: config,
	}
}

// SendVerificationEmail Send verification email
func (s *EmailServiceImpl) SendVerificationEmail(email, token, title, content string) error {
	data := struct {
		Token string
	}{
		Token: token,
	}
	return s.sendEmail(email, title, content, data)
}

// SendPasswordResetEmail Send password reset email
func (s *EmailServiceImpl) SendPasswordResetEmail(email, token, title, content string) error {
	data := struct {
		// BaseURL string
		Token string
	}{
		// BaseURL: s.config.BaseURL,
		Token: token,
	}
	return s.sendEmail(email, title, content, data)
}

// SendLoginNotificationEmail Send login notification email
func (s *EmailServiceImpl) SendLoginNotificationEmail(email, ip, title, content string) error {
	data := struct {
		Ip   string
		Time string
	}{
		Ip:   ip,
		Time: time.Now().Format("2006-01-02 15:04:05"),
	}
	return s.sendEmail(email, title, content, data)
}

// sendEmail General method for sending emails
func (s *EmailServiceImpl) sendEmail(to, subject, tplStr string, data interface{}) error {
	// Parse template
	tpl, err := template.New("email").Parse(tplStr)
	if err != nil {
		return err
	}

	// Render template
	var body bytes.Buffer
	if err := tpl.Execute(&body, data); err != nil {
		return err
	}

	// Build email content
	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n%s", to, s.config.From, subject, body.String()))

	// Extract pure email address from the configured From field
	fromEmail := s.config.From
	if idx := strings.LastIndex(fromEmail, "<"); idx >= 0 {
		if end := strings.LastIndex(fromEmail, ">"); end > idx {
			fromEmail = fromEmail[idx+1 : end]
		}
	}

	// Send email
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	return smtp.SendMail(addr, auth, fromEmail, []string{to}, msg)
}
