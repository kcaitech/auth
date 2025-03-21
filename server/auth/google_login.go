package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// GoogleUserInfo represents user information retrieved from Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type GoogleUser struct {
	UserID        string `json:"user_id" gorm:"primarykey"`
	GoogleID      string `json:"google_id" gorm:"index"`
	Email         string `json:"email" gorm:"index"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// GoogleOAuthConfig configuration options
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Timeout      time.Duration
	DB           *gorm.DB // Added database connection
}

// GoogleOAuth merged structure that handles both OAuth and user management
type GoogleOAuth struct {
	config     *oauth2.Config
	httpClient *http.Client
	db         *gorm.DB
}

// NewGoogleOAuth creates a new Google OAuth handler
func NewGoogleOAuth(cfg GoogleOAuthConfig) (*GoogleOAuth, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("missing required configuration")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		}
	}

	return &GoogleOAuth{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     google.Endpoint,
		},
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		db: cfg.DB,
	}, nil
}

// AutoMigrate automatically migrate database table structure
func (g *GoogleOAuth) AutoMigrate() error {
	if g.db == nil {
		return fmt.Errorf("database not initialized")
	}

	if err := g.db.AutoMigrate(
		&User{},
		&GoogleUser{},
	); err != nil {
		return err
	}
	return nil
}

// GenerateState generates random state parameter
func (g *GoogleOAuth) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetAuthURL gets Google authorization URL
func (g *GoogleOAuth) GetAuthURL(state string) string {
	// Add PKCE support
	verifier := g.generateCodeVerifier()
	challenge := g.generateCodeChallenge(verifier)

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}

	return g.config.AuthCodeURL(state, opts...)
}

// HandleCallback handles OAuth callback
func (g *GoogleOAuth) HandleCallback(ctx context.Context, code, state, expectedState string) (*GoogleUserInfo, error) {
	if state == "" || state != expectedState {
		return nil, fmt.Errorf("invalid state parameter")
	}

	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	if !token.Valid() {
		return nil, fmt.Errorf("received invalid token")
	}

	user, err := g.getUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %w", err)
	}

	return user, nil
}

// getUserInfo gets user information
func (g *GoogleOAuth) getUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	var retries int
	for {
		resp, err := g.httpClient.Do(req)
		if err != nil {
			if retries < 3 {
				retries++
				time.Sleep(time.Second * time.Duration(retries))
				continue
			}
			return nil, fmt.Errorf("failed getting user info after %d retries: %w", retries, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, fmt.Errorf("failed getting user info: status=%d, body=%s",
				resp.StatusCode, string(body))
		}

		var user GoogleUserInfo
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return nil, fmt.Errorf("failed parsing user info: %w", err)
		}

		return &user, nil
	}
}

// RefreshToken refreshes access token
func (g *GoogleOAuth) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	newToken, err := g.config.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// PKCE helper functions
func (g *GoogleOAuth) generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Generate code challenge using SHA256
func (g *GoogleOAuth) generateCodeChallenge(verifier string) string {
	// Use SHA256 to generate code challenge
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// GetUserByGoogleID gets a user by Google ID
func (g *GoogleOAuth) GetUserByGoogleID(googleID, email string) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// First query Google user table
	var googleUser GoogleUser
	var userID string
	err := g.db.Where("google_id = ?", googleID).First(&googleUser).Error
	if err == nil {
		userID = googleUser.UserID
	} else if err == gorm.ErrRecordNotFound {
		var googleUserWithSameEmail EmailUser
		err = g.db.Where("email = ?", email).First(&googleUserWithSameEmail).Error
		if err != nil {
			return nil, err // Not found, return nil to let subsequent flow handle
		}
		userID = googleUserWithSameEmail.UserID
	} else {
		return nil, err
	}

	// Then query the corresponding User record
	var user User
	if err := g.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	return &user, nil
}

// RegisterOrLoginWithGoogle registers or logs in a user with Google
func (g *GoogleOAuth) RegisterOrLoginWithGoogle(ctx context.Context, code, state, expectedState string) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// 1. Handle Google callback, get user information
	googleUserInfo, err := g.HandleCallback(ctx, code, state, expectedState)
	if err != nil {
		return nil, fmt.Errorf("failed to process Google callback: %w", err)
	}

	// 2. Check if the Google user already exists
	user, err := g.GetUserByGoogleID(googleUserInfo.ID, googleUserInfo.Email)
	if err != nil {
		return nil, err
	}

	// 3. If user does not exist, create a new user
	if user == nil {
		user, err = g.CreateUserFromGoogle(googleUserInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to create Google user: %w", err)
		}
	} else {
		// 4. If user already exists, update user information
		if err := g.UpdateGoogleUserInfo(user.UserID, googleUserInfo); err != nil {
			log.Printf("Failed to update Google user information: %v", err)
			// Does not affect login process, just log the error
		}
	}

	// 5. Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := g.db.Save(user).Error; err != nil {
		log.Printf("Failed to update user last login time: %v", err)
		// Does not affect login process, just log the error
	}

	return user, nil
}

// CreateUserFromGoogle creates a user from Google information
func (g *GoogleOAuth) CreateUserFromGoogle(googleInfo *GoogleUserInfo) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Generate random UserID
	// b := make([]byte, 8)
	// if _, err := rand.Read(b); err != nil {
	// 	return nil, fmt.Errorf("failed to generate random ID: %v", err)
	// }
	userID, err := GenerateBase62ID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}

	// Ensure UserID is unique
	for {
		var count int64
		g.db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// Generate a new UserID
		userID, err = GenerateBase62ID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ID: %v", err)
		}
	}

	// Use transaction to ensure data consistency
	tx := g.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Generate random password (user cannot directly login with password)
	randomPassword := make([]byte, 16)
	if _, err := rand.Read(randomPassword); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to generate random password: %v", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("password encryption failed: %v", err)
	}

	// Extract username as nickname
	nickname := googleInfo.Name
	if nickname == "" {
		// If no name, use email prefix as default nickname
		if googleInfo.Email != "" {
			parts := strings.Split(googleInfo.Email, "@")
			nickname = parts[0]
		} else {
			nickname = userID
		}
	}

	// Create basic user record
	now := time.Now()
	user := &User{
		UserID:   userID,
		Password: string(hashedPassword),
		Status:   UserStatusActive,
		Profile: UserProfile{
			Nickname: nickname,
			Avatar:   googleInfo.Picture,
		},
		// LastAttempt: now,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Create Google user association record
	googleUser := &GoogleUser{
		UserID:        userID,
		GoogleID:      googleInfo.ID,
		Email:         googleInfo.Email,
		VerifiedEmail: googleInfo.VerifiedEmail,
		Name:          googleInfo.Name,
		Picture:       googleInfo.Picture,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := tx.Create(googleUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create Google user association: %v", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// UpdateGoogleUserInfo updates Google user information
func (g *GoogleOAuth) UpdateGoogleUserInfo(userID string, googleInfo *GoogleUserInfo) error {
	if g.db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Update Google user table information
	result := g.db.Model(&GoogleUser{}).Where("user_id = ?", userID).Updates(map[string]interface{}{
		"name":           googleInfo.Name,
		"email":          googleInfo.Email,
		"verified_email": googleInfo.VerifiedEmail,
		"picture":        googleInfo.Picture,
		"updated_at":     time.Now(),
	})

	if result.Error != nil {
		return result.Error
	}

	// Extract username as nickname
	nickname := googleInfo.Name
	if nickname == "" {
		// If no name, use email prefix as default nickname
		if googleInfo.Email != "" {
			parts := strings.Split(googleInfo.Email, "@")
			nickname = parts[0]
		}
	}

	// Also update user profile
	return g.db.Model(&User{}).Where("user_id = ?", userID).Update("profile", UserProfile{
		Nickname: nickname,
		Avatar:   googleInfo.Picture,
	}).Error
}
