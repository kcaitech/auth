package auth

// 微信登录

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "strings"
    "errors"
)

// WeixinConfig 微信登录配置
type WeixinConfig struct {
    AppID       string
    AppSecret   string
    RedirectURL string
}

// Validate 验证配置
func (c *WeixinConfig) Validate() error {
    if c.AppID == "" || c.AppSecret == "" || c.RedirectURL == "" {
        return ErrInvalidConfig("微信登录配置无效")
    }
    return nil
}

// WeixinLoginResponse 微信登录响应
type WeixinLoginResponse struct {
    AccessToken  string `json:"access_token"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    OpenID       string `json:"openid"`
    Scope        string `json:"scope"`
    UnionID      string `json:"unionid"`
}

// WeixinUserInfo 微信用户信息
type WeixinUserInfo struct {
    OpenID     string   `json:"openid"`
    Nickname   string   `json:"nickname"`
    Sex        int      `json:"sex"`
    Province   string   `json:"province"`
    City       string   `json:"city"`
    Country    string   `json:"country"`
    HeadImgURL string   `json:"headimgurl"`
    UnionID    string   `json:"unionid"`
}

// WeixinErrorResponse 微信错误响应
type WeixinErrorResponse struct {
    ErrCode int    `json:"errcode"`
    ErrMsg  string `json:"errmsg"`
}

// WeixinLogin 微信登录处理结构体
type WeixinLogin struct {
    Config WeixinConfig
}

// NewWeixinLogin 创建微信登录实例
func NewWeixinLogin(config WeixinConfig) (*WeixinLogin, error) {
    if err := config.Validate(); err != nil {
        return nil, err
    }
    return &WeixinLogin{
        Config: config,
    }, nil
}

// GetAuthURL 获取微信授权URL
func (w *WeixinLogin) GetAuthURL(state string) string {
    return fmt.Sprintf(
        "https://open.weixin.qq.com/connect/qrconnect?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
        url.QueryEscape(w.Config.AppID),
        url.QueryEscape(w.Config.RedirectURL),
        url.QueryEscape(state),
    )
}

// HandleCallback 处理微信回调
func (w *WeixinLogin) HandleCallback(code string) (*WeixinLoginResponse, error) {
    if code == "" {
        return nil, ErrInvalidCode("授权码为空")
    }

    url := fmt.Sprintf(
        "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
        w.Config.AppID,
        w.Config.AppSecret,
        code,
    )
    return doRequest[WeixinLoginResponse](url)
}

// RefreshToken 刷新访问令牌
func (w *WeixinLogin) RefreshToken(refreshToken string) (*WeixinLoginResponse, error) {
    if refreshToken == "" {
        return nil, errors.New("refresh token is required")
    }

    url := fmt.Sprintf(
        "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=%s&grant_type=refresh_token&refresh_token=%s",
        w.Config.AppID,
        refreshToken,
    )
    return doRequest[WeixinLoginResponse](url)
}

// GetUserInfo 获取用户信息
func (w *WeixinLogin) GetUserInfo(accessToken, openID string) (*WeixinUserInfo, error) {
    if accessToken == "" || openID == "" {
        return nil, errors.New("access token and openid are required")
    }

    url := fmt.Sprintf(
        "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s",
        accessToken,
        openID,
    )
    return doRequest[WeixinUserInfo](url)
}

// ValidateAccessToken 验证访问令牌是否有效
func (w *WeixinLogin) ValidateAccessToken(accessToken, openID string) error {
    url := fmt.Sprintf(
        "https://api.weixin.qq.com/sns/auth?access_token=%s&openid=%s",
        accessToken,
        openID,
    )
    resp, err := doRequest[WeixinErrorResponse](url)
    if err != nil {
        return err
    }

    if resp.ErrCode != 0 {
        return fmt.Errorf("invalid access token: %s", resp.ErrMsg)
    }

    return nil
}

// doRequest 执行HTTP请求并处理响应
func doRequest[T any](url string) (*T, error) {
    log.Printf("Requesting WeChat API: %s", url)
    
    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrAPIRequest, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("%w: status code %d", ErrAPIRequest, resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %v", err)
    }

    // 检查是否包含错误响应
    if strings.Contains(string(body), "errcode") {
        var errResp WeixinErrorResponse
        if err := json.Unmarshal(body, &errResp); err != nil {
            return nil, fmt.Errorf("failed to parse error response: %v", err)
        }
        if errResp.ErrCode != 0 {
            return nil, fmt.Errorf("weixin api error: %d - %s", errResp.ErrCode, errResp.ErrMsg)
        }
    }

    var result T
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, fmt.Errorf("failed to parse response: %v", err)
    }

    return &result, nil
}
