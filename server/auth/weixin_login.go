package auth

// 微信登录

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
)

// WeixinConfig 微信登录配置
type WeixinConfig struct {
    AppID     string
    AppSecret string
    RedirectURL string
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

// WeixinLogin 微信登录处理结构体
type WeixinLogin struct {
    Config WeixinConfig
}

// NewWeixinLogin 创建微信登录实例
func NewWeixinLogin(config WeixinConfig) *WeixinLogin {
    return &WeixinLogin{
        Config: config,
    }
}

// GetAuthURL 获取微信授权URL
func (w *WeixinLogin) GetAuthURL(state string) string {
    return fmt.Sprintf(
        "https://open.weixin.qq.com/connect/qrconnect?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
        w.Config.AppID,
        w.Config.RedirectURL,
        state,
    )
}

// HandleCallback 处理微信回调
func (w *WeixinLogin) HandleCallback(code string) (*WeixinLoginResponse, error) {
    url := fmt.Sprintf(
        "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
        w.Config.AppID,
        w.Config.AppSecret,
        code,
    )

    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("failed to get access token: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %v", err)
    }

    var loginResp WeixinLoginResponse
    if err := json.Unmarshal(body, &loginResp); err != nil {
        return nil, fmt.Errorf("failed to parse response: %v", err)
    }

    return &loginResp, nil
}

// GetUserInfo 获取用户信息
func (w *WeixinLogin) GetUserInfo(accessToken, openID string) (*WeixinUserInfo, error) {
    url := fmt.Sprintf(
        "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s",
        accessToken,
        openID,
    )

    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("failed to get user info: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %v", err)
    }

    var userInfo WeixinUserInfo
    if err := json.Unmarshal(body, &userInfo); err != nil {
        return nil, fmt.Errorf("failed to parse user info: %v", err)
    }

    return &userInfo, nil
}
