package config

// 使用 -ldflags "-X 'kcaitech.com/kcauth/server/config.API_ROUTER_PATH=/api'" 来设置
const (
	UserCountLimit    = 0 // 用户数量限制, 0表示不限制
	API_ROUTER_PATH   = "/api"
	ADMIN_ROUTER_PATH = "/api"
)

func defaultConfig(config *Config) {

}
