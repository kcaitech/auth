import { defineStore } from 'pinia'
import axios from 'axios'
import i18n from "@/locales"


const t = i18n.global.t

// 扩展Window接口以包含谷歌API
declare global {
  interface Window {
    google: {
      accounts: {
        id: {
          initialize: (config: any) => any;
          renderButton: (element: HTMLElement, options: any) => void;
          prompt: (momentListener?: any) => void;
          disableAutoSelect: () => void;
          storeCredential: (credential: any, callback: () => void) => void;
          cancel: () => void;
        };
        oauth2: {
          initTokenClient: (config: any) => any;
          initCodeClient: (config: any) => any;
        }
      }
    };
    handleGoogleToken: (response: any) => void;
    onGoogleLibraryLoad: () => void;
  }
}

interface User {
  // id: string
  userID: string
  nickname: string
  email: string
}

// interface RegisterForm {
//   userID: string
//   nickname: string
//   email: string
//   password: string
//   confirmPassword: string
// }

interface AccountRegisterForm {
  username: string
  // nickname: string
  password: string
  confirmPassword: string
}

// 登录提供者
export type AuthProvider = 'account' | 'email' | 'google' | 'weixin' | 'phone'

// 手机注册表单
interface PhoneRegisterForm {
  phone: string
  code: string
  password: string
  nickname: string
}

// 手机验证码登录表单
// interface PhoneCodeLoginForm {
//   phone: string
//   code: string
// }

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null as User | null,
    token: localStorage.getItem('token') || '',
    loading: false,
    error: undefined as string | undefined,
    supportedProviders: [] as AuthProvider[],
  }),
  
  getters: {
    isAuthenticated: (state) => !!state.token,
    currentUser: (state) => state.user,
    hasProvider: (state) => (provider: AuthProvider) => state.supportedProviders.includes(provider)
  },
  
  actions: {
    // 获取后端支持的登录方式
    async fetchSupportedProviders() {
      try {
        this.loading = true
        const response = await axios.get('/providers')
        this.supportedProviders = response.data.providers || []
        return this.supportedProviders
      } catch (error: any) {
        console.error(t('errors.fetchProvidersFailed'), error)
        return []
      } finally {
        this.loading = false
      }
    },
    
    async login(username: string, password: string) {
      try {
        this.loading = true
        this.error = undefined
        
        // 这里应该调用实际的 API 端点
        const response = await axios.post('/account/login', {
          username: username,
          password
        })
        
        const { user_id, token, profile, expire_time } = response.data
        
        this.user = {
          // id: user_id,
          userID: user_id,
          nickname: profile?.nickname || '',
          email: profile?.email || ''
        }
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return this.user
      } catch (error: any) {
        this.error = error.response?.data?.message || t('errors.loginFailed')
        throw new Error(this.error || t('errors.loginFailed'))
      } finally {
        this.loading = false
      }
    },
    
    // async register(registerData: RegisterForm) {
    //   try {
    //     this.loading = true
    //     this.error = null
        
    //     // 这里应该调用实际的 API 端点
    //     const response = await axios.post('/register', registerData)
        
    //     return response.data
    //   } catch (error: any) {
    //     this.error = error.response?.data?.message || '注册失败，请重试'
    //     throw new Error(this.error || '注册失败，请重试')
    //   } finally {
    //     this.loading = false
    //   }
    // },
    
    async registerAccount(registerData: AccountRegisterForm) {
      try {
        this.loading = true
        this.error = undefined
        
        // 使用账号注册API
        const response = await axios.post('/account/register', {
          ...registerData,
        })
        
        const { user_id, token, profile, expire_time } = response.data
        
        this.user = {
          // id: user_id,
          userID: user_id,
          nickname: profile?.nickname || '',
          email: profile?.email || ''
        }
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        return this.user
      } catch (error: any) {
        this.error = error.response?.data?.message || t('errors.registerFailed')
        throw new Error(this.error || t('errors.registerFailed'))
      } finally {
        this.loading = false
      }
    },
    
    async logout() {
      try {
        // 可选：调用登出 API
        await axios.post('/logout')
      } catch (error) {
        console.error(t('errors.logoutFailed'), error)
      } finally {
        this.user = null
        this.token = ''
        localStorage.removeItem('token')
        delete axios.defaults.headers.common['Authorization']
      }
    },
    
    async fetchCurrentUser() {
      try {
        if (!this.token) return null
        
        this.loading = true
        const response = await axios.get('/user')
        this.user = response.data.user
        return this.user
      } catch (error) {
        this.logout()
        return null
      } finally {
        this.loading = false
      }
    },
    
    // Google 登录相关方法
    async initGoogleAuth() {
      return new Promise<void>((resolve, reject) => {
        try {
          // 如果已经加载了谷歌API，直接解析
          if (window.google && window.google.accounts) {
            resolve()
            return
          }
          
          // 创建一个回调函数，当谷歌库加载完成时调用
          window.onGoogleLibraryLoad = () => {
            resolve()
          }
          
          // 检查是否已经存在脚本
          const existingScript = document.querySelector('script[src*="accounts.google.com/gsi/client"]');
          if (existingScript) {
            // 脚本已存在但可能未加载完成，等待onload
            if (window.google && window.google.accounts) {
              resolve()
            }
            return
          }
          
          const script = document.createElement('script')
          script.src = 'https://accounts.google.com/gsi/client'
          script.async = true
          script.defer = true
          script.onload = () => {
            if (window.google && window.google.accounts) {
              resolve()
            }
          }
          script.onerror = () => {
            reject(new Error(t('errors.googleSdkLoadFailed')))
          }
          document.head.appendChild(script)
        } catch (error) {
          reject(error)
        }
      })
    },

    // 创建谷歌登录按钮
    async renderGoogleButton(elementId: string, loginSuccessCallback: () => void) {
      // 检查是否配置了谷歌客户端ID
      const response = await axios.get('/google/client_id')
      const clientID = response.data.client_id
      
      this.initGoogleAuth().then(() => {
        const buttonElement = document.getElementById(elementId);
        if (buttonElement && window.google && window.google.accounts && window.google.accounts.id) {
          // 先初始化谷歌登录
          window.google.accounts.id.initialize({
            client_id: clientID,
            callback: async (response: any) => {
              try {
                if (!response || !response.credential) {
                  this.error = t('errors.googleCredentialMissing');
                  return;
                }
                
                // 获取JWT令牌并发送到后端验证
                const credential = response.credential;
                const authResponse = await axios.post('/google/credential', {
                  credential: credential
                });
                
                // 处理登录结果
                const { user_id, token, profile, expire_time } = authResponse.data
        
                this.user = {
                  // id: user_id,
                  userID: user_id,
                  nickname: profile?.nickname || '',
                  email: profile?.email || ''
                }
                this.token = token;
                localStorage.setItem('token', token);
                axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

                loginSuccessCallback()
              } catch (error: any) {
                this.error = error.response?.data?.message || t('errors.googleLoginProcessFailed');
                console.error(t('errors.googleLoginProcessFailed'), error);
              }
            },
            auto_select: false,
            cancel_on_tap_outside: true
          });
          
          // 然后渲染按钮
          window.google.accounts.id.renderButton(buttonElement, {
            type: 'standard',
            theme: 'outline',
            size: 'large',
            text: 'signin_with',
            shape: 'rectangular',
            logo_alignment: 'center',
            // locale: getPreferredLanguage()
          });
          
          console.log(t('logs.googleButtonRendered'));
        }
      }).catch(error => {
        console.error(t('errors.renderGoogleButtonFailed'), error);
        this.error = t('errors.googleServiceLoadFailed');
      });
    },
    
    // 微信登录相关方法
    async getWechatAuthUrl() {
      try {
        const response = await axios.get('/weixin/url')
        return response.data.url
      } catch (error: any) {
        this.error = error.response?.data?.message || t('errors.wechatUrlFetchFailed')
        throw new Error(this.error || t('errors.wechatUrlFetchFailed'))
      }
    },
    
    async handleWechatLogin(code: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/weixin', { code })
        
        const { user_id, token, profile, expire_time } = response.data
        
        this.user = {
          // id: user_id,
          userID: user_id,
          nickname: profile?.nickname || '',
          email: profile?.email || ''
        }

        this.token = token
        localStorage.setItem('token', token)
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return this.user
      } catch (error: any) {
        this.error = error.response?.data?.message || t('errors.wechatLoginFailed')
        throw new Error(this.error || t('errors.wechatLoginFailed'))
      } finally {
        this.loading = false
      }
    },
    
    // 发送手机验证码
    async sendPhoneVerificationCode(phone: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/send-code', { phone })
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.codeSendFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
    
    // 手机号密码登录
    async phoneLogin(phone: string, password: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/login', {
          phone,
          password
        })
        
        const { user_id, token, profile, expire_time } = response.data
        
        this.user = {
          // id: user_id,
          userID: user_id,
          nickname: profile?.nickname || '',
          email: profile?.email || ''
        }
        
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return this.user
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.phoneLoginFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
    
    // 手机验证码登录
    async phoneCodeLogin(phone: string, code: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/code-login', {
          phone,
          code
        })
        
        const { user_id, token, profile, expire_time } = response.data
        
        this.user = {
          // id: user_id,
          userID: user_id,
          nickname: profile?.nickname || '',
          email: profile?.email || ''
        }
        
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return this.user
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.phoneCodeLoginFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
    
    // 手机号注册
    async registerPhone(registerData: PhoneRegisterForm) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/register', registerData)
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.phoneRegisterFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
    
    // 验证手机号
    async verifyPhone(code: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/verify', { code })
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.phoneVerificationFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
    
    // 手机号重置密码初始化
    async initiatePhonePasswordReset(phone: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/reset-password-init', { phone })
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.passwordResetInitFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
    
    // 完成手机号密码重置
    async completePhonePasswordReset(phone: string, code: string, newPassword: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/phone/reset-password', {
          phone,
          code,
          new_password: newPassword
        })
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.passwordResetFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },

    // 邮箱登录
    async emailLogin(email: string, password: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/email/login', {
          email,
          password
        })

        const { user_id, token, profile, expire_time } = response.data
        
        this.user = {
          // id: user_id,
          userID: user_id,
          nickname: profile?.nickname || '',
          email: profile?.email || ''
        }

        this.token = token
        localStorage.setItem('token', token)
        
        return this.user
      } catch (error: any) {
        this.error = error.response?.data?.error || t('errors.emailLoginFailed')
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
  }
}) 