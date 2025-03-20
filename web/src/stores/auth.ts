import { defineStore } from 'pinia'
import axios from 'axios'

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
  id: string
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
  password: string
  confirmPassword: string
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
    supportedProviders: [] as AuthProvider[]
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
        const response = await axios.get('/auth/providers')
        this.supportedProviders = response.data.providers || []
        return this.supportedProviders
      } catch (error: any) {
        console.error('获取支持的登录方式失败', error)
        return []
      } finally {
        this.loading = false
      }
    },
    
    async login(usernameOrEmail: string, password: string) {
      try {
        this.loading = true
        this.error = undefined
        
        // 这里应该调用实际的 API 端点
        const response = await axios.post('/auth/account/login', {
          username: usernameOrEmail, // 为了保持API兼容性，仍然使用username作为参数名称
          password
        })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.message || '登录失败，请重试'
        throw new Error(this.error || '登录失败，请重试')
      } finally {
        this.loading = false
      }
    },
    
    // async register(registerData: RegisterForm) {
    //   try {
    //     this.loading = true
    //     this.error = null
        
    //     // 这里应该调用实际的 API 端点
    //     const response = await axios.post('/auth/register', registerData)
        
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
        const response = await axios.post('/auth/account/register', {
          ...registerData,
          // email: '' // 传递空邮箱
        })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
      } catch (error: any) {
        this.error = error.response?.data?.message || '账号注册失败，请重试'
        throw new Error(this.error || '账号注册失败，请重试')
      } finally {
        this.loading = false
      }
    },
    
    async logout() {
      try {
        // 可选：调用登出 API
        await axios.post('/auth/logout')
      } catch (error) {
        console.error('登出时发生错误', error)
      } finally {
        // 无论 API 调用是否成功，都清除本地状态
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
        const response = await axios.get('/auth/user')
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
          // 检查是否配置了谷歌客户端ID
          if (!import.meta.env.VITE_GOOGLE_CLIENT_ID) {
            reject(new Error('未配置谷歌客户端ID'));
            return;
          }
          
          // 如果已经加载了谷歌API，直接解析
          if (window.google && window.google.accounts) {
            resolve();
            return;
          }
          
          // 创建一个回调函数，当谷歌库加载完成时调用
          window.onGoogleLibraryLoad = () => {
            resolve();
          };
          
          // 检查是否已经存在脚本
          const existingScript = document.querySelector('script[src*="accounts.google.com/gsi/client"]');
          if (existingScript) {
            // 脚本已存在但可能未加载完成，等待onload
            if (window.google && window.google.accounts) {
              resolve();
            }
            return;
          }
          
          // 加载谷歌库
          const script = document.createElement('script');
          script.src = 'https://accounts.google.com/gsi/client';
          script.async = true;
          script.defer = true;
          script.onload = () => {
            // 谷歌库加载完成时通过全局回调函数调用
            if (window.google && window.google.accounts) {
              resolve();
            }
          };
          script.onerror = () => {
            reject(new Error('加载谷歌登录SDK失败'));
          };
          document.head.appendChild(script);
        } catch (error) {
          reject(error);
        }
      });
    },
    
    // async handleGoogleLogin() {
    //   try {
    //     this.loading = true;
    //     this.error = null;
        
    //     // 检查是否配置了谷歌客户端ID
    //     if (!import.meta.env.VITE_GOOGLE_CLIENT_ID) {
    //       this.loading = false;
    //       this.error = '未配置谷歌客户端ID';
    //       throw new Error(this.error);
    //     }
        
    //     // 确保谷歌库已加载
    //     await this.initGoogleAuth();
        
    //     return new Promise((resolve, reject) => {
    //       // 如果没有加载谷歌库，拒绝Promise
    //       if (!window.google || !window.google.accounts || !window.google.accounts.id) {
    //         this.loading = false;
    //         this.error = '谷歌登录服务未加载';
    //         reject(new Error(this.error));
    //         return;
    //       }
          
    //       // 初始化谷歌登录
    //       window.google.accounts.id.initialize({
    //         client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
    //         callback: async (response: any) => {
    //           try {
    //             // 验证令牌
    //             if (!response || !response.credential) {
    //               this.loading = false;
    //               this.error = '谷歌登录失败：未获取到凭证';
    //               reject(new Error(this.error));
    //               return;
    //             }
                
    //             // 获取JWT令牌
    //             const credential = response.credential;
                
    //             // 将JWT令牌发送到后端验证
    //             const authResponse = await axios.post('/auth/google', {
    //               credential: credential
    //             });
                
    //             // 处理登录结果
    //             const { user, token } = authResponse.data;
                
    //             this.user = user;
    //             this.token = token;
    //             localStorage.setItem('token', token);
    //             axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
                
    //             this.loading = false;
    //             resolve(user);
    //           } catch (error: any) {
    //             this.loading = false;
    //             this.error = error.response?.data?.message || '谷歌登录处理失败';
    //             reject(new Error(this.error || ''));
    //           }
    //         },
    //         auto_select: false,
    //         cancel_on_tap_outside: true
    //       });
          
    //       // 显示谷歌登录提示
    //       window.google.accounts.id.prompt((notification: any) => {
    //         if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
    //           // 如果没有显示登录提示，可能是用户已经登录过或其他原因
    //           this.loading = false;
    //           this.error = '无法显示谷歌登录窗口，请检查浏览器设置或尝试其他登录方式';
    //           reject(new Error(this.error));
    //         }
    //       });
    //     });
    //   } catch (error: any) {
    //     this.loading = false;
    //     this.error = error.message || '谷歌登录初始化失败';
    //     throw new Error(this.error || '');
    //   }
    // },
    
    // 创建谷歌登录按钮
    renderGoogleButton(elementId: string) {
      // 检查是否配置了谷歌客户端ID
      if (!import.meta.env.VITE_GOOGLE_CLIENT_ID) {
        console.error('未配置谷歌客户端ID');
        this.error = '谷歌登录配置不完整';
        return;
      }
      
      this.initGoogleAuth().then(() => {
        const buttonElement = document.getElementById(elementId);
        if (buttonElement && window.google && window.google.accounts && window.google.accounts.id) {
          // 先初始化谷歌登录
          window.google.accounts.id.initialize({
            client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
            callback: async (response: any) => {
              try {
                if (!response || !response.credential) {
                  this.error = '谷歌登录失败：未获取到凭证';
                  return;
                }
                
                // 获取JWT令牌并发送到后端验证
                const credential = response.credential;
                const authResponse = await axios.post('/auth/google', {
                  credential: credential
                });
                
                // 处理登录结果
                const { user, token } = authResponse.data;
                this.user = user;
                this.token = token;
                localStorage.setItem('token', token);
                axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
              } catch (error: any) {
                this.error = error.response?.data?.message || '谷歌登录处理失败';
                console.error('谷歌登录处理失败', error);
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
            locale: 'zh_CN'
          });
          
          console.log('谷歌登录按钮已渲染');
        }
      }).catch(error => {
        console.error('渲染谷歌登录按钮失败', error);
        this.error = '加载谷歌登录服务失败';
      });
    },
    
    // 微信登录相关方法
    async getWechatAuthUrl() {
      try {
        const response = await axios.get('/auth/weixin/url')
        return response.data.url
      } catch (error: any) {
        this.error = error.response?.data?.message || '获取微信登录链接失败'
        throw new Error(this.error || '获取微信登录链接失败')
      }
    },
    
    async handleWechatLogin(code: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/auth/weixin', { code })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        localStorage.setItem('token', token)
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.message || '微信登录失败'
        throw new Error(this.error || '微信登录失败')
      } finally {
        this.loading = false
      }
    },
    
    // 发送手机验证码
    async sendPhoneVerificationCode(phone: string) {
      try {
        this.loading = true
        this.error = undefined
        
        const response = await axios.post('/auth/phone/send-code', { phone })
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || '发送验证码失败，请重试'
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
        
        const response = await axios.post('/auth/phone/login', {
          phone,
          password
        })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.error || '手机号登录失败，请重试'
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
        
        const response = await axios.post('/auth/phone/code-login', {
          phone,
          code
        })
        
        const { user, token } = response.data
        
        this.user = user
        this.token = token
        
        // 保存 token 到本地存储
        localStorage.setItem('token', token)
        
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        
        return user
      } catch (error: any) {
        this.error = error.response?.data?.error || '验证码登录失败，请重试'
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
        
        const response = await axios.post('/auth/phone/register', registerData)
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || '手机号注册失败，请重试'
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
        
        const response = await axios.post('/auth/phone/verify', { code })
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || '手机号验证失败，请重试'
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
        
        const response = await axios.post('/auth/phone/reset-password-init', { phone })
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || '发起密码重置失败，请重试'
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
        
        const response = await axios.post('/auth/phone/reset-password', {
          phone,
          code,
          new_password: newPassword
        })
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.error || '重置密码失败，请重试'
        throw new Error(this.error)
      } finally {
        this.loading = false
      }
    },
  }
}) 