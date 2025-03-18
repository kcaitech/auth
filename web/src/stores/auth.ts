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
  username: string
  email: string
}

interface RegisterForm {
  username: string
  email: string
  password: string
  confirmPassword: string
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null as User | null,
    token: localStorage.getItem('token') || '',
    loading: false,
    error: null as string | null
  }),
  
  getters: {
    isAuthenticated: (state) => !!state.token,
    currentUser: (state) => state.user
  },
  
  actions: {
    async login(username: string, password: string) {
      try {
        this.loading = true
        this.error = null
        
        // 这里应该调用实际的 API 端点
        const response = await axios.post('/auth/login', {
          username,
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
    
    async register(registerData: RegisterForm) {
      try {
        this.loading = true
        this.error = null
        
        // 这里应该调用实际的 API 端点
        const response = await axios.post('/auth/register', registerData)
        
        return response.data
      } catch (error: any) {
        this.error = error.response?.data?.message || '注册失败，请重试'
        throw new Error(this.error || '注册失败，请重试')
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
        const response = await axios.get('/auth/me')
        this.user = response.data
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
          script.onerror = (error) => {
            reject(new Error('加载谷歌登录SDK失败'));
          };
          document.head.appendChild(script);
        } catch (error) {
          reject(error);
        }
      });
    },
    
    async handleGoogleLogin() {
      try {
        this.loading = true;
        this.error = null;
        
        // 确保谷歌库已加载
        await this.initGoogleAuth();
        
        return new Promise((resolve, reject) => {
          // 如果没有加载谷歌库，拒绝Promise
          if (!window.google || !window.google.accounts || !window.google.accounts.id) {
            this.loading = false;
            this.error = '谷歌登录服务未加载';
            reject(new Error(this.error));
            return;
          }
          
          // 初始化谷歌登录
          window.google.accounts.id.initialize({
            client_id: '你的谷歌客户端ID.apps.googleusercontent.com',
            callback: async (response: any) => {
              try {
                // 验证令牌
                if (!response || !response.credential) {
                  this.loading = false;
                  this.error = '谷歌登录失败：未获取到凭证';
                  reject(new Error(this.error));
                  return;
                }
                
                // 获取JWT令牌
                const credential = response.credential;
                
                // 将JWT令牌发送到后端验证
                const authResponse = await axios.post('/auth/google', {
                  credential: credential
                });
                
                // 处理登录结果
                const { user, token } = authResponse.data;
                
                this.user = user;
                this.token = token;
                localStorage.setItem('token', token);
                axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
                
                this.loading = false;
                resolve(user);
              } catch (error: any) {
                this.loading = false;
                this.error = error.response?.data?.message || '谷歌登录处理失败';
                reject(new Error(this.error || ''));
              }
            },
            auto_select: false,
            cancel_on_tap_outside: true
          });
          
          // 显示谷歌登录提示
          window.google.accounts.id.prompt((notification: any) => {
            if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
              // 如果没有显示登录提示，可能是用户已经登录过或其他原因
              this.loading = false;
              this.error = '无法显示谷歌登录窗口，请检查浏览器设置或尝试其他登录方式';
              reject(new Error(this.error));
            }
          });
        });
      } catch (error: any) {
        this.loading = false;
        this.error = error.message || '谷歌登录初始化失败';
        throw new Error(this.error || '');
      }
    },
    
    // 创建谷歌登录按钮
    renderGoogleButton(elementId: string) {
      this.initGoogleAuth().then(() => {
        const buttonElement = document.getElementById(elementId);
        if (buttonElement && window.google && window.google.accounts && window.google.accounts.id) {
          window.google.accounts.id.renderButton(buttonElement, {
            type: 'standard',
            theme: 'outline',
            size: 'large',
            text: 'signin_with',
            shape: 'rectangular',
            logo_alignment: 'left',
            locale: 'zh_CN'
          });
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
        this.error = null
        
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
    }
  }
}) 