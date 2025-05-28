/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import axios from 'axios'

// API响应类型定义
interface AuthResponse {
    user_id: string
    token: string
    nickname: string
    avatar: string
}

export type AuthProvider = 'account' | 'email' | 'google' | 'weixin' | 'phone'


// 响应拦截器：处理重定向响应
// axios.interceptors.response.use(
//     (response) => {
//         return response
//     },
//     (error) => {
//         // 处理307重定向或其他重定向状态码
//         if (error.response && [301, 302, 307, 308].includes(error.response.status)) {
//             const redirectUrl = error.response.headers.location
//             if (redirectUrl) {
//                 // 如果是登录重定向，直接跳转到新地址
//                 window.location.href = redirectUrl
//                 return Promise.resolve({ redirected: true, url: redirectUrl })
//             }
//         }
//         return Promise.reject(error)
//     }
// )

class ServerApi {

    clientId: string = ''
    redirectUri: string = ''

    updateUserInfo(response: AuthResponse) {
        const { user_id, token, nickname, avatar } = response
    
        // 保存信息到本地存储
        localStorage.setItem('token', token)
        localStorage.setItem('avatar', avatar)
        localStorage.setItem('nickname', nickname)
        localStorage.setItem('userId', user_id)
    
        // 设置 axios 默认 headers
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`

        this.handleLoginRedirect() // 重定向到应用
    }

    updateAuthData(clientId: string, redirectUri?: string) {
        serverApi.clientId = clientId
        if (redirectUri) {
            serverApi.redirectUri = redirectUri
            sessionStorage.setItem(clientId, redirectUri)
        } else {
            serverApi.redirectUri = sessionStorage.getItem(clientId) || ''
        }
    }

    async refreshToken() {
        const response = await axios.post('/token/refresh', { client_id: this.clientId, redirect_uri: this.redirectUri })
        const token = response.data.token
        const expireTime = response.data.expire_time
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
        localStorage.setItem('token', token)
        return { token, expireTime }
    }

    // 获取支持的登录方式
    async fetchSupportedProviders(): Promise<{ providers: AuthProvider[] }> {
        const response = await axios.get('/providers')
        return response.data
    }

    // 账号密码登录
    async login(username: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/account/login', { username, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 账号注册
    async registerAccount(username: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/account/register', { username, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 获取当前用户信息
    async fetchCurrentUser() {
        const response = await axios.get('/user')
        return response.data.user
    }

    // 登出
    async logout() {
        localStorage.removeItem('token')
        localStorage.removeItem('avatar')
        localStorage.removeItem('nickname')
        localStorage.removeItem('userId')
        return axios.post('/logout')
    }

    // Google相关
    async getGoogleClientId() {
        const response = await axios.get('/google/client_id')
        return response.data.client_id
    }

    async handleGoogleCallback(credential: string): Promise<AuthResponse> {
        const response = await axios.post('/google/callback', { credential, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 微信相关
    async getWechatAuthUrl(): Promise<string> {
        const response = await axios.get('/weixin/url')
        return response.data.url
    }

    async handleWeixinCallback(code: string, state: string): Promise<AuthResponse> {
        const response = await axios.get('/weixin/callback', { params: { code, state, client_id: this.clientId, redirect_uri: this.redirectUri } })
        this.updateUserInfo(response.data)
        return response.data
    }

    // 当前已经登陆，直接回调
    async handleLoginRedirect(): Promise<void> {
        const response = await axios.get('/login/redirect', { params: { client_id: this.clientId, redirect_uri: this.redirectUri } })
        const url = response.data.url as string
        if (url) {
            window.location.href = url
        }
        // return response.data
    }

    // 手机相关
    async sendPhoneVerificationCode(phone: string) {
        const response = await axios.post('/phone/send-code', { phone })
        return response.data
    }

    async phoneLogin(phone: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/phone/login', { phone, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    async phoneCodeLogin(phone: string, code: string): Promise<AuthResponse> {
        const response = await axios.post('/phone/code-login', { phone, code, client_id: this.clientId, redirect_uri: this.redirectUri })
        this.updateUserInfo(response.data)
        return response.data
    }

    async registerPhone(phone: string, code: string, password: string, nickname: string): Promise<AuthResponse> {
        const response = await axios.post('/phone/register', { phone, code, password, nickname })
        this.updateUserInfo(response.data)
        return response.data
    }

    async verifyPhone(code: string) {
        const response = await axios.post('/phone/verify', { code, client_id: this.clientId, redirect_uri: this.redirectUri })
        return response.data
    }

    async initiatePhonePasswordReset(phone: string) {
        const response = await axios.post('/phone/reset-password-init', { phone })
        return response.data
    }

    async completePhonePasswordReset(phone: string, code: string, newPassword: string) {
        const response = await axios.post('/phone/reset-password', {
            phone,
            code,
            new_password: newPassword
        })
        return response.data
    }

    // 邮箱相关
    async emailLogin(email: string, password: string): Promise<AuthResponse> {
        const response = await axios.post('/email/login', { email, password, client_id: this.clientId, redirect_uri: this.redirectUri })
        return response.data
    }
}

export const serverApi = new ServerApi() 