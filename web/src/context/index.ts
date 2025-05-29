/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */


import { serverApi } from '@/api/serverApi'
import type { AuthProvider } from '@/api/serverApi'



export class Context {

    private loading: boolean = false
    private supportedProviders: AuthProvider[] = []



    // Getters
    get isAuthenticated(): boolean {
        return !!localStorage.getItem('token')
    }

    get isLoading(): boolean {
        return this.loading
    }

    hasProvider(provider: AuthProvider): boolean {
        return this.supportedProviders.includes(provider)
    }

    // 获取支持的登录方式
    async fetchSupportedProviders() {
        try {
            this.loading = true
            const data = await serverApi.fetchSupportedProviders()
            this.supportedProviders = data.providers
            return data
        } catch (error) {
            console.error('Failed to get providers:', error)
            throw error
        } finally {
            this.loading = false
        }
    }
}

export const context = new Context()