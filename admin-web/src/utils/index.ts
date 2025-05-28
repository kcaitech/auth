/*
 * Copyright (c) 2023-2024 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import { UserInfo } from "@/api"

/**
 * 检查用户是否已认证（通过localStorage）
 */
export function isAuthenticated(): boolean {
    const storedUser = localStorage.getItem('admin_session')
    return !!storedUser
  }
  
  /**
   * 获取存储的用户信息
   */
  export function getStoredUserInfo(): UserInfo | null {
    const storedUser = localStorage.getItem('admin_session')
    if (storedUser) {
      try {
        return JSON.parse(storedUser)
      } catch (e) {
        localStorage.removeItem('admin_session')
        return null
      }
    }
    return null
  }