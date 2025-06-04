/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import { getStoredUserInfo, isAuthenticated } from "@/utils"


class Context {

  loading: boolean = false

  error: string = ''

  get isAuthenticated(): boolean {
    return isAuthenticated()
  }

  get username(): string {
    return getStoredUserInfo()?.username || ''
  }

  get roles(): string[] {
    return getStoredUserInfo()?.roles || []
  }
  
  

}

export const context = new Context()