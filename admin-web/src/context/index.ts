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