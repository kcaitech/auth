<template>
  <div class="google-login-container">
    <div id="google-signin-button" class="google-btn-container"></div>
  </div>
</template>

<script lang="ts" setup>
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { serverApi } from '@/api/serverApi'
import router from '@/router'


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

interface GoogleResponse {
  credential: string;
}

const emit = defineEmits<{
  (e: 'login-error', message: string): void
}>()

const { t } = useI18n()

// Google SDK 初始化
const initGoogleAuth = async (): Promise<void> => {
  if (window.google?.accounts) {
    return
  }

  return new Promise((resolve, reject) => {
    try {
      window.onGoogleLibraryLoad = () => resolve()

      const existingScript = document.querySelector('script[src*="accounts.google.com/gsi/client"]')
      if (existingScript) {
        if (window.google?.accounts) {
          resolve()
        }
        return
      }

      const script = document.createElement('script')
      script.src = 'https://accounts.google.com/gsi/client'
      script.async = true
      script.defer = true
      script.onload = () => window.google?.accounts && resolve()
      script.onerror = () => reject(new Error(t('errors.googleSdkLoadFailed')))
      document.head.appendChild(script)
    } catch (error) {
      reject(error)
    }
  })
}

// 处理 Google 登录回调
const handleGoogleCallback = async (credential: string) => {
  try {
    const data = await serverApi.handleGoogleCallback(credential)
    if (!data) {
      router.push('/login')
      return
    }
    // TODO: 处理登录成功后的用户信息更新
  } catch (error) {
    console.error(t('errors.googleLoginProcessFailed'), error)
    emit('login-error', t('errors.googleLoginProcessFailed'))
  }
}

// 渲染 Google 登录按钮
const renderGoogleButton = async (elementId: string): Promise<void> => {
  try {
    const clientID = await serverApi.getGoogleClientId()
    await initGoogleAuth()

    const buttonElement = document.getElementById(elementId)
    if (!buttonElement || !window.google?.accounts?.id) {
      throw new Error(t('errors.googleServiceLoadFailed'))
    }

    window.google.accounts.id.initialize({
      client_id: clientID,
      callback: async (response: GoogleResponse) => {
        if (!response?.credential) {
          emit('login-error', t('errors.googleCredentialMissing'))
          return
        }
        await handleGoogleCallback(response.credential)
      },
      auto_select: false,
      cancel_on_tap_outside: true
    })

    window.google.accounts.id.renderButton(buttonElement, {
      type: 'standard',
      theme: 'outline',
      size: 'large',
      text: 'signin_with',
      shape: 'rectangular',
      logo_alignment: 'center',
    })

    console.log(t('logs.googleButtonRendered'))
  } catch (error) {
    console.error(t('errors.renderGoogleButtonFailed'), error)
    emit('login-error', t('errors.googleServiceLoadFailed'))
  }
}

onMounted(async () => {
  try {
    await renderGoogleButton('google-signin-button')
    console.log(t('logs.googleInitComplete'))
  } catch (error) {
    console.error(t('logs.googleInitFailed'), error)
    emit('login-error', t('errors.googleLoginFailed'))
  }
})
</script>

<style scoped>
.google-login-container {
  width: 100%;
}

.google-btn-container {
  width: 100%;
  height: 44px;
  border-radius: 8px;
  overflow: hidden;
  box-sizing: border-box;
  display: flex;
  justify-content: center;
  align-items: center;
}

:deep(.google-btn-container iframe) {
  width: 100% !important;
}

:deep(.google-btn-container > div) {
  width: 100% !important;
}

@media screen and (max-width: 450px) {
  .google-btn-container {
    transform: scale(0.95);
    transform-origin: center;
  }
}
</style> 