/* * Copyright (c) 2025 KCai Technology (https://kcaitech.com) * Licensed under
the MIT License. */

<template>
  <div class="failed">
    <button v-if="loginFailed" @click="againLogin">重新加载</button>
    <div v-else class="container">
      <div class="loading"></div>
      <div class="content">正在加载{{ isLoading }}</div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, defineEmits, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { serverApi } from "@/api/serverApi";
import { useRoute } from "vue-router";

const emit = defineEmits<{
  (e: "login-error", message: string): void;
  //   (e: 'login-success', data: any): void
}>();

const route = useRoute();
const { t } = useI18n();
const isLoading = ref(true);
const loginFailed = ref<boolean>(false);

const againLogin = () => {
  localStorage.clear();
  let miniprogram: any;
  miniprogram = navigator.userAgent.includes("miniProgram");
  if (miniprogram) {
    (window as any).wx.miniProgram.postMessage({
      data: {
        login: false,
      },
    });
    (window as any).wx.miniProgram.redirectTo({
      url: "/pages/index/index",
    });
  }
};

const handleWechatMiniLogin = async () => {
  try {
    
    const code = route.query.code as string;
    // 调用微信小程序登录
    if (!code) {
      throw new Error(t("errors.wechatMiniLoginFailed"));
    }

    

    // 调用后端登录接口
    const res = await serverApi.weixinMiniLogin(code);

    console.log(res,'res');
    
    // 触发登录成功事件
    // emit('login-success', res)
  } catch (error: any) {
    emit(
      "login-error",
      error.response?.data?.message || t("errors.wechatMiniLoginFailed")
    );
  } finally {
    isLoading.value = false;
  }
};

onMounted(() => {
  handleWechatMiniLogin();
});
</script>

<style scoped>
.failed {
  display: flex;
  width: 100%;
  height: 100%;
}

button {
  margin: auto;
  border: none;
  padding: 8px 12px;
  border-radius: 4px;
  color: white;
  font-size: 13px;
  background-color: rgba(24, 120, 245, 1);
}

.container {
  position: absolute;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}

.loading {
  border: 2px solid transparent;
  border-top: 2px solid blue;
  border-left: 2px solid blue;
  border-bottom: 2px solid blue;
  border-radius: 50%;
  width: 18px;
  height: 18px;
  color: #000;
  animation: spin 1s linear infinite;
}

.content {
  margin-left: 8px;
  font-size: 14px;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}
</style>
