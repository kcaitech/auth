<template>
  <div class="app-container">
    <router-view />
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue'

export default defineComponent({
  name: 'App'
})
</script>

<style lang="scss">
html, body {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
}

#app, .app-container {
  height: 100vh;
  width: 100%;
}

* {
  box-sizing: border-box;
}
</style> 