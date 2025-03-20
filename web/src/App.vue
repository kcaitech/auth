<template>
  <div class="app-container">
    <router-view />
  </div>
</template>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

/* 防止滚动条出现导致页面抖动 */
html {
  overflow-y: scroll;
}

/* 自定义滚动条样式 */
::-webkit-scrollbar {
  width: 3px; /* 设置滚动条宽度 */
}

::-webkit-scrollbar-track {
  background: #f1f1f1; /* 滚动条轨道背景色 */
  border-radius: 2px;
}

::-webkit-scrollbar-thumb {
  background: #c1c1c1; /* 滚动条滑块颜色 */
  border-radius: 2px;
}

::-webkit-scrollbar-thumb:hover {
  background: #a8a8a8; /* 鼠标悬停时的颜色 */
}

body {
  font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
  background-color: #f5f7fa;
  min-height: 100vh;
}

.app-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}
</style> 