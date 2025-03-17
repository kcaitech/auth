<template>
  <div class="not-found">
    <h1>404</h1>
    <h2>页面未找到</h2>
    <p>抱歉，您访问的页面不存在。</p>
    <router-link to="/" class="home-link">返回首页</router-link>
  </div>
</template>

<style scoped>
.not-found {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 70vh;
  text-align: center;
}

h1 {
  font-size: 72px;
  color: #1890ff;
  margin-bottom: 0;
}

h2 {
  font-size: 24px;
  color: #303133;
  margin: 16px 0;
}

p {
  color: #606266;
  margin-bottom: 24px;
}

.home-link {
  display: inline-block;
  padding: 10px 20px;
  background-color: #1890ff;
  color: white;
  text-decoration: none;
  border-radius: 4px;
  transition: background-color 0.3s;
}

.home-link:hover {
  background-color: #40a9ff;
}
</style> 