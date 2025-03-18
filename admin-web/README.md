# KC认证系统管理控制台

基于Vue 3 + TypeScript + Vite + Element Plus构建的管理后台前端项目。

## 功能特点

- 完全使用TypeScript开发
- 基于Composition API的组件设计
- 响应式布局，适配不同屏幕尺寸
- 专业的数据可视化展示
- 完整的用户管理功能
- 详细的活跃度分析

## 技术栈

- Vue 3
- TypeScript
- Vite
- Vue Router
- Pinia (状态管理)
- Element Plus (UI组件库)
- Chart.js (图表可视化)

## 项目结构

```
admin-web/
├── public/            # 静态资源
├── src/
│   ├── api/           # API接口
│   ├── assets/        # 资源文件
│   ├── components/    # 公共组件
│   ├── router/        # 路由配置
│   ├── store/         # 状态管理
│   ├── utils/         # 工具函数
│   ├── views/         # 页面组件
│   ├── App.vue        # 根组件
│   └── main.ts        # 入口文件
├── index.html         # HTML模板
├── tsconfig.json      # TypeScript配置
├── vite.config.ts     # Vite配置
└── package.json       # 项目依赖
```

## 开发指南

### 安装依赖

```bash
cd server/admin-web
npm install
```

### 启动开发服务器

```bash
npm run dev
```

### 构建生产版本

```bash
npm run build
```

构建后的文件将输出到 `../admin/assets/dist` 目录中，可直接被后端服务使用。

## 后端API集成

管理控制台通过以下API与后端进行通信：

- `/login` - 管理员登录
- `/api/stats` - 获取用户统计数据
- `/api/users` - 获取用户列表
- `/api/activity` - 获取用户活跃数据
- `/api/logout` - 管理员注销

所有API请求都会自动包含cookie凭证，以确保会话持续性。 