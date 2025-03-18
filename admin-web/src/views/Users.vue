<template>
  <div class="users-container">
    <el-card class="users-card">
      <template #header>
        <div class="card-header">
          <h2>用户管理</h2>
        </div>
      </template>
      
      <!-- 筛选条件 -->
      <div class="filter-container">
        <el-form :model="filter" label-width="80px" :inline="true" size="small">
          <el-form-item label="状态">
            <el-select v-model="filter.status" placeholder="选择状态" clearable>
              <el-option label="活跃" value="active" />
              <el-option label="未激活" value="inactive" />
              <el-option label="锁定" value="locked" />
              <el-option label="封禁" value="banned" />
            </el-select>
          </el-form-item>
          
          <el-form-item label="提供商">
            <el-select v-model="filter.provider" placeholder="选择提供商" clearable>
              <el-option label="本地账号" value="local" />
              <el-option label="Google" value="google" />
              <el-option label="微信" value="weixin" />
            </el-select>
          </el-form-item>
          
          <el-form-item label="验证状态">
            <el-select v-model="filter.verified" placeholder="验证状态" clearable>
              <el-option label="已验证" value="true" />
              <el-option label="未验证" value="false" />
            </el-select>
          </el-form-item>
          
          <el-form-item label="搜索">
            <el-input v-model="filter.search" placeholder="用户名/邮箱" clearable />
          </el-form-item>
          
          <el-form-item>
            <el-button type="primary" @click="handleFilter">筛选</el-button>
            <el-button @click="resetFilter">重置</el-button>
          </el-form-item>
        </el-form>
      </div>
      
      <!-- 用户表格 -->
      <el-table
        v-loading="loading"
        :data="users"
        style="width: 100%"
        border
        stripe
      >
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="username" label="用户名" />
        <el-table-column prop="email" label="邮箱" />
        
        <el-table-column prop="status" label="状态" width="100">
          <template #default="scope">
            <el-tag :type="getStatusType(scope.row.status)">
              {{ getStatusText(scope.row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        
        <el-table-column prop="provider" label="提供商" width="100">
          <template #default="scope">
            <el-tag type="info">
              {{ getProviderText(scope.row.provider) }}
            </el-tag>
          </template>
        </el-table-column>
        
        <el-table-column prop="verified" label="已验证" width="80">
          <template #default="scope">
            <el-tag :type="scope.row.verified ? 'success' : 'danger'" size="small">
              {{ scope.row.verified ? '是' : '否' }}
            </el-tag>
          </template>
        </el-table-column>
        
        <el-table-column prop="created_at" label="注册时间" width="180">
          <template #default="scope">
            {{ formatDate(scope.row.created_at) }}
          </template>
        </el-table-column>
        
        <el-table-column prop="last_login" label="最后登录" width="180">
          <template #default="scope">
            {{ scope.row.last_login ? formatDate(scope.row.last_login) : '未登录' }}
          </template>
        </el-table-column>
        
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="scope">
            <el-button size="small" type="primary" @click="viewUserDetail(scope.row)">
              查看
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      
      <!-- 分页 -->
      <div class="pagination-container">
        <el-pagination
          v-model:current-page="pagination.page"
          v-model:page-size="pagination.size"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          :total="pagination.total"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>
    
    <!-- 用户详情对话框 -->
    <el-dialog
      v-model="userDetailVisible"
      title="用户详情"
      width="80%"
      destroy-on-close
    >
      <UserDetail
        v-if="userDetailVisible && selectedUser"
        :user="selectedUser"
        @update:user="handleUserUpdated"
        @close="userDetailVisible = false"
      />
    </el-dialog>
  </div>
</template>

<script lang="ts">
import { defineComponent, reactive, ref, onMounted, computed } from 'vue'
import api, { User } from '@/api'
import { ElMessage } from 'element-plus'
import UserDetail from '@/components/UserDetail.vue'

export default defineComponent({
  name: 'UsersView',
  components: {
    UserDetail
  },
  setup() {
    // 用户列表数据
    const users = ref<User[]>([])
    const loading = ref(true)
    const error = ref('')
    
    // 筛选条件
    const filter = reactive({
      status: '',
      provider: '',
      verified: '',
      search: ''
    })
    
    // 分页信息
    const pagination = reactive({
      page: 1,
      size: 20,
      total: 0,
      totalPages: 0
    })
    
    // 用户详情
    const userDetailVisible = ref(false)
    const selectedUser = ref<User | null>(null)
    
    // 获取用户数据
    const fetchUsers = async () => {
      loading.value = true
      error.value = ''
      
      try {
        const params = {
          page: pagination.page,
          size: pagination.size,
          ...filter
        }
        
        const response = await api.getUsers(params)
        
        users.value = response.users
        pagination.total = response.total
        pagination.totalPages = response.total_page
      } catch (e: any) {
        error.value = e.response?.data?.error || '加载用户列表失败'
        ElMessage.error(error.value)
        console.error('获取用户列表失败', e)
      } finally {
        loading.value = false
      }
    }
    
    // 筛选处理
    const handleFilter = () => {
      pagination.page = 1
      fetchUsers()
    }
    
    // 重置筛选条件
    const resetFilter = () => {
      Object.keys(filter).forEach(key => {
        filter[key as keyof typeof filter] = ''
      })
      pagination.page = 1
      fetchUsers()
    }
    
    // 分页处理
    const handleSizeChange = (size: number) => {
      pagination.size = size
      pagination.page = 1
      fetchUsers()
    }
    
    const handleCurrentChange = (page: number) => {
      pagination.page = page
      fetchUsers()
    }
    
    // 查看用户详情
    const viewUserDetail = (user: User) => {
      selectedUser.value = user
      userDetailVisible.value = true
    }
    
    // 处理用户信息更新
    const handleUserUpdated = (updatedUser: User) => {
      // 更新用户列表中的用户信息
      const index = users.value.findIndex(u => u.id === updatedUser.id)
      if (index !== -1) {
        users.value[index] = updatedUser
      }
    }
    
    // 格式化日期
    const formatDate = (dateStr: string) => {
      return new Date(dateStr).toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      })
    }
    
    // 获取状态类型
    const getStatusType = (status: string) => {
      const map: Record<string, string> = {
        active: 'success',
        inactive: 'info',
        locked: 'warning',
        banned: 'danger'
      }
      return map[status] || 'info'
    }
    
    // 获取状态文本
    const getStatusText = (status: string) => {
      const map: Record<string, string> = {
        active: '活跃',
        inactive: '未激活',
        locked: '锁定',
        banned: '封禁'
      }
      return map[status] || status
    }
    
    // 获取提供商文本
    const getProviderText = (provider: string) => {
      const map: Record<string, string> = {
        local: '本地账号',
        google: 'Google',
        weixin: '微信'
      }
      return map[provider] || provider
    }
    
    // 组件挂载时获取数据
    onMounted(() => {
      fetchUsers()
    })
    
    return {
      users,
      loading,
      error,
      filter,
      pagination,
      fetchUsers,
      handleFilter,
      resetFilter,
      handleSizeChange,
      handleCurrentChange,
      viewUserDetail,
      formatDate,
      getStatusType,
      getStatusText,
      getProviderText,
      userDetailVisible,
      selectedUser,
      handleUserUpdated
    }
  }
})
</script>

<style lang="scss" scoped>
.users-container {
  .users-card {
    margin-bottom: 20px;
  }
  
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    
    h2 {
      margin: 0;
      font-size: 1.2rem;
      font-weight: 500;
    }
  }
  
  .filter-container {
    margin-bottom: 20px;
    padding: 16px;
    background-color: #f5f7fa;
    border-radius: 4px;
  }
  
  .pagination-container {
    margin-top: 20px;
    display: flex;
    justify-content: flex-end;
  }
}
</style> 