<template>
  <div class="users-container">
    <el-card class="users-card">
      <template #header>
        <div class="card-header">
          <h2>{{ $t('user.title') }}</h2>
        </div>
      </template>
      
      <!-- 筛选条件 -->
      <div class="filter-container">
        <el-form :model="filter" label-width="80px" :inline="true" size="small">
          <el-form-item :label="$t('user.status')">
            <el-select v-model="filter.status" :placeholder="$t('user.select_status')" clearable>
              <el-option :label="$t('user.status_active')" value="active" />
              <el-option :label="$t('user.status_inactive')" value="inactive" />
              <el-option :label="$t('user.status_locked')" value="locked" />
              <el-option :label="$t('user.status_banned')" value="banned" />
            </el-select>
          </el-form-item>
          
          <el-form-item :label="$t('user.search')">
            <el-input v-model="filter.search" :placeholder="$t('user.username_email')" clearable />
          </el-form-item>
          
          <el-form-item>
            <el-button type="primary" @click="handleFilter">{{ $t('user.filter') }}</el-button>
            <el-button @click="resetFilter">{{ $t('user.reset') }}</el-button>
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
        <el-table-column :label="$t('user.id')" width="80">
          <template #default="scope">
            {{ getUserId(scope.row) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('user.username')">
          <template #default="scope">
            {{ getUserName(scope.row) }}
          </template>
        </el-table-column>
        <!-- <el-table-column :label="$t('user.email')">
          <template #default="scope">
            {{ scope.row.email || $t('user.none') }}
          </template>
        </el-table-column> -->
        
        <el-table-column :label="$t('user.status')" width="100">
          <template #default="scope">
            <el-tag :type="getStatusType(getStatus(scope.row))">
              {{ getStatusText(getStatus(scope.row)) }}
            </el-tag>
          </template>
        </el-table-column>
        
        <!-- <el-table-column :label="$t('user.provider')" width="100">
          <template #default="scope">
            <el-tag type="info">
              {{ getProviderText(getProvider(scope.row)) }}
            </el-tag>
          </template>
        </el-table-column> -->
        
        <!-- <el-table-column :label="$t('user.is_verified')" width="80">
          <template #default="scope">
            <el-tag :type="isVerified(scope.row) ? 'success' : 'danger'" size="small">
              {{ isVerified(scope.row) ? $t('common.yes') : $t('common.no') }}
            </el-tag>
          </template>
        </el-table-column> -->
        
        <el-table-column :label="$t('user.registration_time')" width="180">
          <template #default="scope">
            {{ formatDate(getCreatedAt(scope.row)) || $t('user.none') }}
          </template>
        </el-table-column>
        
        <el-table-column :label="$t('user.last_login')" width="180">
          <template #default="scope">
            {{ getLastLogin(scope.row) ? formatDate(getLastLogin(scope.row) as string) : $t('user.never_logged_in') }}
          </template>
        </el-table-column>
        
        <el-table-column :label="$t('user.actions')" width="150" fixed="right">
          <template #default="scope">
            <div class="operation-buttons">
              <el-button size="small" type="primary" @click="viewUserDetail(scope.row)">
                {{ $t('user.view') }}
              </el-button>
              <el-button size="small" type="warning" @click="viewUserSessions(scope.row)">
                {{ $t('user.sessions') }}
              </el-button>
            </div>
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
      :title="$t('user.user_detail')"
      width="80%"
      destroy-on-close
    >
      <UserDetail
        v-if="userDetailVisible && selectedUser"
        :user="selectedUser"
        :initial-tab="sessionTabSelected ? 'sessions' : 'basic'"
        @update:user="handleUserUpdated"
        @close="userDetailVisible = false"
      />
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { User, serverApi as api } from '@/api/index'
import { ElMessage } from 'element-plus'
import UserDetail from '@/components/UserDetail.vue'
import i18n from '@/lang'

const { t } = i18n.global

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

// 用户会话管理对话框
const sessionTabSelected = ref(false)

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
    
    // 调试日志：查看返回的用户数据
    console.debug(t('user.debug_user_data'), response)
    
    // 确保 users 字段存在，否则尝试适配数据结构
    if (response.users) {
      users.value = response.users
    } else if (Array.isArray(response.data)) {
      // 可能服务器返回的是 data 字段
      users.value = response.data
      console.info(t('user.using_data_as_users'))
    } else if (Array.isArray(response.list)) {
      // 或者是 list 字段
      users.value = response.list
      console.info(t('user.using_list_as_users'))
    } else if (Array.isArray(response)) {
      // 或者直接是数组
      users.value = response
      console.info(t('user.using_response_as_users'))
    } else {
      console.error(t('user.unrecognized_data_format'), response)
      users.value = []
      error.value = t('user.unrecognized_server_data')
    }
    
    // 设置分页信息，兼容不同的字段名
    if (!Array.isArray(response)) {
      pagination.total = response.total || response.total_count || response.count || 0
      pagination.totalPages = response.total_page || response.pages || Math.ceil(pagination.total / pagination.size) || 0
    } else {
      // 如果响应是数组，则使用数组长度作为总数
      pagination.total = response.length
      pagination.totalPages = Math.ceil(response.length / pagination.size)
    }
  } catch (e: any) {
    error.value = e.response?.data?.error || t('user.load_failed')
    ElMessage.error(error.value)
    console.error(t('user.fetch_users_failed'), e)
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
  console.log('viewUserDetail', user)
  selectedUser.value = user
  userDetailVisible.value = true
  sessionTabSelected.value = false
}

// 查看用户会话
const viewUserSessions = (user: User) => {
  selectedUser.value = user
  userDetailVisible.value = true
  sessionTabSelected.value = true
  // 下一轮事件循环中设置激活标签为会话
  setTimeout(() => {
    if (document.querySelector('.user-detail')) {
      const tabEl = document.querySelector('.user-detail .el-tabs__item[data-name="sessions"]') as HTMLElement
      if (tabEl) tabEl.click()
    }
  }, 0)
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
const formatDate = (dateStr: string | null | undefined): string => {
  if (!dateStr) return t('user.none')
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
    active: t('user.status_active'),
    inactive: t('user.status_inactive'),
    locked: t('user.status_locked'),
    banned: t('user.status_banned')
  }
  return map[status] || status
}

// 获取提供商文本
const getProviderText = (provider: string) => {
  const map: Record<string, string> = {
    local: t('user.provider_local'),
    google: 'Google',
    weixin: t('user.provider_weixin')
  }
  return map[provider] || provider
}

// 辅助函数：获取用户ID
const getUserId = (user: User): string => {
  return String(user.user_id || t('user.unknown_id'))
}

// 辅助函数：获取用户名
const getUserName = (user: User): string => {
  return user.nickname || t('user.unknown_username')
}

// 辅助函数：获取状态
const getStatus = (user: User): string => {
  return user.status || 'inactive'
}

// 辅助函数：获取提供商
// const getProvider = (user: User): string => {
//   return user.provider || user.auth_provider || 'local'
// }

// 辅助函数：检查是否已验证
const isVerified = (user: User): boolean => {
  return user.verified === true || user.is_verified === true
}

// 辅助函数：获取创建时间
const getCreatedAt = (user: User): string => {
  return user.created_at || user.register_time || ''
}

// 辅助函数：获取最后登录时间
const getLastLogin = (user: User): string | null => {
  return user.last_login || user.last_login_time || null
}

// 组件挂载时获取数据
onMounted(() => {
  fetchUsers()
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
  
  .operation-buttons {
    display: flex;
    justify-content: space-around;
    gap: 5px;
  }
}
</style> 