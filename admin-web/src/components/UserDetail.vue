<template>
  <div class="user-detail">
    <el-tabs v-model="activeTab">
      <!-- 基本信息选项卡 -->
      <el-tab-pane label="基本信息" name="basic">
        <el-descriptions title="用户信息" :column="2" border>
          <el-descriptions-item label="用户ID">{{ getUserId(user) }}</el-descriptions-item>
          <el-descriptions-item label="用户名">{{ getUserName(user) }}</el-descriptions-item>
          <el-descriptions-item label="电子邮箱">{{ user.email || '无' }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="getStatusType(getStatus(user))">{{ getStatusText(getStatus(user)) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="提供商">
            <el-tag type="info">{{ getProviderText(getProvider(user)) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="验证状态">
            <el-tag :type="isVerified(user) ? 'success' : 'danger'">
              {{ isVerified(user) ? '已验证' : '未验证' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="双因素认证">
            <el-tag :type="user.two_factor_enabled ? 'success' : 'info'">
              {{ user.two_factor_enabled ? '已启用' : '未启用' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="注册时间">
            {{ formatDateTime(getCreatedAt(user)) }}
          </el-descriptions-item>
          <el-descriptions-item label="最后登录">
            {{ getLastLogin(user) ? formatDateTime(getLastLogin(user)) : '从未登录' }}
          </el-descriptions-item>
          <el-descriptions-item label="登录尝试次数">{{ user.login_attempts || 0 }}</el-descriptions-item>
          <el-descriptions-item label="最后尝试时间">
            {{ user.last_attempt ? formatDateTime(user.last_attempt) : '无' }}
          </el-descriptions-item>
        </el-descriptions>

        <div class="action-buttons">
          <el-button type="primary" @click="handleEditUser">编辑用户</el-button>
          <el-button :type="getActionButtonType(getStatus(user))" @click="handleToggleStatus">
            {{ getActionButtonText(getStatus(user)) }}
          </el-button>
          <el-button 
            :type="isVerified(user) ? 'warning' : 'success'" 
            @click="handleToggleVerified"
          >
            {{ isVerified(user) ? '取消验证' : '标记为已验证' }}
          </el-button>
        </div>
      </el-tab-pane>

      <!-- 会话信息选项卡 -->
      <el-tab-pane label="登录信息" name="sessions">
        <div class="action-buttons mb-4">
          <el-button type="danger" @click="handleTerminateAll" :loading="terminatingAll">
            强制退出所有会话
          </el-button>
          <el-button @click="refreshSessions" :loading="loadingSessions">
            刷新会话信息
          </el-button>
        </div>

        <el-alert
          v-if="loadingError"
          :title="loadingError"
          type="error"
          :closable="true"
          @close="loadingError = ''"
          style="margin-bottom: 15px;"
        />

        <el-alert
          v-if="!sessions.length && !jwtSessions.length && !loadingSessions && !loadingError"
          title="该用户目前没有活跃会话"
          type="info"
          :closable="false"
        />

        <!-- 标准会话表格 -->
        <template v-if="sessions.length">
          <h3 class="my-3">标准会话</h3>
          <el-table
            :data="sessions"
            style="width: 100%"
            border
            stripe
            v-loading="loadingSessions"
          >
            <el-table-column prop="id" label="会话ID" width="280" />
            <el-table-column prop="ip" label="IP地址" width="150" />
            <el-table-column label="用户代理" min-width="200">
              <template #default="scope">
                <div class="user-agent-cell">{{ scope.row.user_agent }}</div>
              </template>
            </el-table-column>
            <el-table-column label="创建时间" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.created_at) }}
              </template>
            </el-table-column>
            <el-table-column label="过期时间" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.expires_at) }}
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="scope">
                <el-button 
                  size="small" 
                  type="danger" 
                  @click="handleTerminateSession(scope.row.id, false)"
                  :loading="terminatingSessionId === scope.row.id"
                >
                  强制退出
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </template>

        <!-- JWT会话表格 -->
        <template v-if="jwtSessions.length">
          <h3 class="my-3">JWT会话</h3>
          <el-table
            :data="jwtSessions"
            style="width: 100%"
            border
            stripe
            v-loading="loadingSessions"
          >
            <el-table-column prop="key_id" label="密钥ID" width="280" />
            <el-table-column prop="token_type" label="令牌类型" width="120">
              <template #default="scope">
                <el-tag :type="scope.row.token_type === 'access' ? 'success' : 'warning'">
                  {{ scope.row.token_type === 'access' ? '访问令牌' : '刷新令牌' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="ip" label="IP地址" width="150" />
            <el-table-column label="用户代理" min-width="200">
              <template #default="scope">
                <div class="user-agent-cell">{{ scope.row.user_agent || '未知' }}</div>
              </template>
            </el-table-column>
            <el-table-column label="发行时间" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.issued_at) }}
              </template>
            </el-table-column>
            <el-table-column label="过期时间" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.expires_at) }}
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="scope">
                <el-button 
                  size="small" 
                  type="danger" 
                  @click="handleTerminateSession('jwt:' + scope.row.key_id, true)"
                  :loading="terminatingSessionId === 'jwt:' + scope.row.key_id"
                >
                  强制退出
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </template>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, PropType, computed, onMounted, watch } from 'vue'
import { User, SessionData, JWTSessionData } from '@/api'
import api from '@/api'
import { ElMessage, ElMessageBox } from 'element-plus'

export default defineComponent({
  name: 'UserDetail',
  props: {
    user: {
      type: Object as PropType<User>,
      required: true
    },
    // 添加新属性，允许父组件指定初始标签页
    initialTab: {
      type: String,
      default: 'basic'
    }
  },
  emits: ['update:user', 'close'],
  setup(props, { emit }) {
    const activeTab = ref(props.initialTab)
    
    // 监听 initialTab 变化
    watch(() => props.initialTab, (newVal) => {
      activeTab.value = newVal
    })

    const sessions = ref<SessionData[]>([])
    const jwtSessions = ref<JWTSessionData[]>([])
    const loadingSessions = ref(false)
    const loadingError = ref('')
    const terminatingSessionId = ref('')
    const terminatingAll = ref(false)

    // 获取用户会话
    const fetchSessions = async () => {
      console.log('fetchSessions', props.user.user_id)
      if (!props.user.user_id) return
      
      loadingSessions.value = true
      loadingError.value = ''
      
      try {
        const userId = (getUserId(props.user))
        const response = await api.getUserSessions(userId)
        sessions.value = response.sessions || []
        jwtSessions.value = response.jwt_sessions || []
        
        // 如果获取会话成功但会话列表为空，显示友好提示
        if (sessions.value.length === 0 && jwtSessions.value.length === 0) {
          console.log('用户没有活跃会话')
        }
      } catch (error: any) {
        console.error('获取用户会话失败:', error)
        // 提取详细错误信息
        const errorResponse = error.response?.data
        const errorMsg = 
          errorResponse?.error || 
          error.message || 
          '服务器连接失败，请检查网络连接'
        
        loadingError.value = `获取用户会话信息失败：${errorMsg}`
        
        if (errorMsg.includes('Redis连接未初始化')) {
          loadingError.value = '系统配置错误：Redis连接未初始化，JWT会话功能不可用。请联系系统管理员。'
        }
        
        ElMessage.error(loadingError.value)
      } finally {
        loadingSessions.value = false
      }
    }

    // 终止单个会话
    const handleTerminateSession = async (sessionId: string, isJwt: boolean) => {
      try {
        terminatingSessionId.value = sessionId
        
        await ElMessageBox.confirm(
          '确定要强制终止该会话吗？这将使用户立即退出登录。',
          '确认操作',
          {
            confirmButtonText: '确定终止',
            cancelButtonText: '取消',
            type: 'warning'
          }
        )
        
        const userId = (getUserId(props.user))
        await api.terminateUserSession(userId, sessionId)
        ElMessage.success('会话已成功终止')
        
        // 从列表中移除终止的会话
        if (isJwt) {
          const keyId = sessionId.replace('jwt:', '')
          jwtSessions.value = jwtSessions.value.filter(s => s.key_id !== keyId)
        } else {
          sessions.value = sessions.value.filter(s => s.id !== sessionId)
        }
      } catch (error: any) {
        if (error !== 'cancel') {
          console.error('终止会话失败:', error)
          
          // 提取详细错误信息
          const errorResponse = error.response?.data
          const errorMsg = 
            errorResponse?.error || 
            error.message || 
            '未知错误'
          
          ElMessage.error(`终止会话失败：${errorMsg}`)
        }
      } finally {
        terminatingSessionId.value = ''
      }
    }

    // 终止所有会话
    const handleTerminateAll = async () => {
      try {
        terminatingAll.value = true
        
        await ElMessageBox.confirm(
          '确定要强制终止该用户的所有会话吗？这将使用户在所有设备上立即退出登录。',
          '确认操作',
          {
            confirmButtonText: '确定终止所有',
            cancelButtonText: '取消',
            type: 'warning'
          }
        )
        
        const userId = (getUserId(props.user))
        await api.terminateAllUserSessions(userId)
        ElMessage.success('所有会话已成功终止')
        
        // 清空会话列表
        sessions.value = []
        jwtSessions.value = []
      } catch (error: any) {
        if (error !== 'cancel') {
          console.error('终止所有会话失败:', error)
          ElMessage.error('终止所有会话失败，请重试')
        }
      } finally {
        terminatingAll.value = false
      }
    }

    // 刷新会话信息
    const refreshSessions = () => {
      fetchSessions()
    }

    // 编辑用户
    const handleEditUser = () => {
      ElMessage.info('编辑用户功能暂未实现')
    }

    // 切换用户状态
    const handleToggleStatus = () => {
      ElMessage.info('切换用户状态功能暂未实现')
    }

    // 切换验证状态
    const handleToggleVerified = () => {
      ElMessage.info('切换验证状态功能暂未实现')
    }

    // 辅助函数：获取用户ID
    const getUserId = (user: User): string => {
      return String(user.user_id || '未知ID')
    }
    
    // 辅助函数：获取用户名
    const getUserName = (user: User): string => {
      return user.profile.nickname || '未知用户名'
    }
    
    // 辅助函数：获取状态
    const getStatus = (user: User): string => {
      return user.status || 'inactive'
    }
    
    // 辅助函数：获取提供商
    const getProvider = (user: User): string => {
      return user.provider || user.auth_provider || 'local'
    }
    
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

    // 格式化日期时间
    const formatDateTime = (dateStr: string | null) => {
      if (!dateStr) return '无'
      return new Date(dateStr).toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
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

    // 获取操作按钮类型
    const getActionButtonType = (status: string) => {
      if (status === 'active') return 'warning'
      if (status === 'locked') return 'warning'
      if (status === 'banned') return 'danger'
      return 'success'
    }

    // 获取操作按钮文本
    const getActionButtonText = (status: string) => {
      if (status === 'active') return '锁定账号'
      if (status === 'inactive') return '激活账号'
      if (status === 'locked') return '解锁账号'
      if (status === 'banned') return '解封账号'
      return '更改状态'
    }

    onMounted(() => {
      fetchSessions()
    })

    return {
      activeTab,
      sessions,
      jwtSessions,
      loadingSessions,
      loadingError,
      terminatingSessionId,
      terminatingAll,
      handleTerminateSession,
      handleTerminateAll,
      refreshSessions,
      handleEditUser,
      handleToggleStatus,
      handleToggleVerified,
      formatDateTime,
      getStatusType,
      getStatusText,
      getProviderText,
      getActionButtonType,
      getActionButtonText,
      getUserId,
      getUserName,
      getStatus,
      getProvider,
      isVerified,
      getCreatedAt,
      getLastLogin
    }
  }
})
</script>

<style lang="scss" scoped>
.user-detail {
  padding: 20px 0;
}

.action-buttons {
  margin-top: 20px;
  display: flex;
  gap: 10px;
}

.mb-4 {
  margin-bottom: 20px;
}

.my-3 {
  margin-top: 15px;
  margin-bottom: 15px;
}

.user-agent-cell {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 400px;
}
</style> 