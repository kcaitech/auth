<template>
  <div class="user-detail">
    <el-tabs v-model="activeTab">
      <!-- 基本信息选项卡 -->
      <el-tab-pane :label="$t('userDetail.basic_info')" name="basic">
        <el-descriptions :title="$t('userDetail.user_info')" :column="2" border>
          <el-descriptions-item :label="$t('userDetail.user_id')">{{ getUserId(user) }}</el-descriptions-item>
          <el-descriptions-item :label="$t('userDetail.username')">{{ getUserName(user) }}</el-descriptions-item>
          <!-- <el-descriptions-item :label="$t('userDetail.email')">{{ user.email || $t('userDetail.none') }}</el-descriptions-item> -->
          <!-- <el-descriptions-item :label="$t('userDetail.status')">
            <el-tag :type="getStatusType(getStatus(user))">{{ getStatusText(getStatus(user)) }}</el-tag>
          </el-descriptions-item> -->
          <!-- <el-descriptions-item :label="$t('userDetail.provider')">
            <el-tag type="info">{{ getProviderText(getProvider(user)) }}</el-tag>
          </el-descriptions-item> -->
          <!-- <el-descriptions-item :label="$t('userDetail.verification_status')">
            <el-tag :type="isVerified(user) ? 'success' : 'danger'">
              {{ isVerified(user) ? $t('userDetail.verified') : $t('userDetail.not_verified') }}
            </el-tag>
          </el-descriptions-item> -->
          <el-descriptions-item :label="$t('userDetail.two_factor_auth')">
            <el-tag :type="user.two_factor_enabled ? 'success' : 'info'">
              {{ user.two_factor_enabled ? $t('userDetail.enabled') : $t('userDetail.disabled') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('userDetail.registration_time')">
            {{ formatDateTime(getCreatedAt(user)) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('userDetail.last_login')">
            {{ getLastLogin(user) ? formatDateTime(getLastLogin(user)) : $t('userDetail.never_logged_in') }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('userDetail.login_attempts')">{{ user.login_attempts || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="$t('userDetail.last_attempt_time')">
            {{ user.last_attempt ? formatDateTime(user.last_attempt) : $t('userDetail.none') }}
          </el-descriptions-item>
        </el-descriptions>

        <div class="action-buttons">
          <el-button type="primary" @click="handleEditUser">{{ $t('userDetail.edit_user') }}</el-button>
          <!-- <el-button :type="getActionButtonType(getStatus(user))" @click="handleToggleStatus">
            {{ getActionButtonText(getStatus(user)) }}
          </el-button> -->
          <!-- <el-button 
            :type="isVerified(user) ? 'warning' : 'success'" 
            @click="handleToggleVerified"
          >
            {{ isVerified(user) ? $t('userDetail.cancel_verification') : $t('userDetail.mark_as_verified') }}
          </el-button> -->
        </div>
      </el-tab-pane>

      <!-- 会话信息选项卡 -->
      <el-tab-pane :label="$t('userDetail.login_info')" name="sessions">
        <div class="action-buttons mb-4">
          <el-button type="danger" @click="handleTerminateAll" :loading="terminatingAll">
            {{ $t('userDetail.terminate_all_sessions') }}
          </el-button>
          <el-button @click="refreshSessions" :loading="loadingSessions">
            {{ $t('userDetail.refresh_sessions') }}
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
          :title="$t('userDetail.no_active_sessions')"
          type="info"
          :closable="false"
        />

        <!-- 标准会话表格 -->
        <template v-if="sessions.length">
          <h3 class="my-3">{{ $t('userDetail.standard_sessions') }}</h3>
          <el-table
            :data="sessions"
            style="width: 100%"
            border
            stripe
            v-loading="loadingSessions"
          >
            <el-table-column prop="id" :label="$t('userDetail.session_id')" width="280" />
            <el-table-column prop="ip" :label="$t('userDetail.ip_address')" width="150" />
            <el-table-column :label="$t('userDetail.user_agent')" min-width="200">
              <template #default="scope">
                <div class="user-agent-cell">{{ scope.row.user_agent }}</div>
              </template>
            </el-table-column>
            <el-table-column :label="$t('userDetail.creation_time')" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.created_at) }}
              </template>
            </el-table-column>
            <el-table-column :label="$t('userDetail.expiry_time')" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.expires_at) }}
              </template>
            </el-table-column>
            <el-table-column :label="$t('userDetail.actions')" width="120" fixed="right">
              <template #default="scope">
                <el-button 
                  size="small" 
                  type="danger" 
                  @click="handleTerminateSession(scope.row.id, false)"
                  :loading="terminatingSessionId === scope.row.id"
                >
                  {{ $t('userDetail.force_logout') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </template>

        <!-- JWT会话表格 -->
        <template v-if="jwtSessions.length">
          <h3 class="my-3">{{ $t('userDetail.jwt_sessions') }}</h3>
          <el-table
            :data="jwtSessions"
            style="width: 100%"
            border
            stripe
            v-loading="loadingSessions"
          >
            <el-table-column prop="key_id" :label="$t('userDetail.key_id')" width="280" />
            <el-table-column prop="token_type" :label="$t('userDetail.token_type')" width="120">
              <template #default="scope">
                <el-tag :type="scope.row.token_type === 'access' ? 'success' : 'warning'">
                  {{ scope.row.token_type === 'access' ? $t('userDetail.access_token') : $t('userDetail.refresh_token') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="ip" :label="$t('userDetail.ip_address')" width="150" />
            <el-table-column :label="$t('userDetail.user_agent')" min-width="200">
              <template #default="scope">
                <div class="user-agent-cell">{{ scope.row.user_agent || $t('userDetail.unknown') }}</div>
              </template>
            </el-table-column>
            <el-table-column :label="$t('userDetail.issue_time')" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.issued_at) }}
              </template>
            </el-table-column>
            <el-table-column :label="$t('userDetail.expiry_time')" width="180">
              <template #default="scope">
                {{ formatDateTime(scope.row.expires_at) }}
              </template>
            </el-table-column>
            <el-table-column :label="$t('userDetail.actions')" width="120" fixed="right">
              <template #default="scope">
                <el-button 
                  size="small" 
                  type="danger" 
                  @click="handleTerminateSession('jwt:' + scope.row.key_id, true)"
                  :loading="terminatingSessionId === 'jwt:' + scope.row.key_id"
                >
                  {{ $t('userDetail.force_logout') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </template>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, PropType, onMounted, watch } from 'vue'
import { User, SessionData, JWTSessionData } from '@/api'
import { serverApi as api } from '@/api/index'
import { ElMessage, ElMessageBox } from 'element-plus'
import i18n from '@/lang'

const props = defineProps({
    user: {
      type: Object as PropType<User>,
      required: true
    },
    // 添加新属性，允许父组件指定初始标签页
    initialTab: {
      type: String,
      default: 'basic'
    }
  })


const { t } = i18n.global
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
      console.log(t('userDetail.no_active_sessions'))
    }
  } catch (error: any) {
    console.error(t('userDetail.fetch_sessions_error'), error)
    // 提取详细错误信息
    const errorResponse = error.response?.data
    const errorMsg = 
      errorResponse?.error || 
      error.message || 
      t('userDetail.server_connection_error')
    
    loadingError.value = `${t('userDetail.fetch_sessions_failed')}: ${errorMsg}`
    
    if (errorMsg.includes('Redis连接未初始化')) {
      loadingError.value = t('userDetail.redis_not_initialized')
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
      t('userDetail.terminate_session_confirm'),
      t('userDetail.confirm_operation'),
      {
        confirmButtonText: t('userDetail.confirm_terminate'),
        cancelButtonText: t('common.cancel'),
        type: 'warning'
      }
    )
    
    const userId = (getUserId(props.user))
    await api.terminateUserSession(userId, sessionId)
    ElMessage.success(t('userDetail.session_terminated_success'))
    
    // 从列表中移除终止的会话
    if (isJwt) {
      const keyId = sessionId.replace('jwt:', '')
      jwtSessions.value = jwtSessions.value.filter(s => s.key_id !== keyId)
    } else {
      sessions.value = sessions.value.filter(s => s.id !== sessionId)
    }
  } catch (error: any) {
    if (error !== 'cancel') {
      console.error(t('userDetail.terminate_session_error'), error)
      
      // 提取详细错误信息
      const errorResponse = error.response?.data
      const errorMsg = 
        errorResponse?.error || 
        error.message || 
        t('userDetail.unknown_error')
      
      ElMessage.error(`${t('userDetail.terminate_session_failed')}: ${errorMsg}`)
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
      t('userDetail.terminate_all_sessions_confirm'),
      t('userDetail.confirm_operation'),
      {
        confirmButtonText: t('userDetail.confirm_terminate_all'),
        cancelButtonText: t('common.cancel'),
        type: 'warning'
      }
    )
    
    const userId = (getUserId(props.user))
    await api.terminateAllUserSessions(userId)
    ElMessage.success(t('userDetail.all_sessions_terminated'))
    
    // 清空会话列表
    sessions.value = []
    jwtSessions.value = []
  } catch (error: any) {
    if (error !== 'cancel') {
      console.error(t('userDetail.terminate_all_sessions_error'), error)
      ElMessage.error(t('userDetail.terminate_all_sessions_failed'))
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
  ElMessage.info(t('userDetail.edit_user_not_implemented'))
}

// 切换用户状态
const handleToggleStatus = () => {
  ElMessage.info(t('userDetail.toggle_status_not_implemented'))
}

// 切换验证状态
const handleToggleVerified = () => {
  ElMessage.info(t('userDetail.toggle_verification_not_implemented'))
}

// 辅助函数：获取用户ID
const getUserId = (user: User): string => {
  return String(user.user_id || t('userDetail.unknown_id'))
}

// 辅助函数：获取用户名
const getUserName = (user: User): string => {
  return user.nickname || t('userDetail.unknown_username')
}

// 辅助函数：获取状态
// const getStatus = (user: User): string => {
//   return user.status || 'inactive'
// }

// 辅助函数：获取提供商
// const getProvider = (user: User): string => {
//   return user.provider || user.auth_provider || 'local'
// }

// 辅助函数：检查是否已验证
// const isVerified = (user: User): boolean => {
//   return user.verified === true || user.is_verified === true
// }

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
  if (!dateStr) return t('userDetail.none')
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
    active: t('userDetail.status_active'),
    inactive: t('userDetail.status_inactive'),
    locked: t('userDetail.status_locked'),
    banned: t('userDetail.status_banned')
  }
  return map[status] || status
}

// 获取提供商文本
const getProviderText = (provider: string) => {
  const map: Record<string, string> = {
    local: t('userDetail.provider_local'),
    google: 'Google',
    weixin: t('userDetail.provider_weixin')
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
  if (status === 'active') return t('userDetail.lock_account')
  if (status === 'inactive') return t('userDetail.activate_account')
  if (status === 'locked') return t('userDetail.unlock_account')
  if (status === 'banned') return t('userDetail.unban_account')
  return t('userDetail.change_status')
}

onMounted(() => {
  fetchSessions()
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