<template>
  <div class="my-sessions-container">
    <el-card class="sessions-card">
      <template #header>
        <div class="card-header">
          <h2>我的登录会话</h2>
          <div class="actions">
            <el-button type="danger" @click="handleTerminateAll" :loading="terminatingAll">
              退出所有其他设备
            </el-button>
            <el-button type="primary" @click="refreshSessions" :loading="loading">
              <i class="el-icon-refresh"></i> 刷新
            </el-button>
          </div>
        </div>
      </template>
      
      <el-alert
        v-if="error"
        :title="error"
        type="error"
        :closable="true"
        @close="error = ''"
        style="margin-bottom: 15px;"
      />

      <el-alert
        v-if="!sessions.length && !jwtSessions.length && !loading && !error"
        title="您目前没有其他活跃会话"
        type="info"
        :closable="false"
      />

      <!-- 标准会话表格 -->
      <template v-if="sessions.length">
        <h3 class="section-title">标准会话</h3>
        <div class="table-info">当前会话以 <el-tag type="success">绿色</el-tag> 标记</div>
        <el-table
          :data="sessions"
          style="width: 100%"
          border
          stripe
          v-loading="loading"
        >
          <el-table-column label="会话状态" width="100">
            <template #default="scope">
              <el-tag :type="isCurrentSession(scope.row.id) ? 'success' : 'info'">
                {{ isCurrentSession(scope.row.id) ? '当前会话' : '其他会话' }}
              </el-tag>
            </template>
          </el-table-column>
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
                @click="handleTerminateSession(scope.row.id)"
                :loading="terminatingSessionId === scope.row.id"
                :disabled="isCurrentSession(scope.row.id)"
              >
                退出
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>

      <!-- JWT会话表格 -->
      <template v-if="jwtSessions.length">
        <h3 class="section-title">JWT会话</h3>
        <el-table
          :data="jwtSessions"
          style="width: 100%"
          border
          stripe
          v-loading="loading"
        >
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
                @click="handleTerminateJWTSession(scope.row.key_id)"
                :loading="terminatingSessionId === 'jwt:' + scope.row.key_id"
              >
                撤销
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>
    </el-card>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, onMounted } from 'vue'
import api, { SessionData, JWTSessionData } from '@/api'
import { ElMessage, ElMessageBox } from 'element-plus'

export default defineComponent({
  name: 'MySessionsView',
  setup() {
    const sessions = ref<SessionData[]>([])
    const jwtSessions = ref<JWTSessionData[]>([])
    const loading = ref(false)
    const error = ref('')
    const terminatingSessionId = ref('')
    const terminatingAll = ref(false)
    
    // 当前会话ID
    const currentSessionId = ref('')
    // 当前管理员ID
    const currentAdminId = ref<string>('')

    // 获取会话列表
    const fetchSessions = async () => {
      loading.value = true
      error.value = ''
      
      try {
        // 如果没有当前管理员ID，则获取当前管理员信息
        if (!currentAdminId.value) {
          try {
            // 从localStorage中获取管理员信息
            const adminSession = localStorage.getItem('admin_session')
            if (adminSession) {
              const adminInfo = JSON.parse(adminSession)
              currentAdminId.value = adminInfo.id || adminInfo.user_id
            }
            
            if (!currentAdminId.value) {
              throw new Error('无法获取当前管理员ID')
            }
          } catch (e) {
            console.error('获取管理员信息失败:', e)
            error.value = '无法获取当前管理员信息'
            loading.value = false
            return
          }
        }
        
        // 使用现有的API获取会话
        const response = await api.getUserSessions((currentAdminId.value))
        sessions.value = response.sessions || []
        jwtSessions.value = response.jwt_sessions || []
        
        // 获取当前会话ID (从cookie或其他地方)
        // 这里需要根据实际情况替换获取当前会话ID的逻辑
        const cookies = document.cookie.split(';')
        for (const cookie of cookies) {
          const [name, value] = cookie.trim().split('=')
          if (name === 'admin_session_id') {
            currentSessionId.value = value
            break
          }
        }
        
      } catch (e: any) {
        console.error('获取会话列表失败:', e)
        error.value = e.response?.data?.error || '加载会话列表失败'
        ElMessage.error(error.value)
      } finally {
        loading.value = false
      }
    }
    
    // 检查是否为当前会话
    const isCurrentSession = (sessionId: string): boolean => {
      return sessionId === currentSessionId.value
    }

    // 终止会话
    const handleTerminateSession = async (sessionId: string) => {
      try {
        terminatingSessionId.value = sessionId
        
        await ElMessageBox.confirm(
          '确定要退出该设备的会话吗？',
          '确认操作',
          {
            confirmButtonText: '确定',
            cancelButtonText: '取消',
            type: 'warning'
          }
        )
        
        await api.terminateUserSession((currentAdminId.value), sessionId)
        ElMessage.success('会话已成功终止')
        
        // 从列表中移除
        sessions.value = sessions.value.filter(s => s.id !== sessionId)
        
      } catch (error: any) {
        if (error !== 'cancel') {
          ElMessage.error('终止会话失败')
          console.error('终止会话失败:', error)
        }
      } finally {
        terminatingSessionId.value = ''
      }
    }
    
    // 终止JWT会话
    const handleTerminateJWTSession = async (keyId: string) => {
      try {
        terminatingSessionId.value = 'jwt:' + keyId
        
        await ElMessageBox.confirm(
          '确定要撤销该JWT令牌吗？',
          '确认操作',
          {
            confirmButtonText: '确定',
            cancelButtonText: '取消',
            type: 'warning'
          }
        )
        
        await api.terminateUserSession((currentAdminId.value), 'jwt:' + keyId)
        ElMessage.success('JWT令牌已成功撤销')
        
        // 从列表中移除
        jwtSessions.value = jwtSessions.value.filter(s => s.key_id !== keyId)
        
      } catch (error: any) {
        if (error !== 'cancel') {
          ElMessage.error('撤销令牌失败')
          console.error('撤销令牌失败:', error)
        }
      } finally {
        terminatingSessionId.value = ''
      }
    }

    // 终止所有其他会话
    const handleTerminateAll = async () => {
      try {
        terminatingAll.value = true
        
        await ElMessageBox.confirm(
          '确定要将您的账号从所有其他设备上退出吗？',
          '确认操作',
          {
            confirmButtonText: '确定',
            cancelButtonText: '取消',
            type: 'warning'
          }
        )
        
        await api.terminateAllUserSessions((currentAdminId.value))
        ElMessage.success('已成功从所有其他设备退出')
        
        // 重新获取会话列表
        await fetchSessions()
        
      } catch (error: any) {
        if (error !== 'cancel') {
          ElMessage.error('操作失败，请重试')
          console.error('终止所有其他会话失败:', error)
        }
      } finally {
        terminatingAll.value = false
      }
    }

    // 刷新会话列表
    const refreshSessions = () => {
      fetchSessions()
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

    // 组件挂载时获取数据
    onMounted(() => {
      console.log('MySessionsView mounted')
      fetchSessions()
    })

    return {
      sessions,
      jwtSessions,
      loading,
      error,
      terminatingSessionId,
      terminatingAll,
      currentSessionId,
      currentAdminId,
      isCurrentSession,
      handleTerminateSession,
      handleTerminateJWTSession,
      handleTerminateAll,
      refreshSessions,
      formatDateTime
    }
  }
})
</script>

<style lang="scss" scoped>
.my-sessions-container {
  .sessions-card {
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
    
    .actions {
      display: flex;
      gap: 10px;
    }
  }
  
  .section-title {
    margin-top: 20px;
    margin-bottom: 10px;
    font-size: 16px;
    font-weight: 500;
  }
  
  .table-info {
    margin-bottom: 10px;
    color: #666;
    font-size: 14px;
  }
  
  .user-agent-cell {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 400px;
  }
}
</style> 