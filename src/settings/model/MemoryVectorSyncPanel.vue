<template>
  <div class="memory-vector-sync-panel">
    <h3>Memory Vector Sync</h3>
    <div class="panel-content">
      <div v-if="!controller.lifeId" class="empty-state">
        No active life profile to sync memories for.
      </div>
      <div v-else>
        <!-- Auth switch -->
        <div class="switch-container">
          <label>
            <input 
              type="checkbox" 
              :checked="controller.settings?.enabled" 
              @change="handleToggleEnabled"
              :disabled="controller.state === 'loadingStatus' || controller.state === 'failed'"
            />
            自动同步已确认记忆的向量索引
          </label>
        </div>

        <!-- Status -->
        <div class="status-container" v-if="controller.status">
          <p>
            状态: <strong>{{ statusText }}</strong>
          </p>
          <ul class="stats-list">
            <li>Pending: {{ controller.status.pendingCount }}</li>
            <li>Processing: {{ controller.status.processingCount }}</li>
            <li>Blocked: {{ controller.status.blockedCount }}</li>
            <li>Failed: {{ controller.status.failedCount }}</li>
            <li v-if="controller.status.retryWaitCount > 0">Waiting to Retry: {{ controller.status.retryWaitCount }}</li>
            <li v-if="controller.lastDrainResult">
              Last manual run: processed {{ controller.lastDrainResult.processed }}
              (applied {{ controller.lastDrainResult.appliedUpserts }} upserts /
              {{ controller.lastDrainResult.appliedDeletes }} deletes;
              failed {{ controller.lastDrainResult.failed }};
              blocked {{ controller.lastDrainResult.blocked }})
            </li>
          </ul>
        </div>

        <!-- Actions -->
        <div class="actions-container">
          <button 
            @click="handleStart" 
            :disabled="!controller.canStart || props.rebuildRunning"
            title="Runs one bounded fenced drain that processes at most 32 items; it is not a permanent background worker."
          >
            开始同步
          </button>
          
          <button 
            v-if="controller.canRetry" 
            @click="handleRetry"
            title="Marks blocked and failed outbox entries for retry."
          >
            重试失败项
          </button>
        </div>

        <!-- Confirm Start Modal -->
        <div v-if="showStartConfirm" class="modal-overlay" role="dialog" aria-modal="true">
          <div class="modal-content">
            <h4>确认启动同步？</h4>
            <p>本次手动执行最多处理 32 项；它不是常驻后台进程。<br/>本次执行返回后，如果仍有 pending 任务，可以再次点击“开始同步”。<br/>可能调用外部 Embedding API。</p>
            <div class="modal-actions">
              <button @click="confirmStart">确认</button>
              <button @click="showStartConfirm = false">取消</button>
            </div>
          </div>
        </div>

        <!-- Confirm Enable Modal -->
        <div v-if="showEnableConfirm" class="modal-overlay" role="dialog" aria-modal="true">
          <div class="modal-content">
            <h4>确认启用增量同步？</h4>
            <p>
              只有 confirmed 且非敏感记忆会发送给 Embedding Provider；<br/>
              candidate 和敏感记忆不会发送；<br/>
              可能产生 API 费用；<br/>
              同步只更新可重建的 LanceDB 派生索引；<br/>
              SQLite 记忆不会被删除或修改；<br/>
              启用后仍不会在应用启动时自动常驻运行；<br/>
              每次同步由用户主动点击“开始同步”执行最多 32 项。
            </p>
            <div class="modal-actions">
              <button @click="confirmEnable">同意启用</button>
              <button @click="cancelEnable">取消</button>
            </div>
          </div>
        </div>

        <!-- Error display -->
        <div v-if="controller.error" class="error-container" aria-live="polite">
          <strong>Error [{{ controller.error.code }}] ({{ controller.error.operation }})</strong>
          <p>{{ controller.error.safeMessage }}</p>
        </div>
        <div v-if="props.rebuildRunning" class="warning-container">
          <p>全量重建进行中。增量同步已暂时禁用。</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from "vue";
import { MemoryVectorSyncController } from "./memoryVectorSyncController.ts";

const props = defineProps<{
  rebuildRunning: boolean;
}>();

const controller = ref(new MemoryVectorSyncController());
const showStartConfirm = ref(false);
const showEnableConfirm = ref(false);

const handleToggleEnabled = (event: Event) => {
  const target = event.target as HTMLInputElement;
  const checked = target.checked;
  // Revert UI immediately until confirmed
  target.checked = !checked;
  
  if (checked) {
    showEnableConfirm.value = true;
  } else {
    // Disable directly without confirm
    controller.value.toggleEnabled(false).then((success) => {
      if (success) {
        target.checked = false;
      }
    });
  }
};

const confirmEnable = async () => {
  showEnableConfirm.value = false;
  await controller.value.toggleEnabled(true);
};

const cancelEnable = () => {
  showEnableConfirm.value = false;
};

const handleStart = () => {
  if (props.rebuildRunning) return;
  showStartConfirm.value = true;
};

const confirmStart = async () => {
  showStartConfirm.value = false;
  await controller.value.startSync();
};

const handleRetry = async () => {
  const isBlocked = (controller.value.status?.blockedCount ?? 0) > 0;
  if (isBlocked) {
    const confirmRetry = confirm("blocked 问题应先修复模型档案、凭据或存储配置；重试不会自动切换 Embedding 模型，也不会使用 Chat Credential。确认重试？");
    if (!confirmRetry) return;
  }
  await controller.value.retryFailures();
};

const statusText = computed(() => {
  if (!controller.value.settings?.enabled) return "未启用";
  if (controller.value.status?.workerState === "running" || controller.value.status?.workerState === "pausing") {
    return controller.value.status.workerState === "pausing" ? "正在暂停" : "正在同步";
  }
  if (controller.value.status?.failedCount && controller.value.status.failedCount > 0) return "存在失败任务";
  if (controller.value.status?.blockedCount && controller.value.status.blockedCount > 0) return "存在被阻塞任务";
  if (controller.value.status?.retryWaitCount && controller.value.status.retryWaitCount > 0) return "存在等待重试任务";
  
  // If it's enabled but stopped and we have pending tasks
  if (controller.value.status?.pendingCount && controller.value.status.pendingCount > 0) {
    return "已启用，等待用户启动";
  }
  
  return "本次处理完成";
});

const onVisibilityChange = () => {
  if (document.hidden) {
    controller.value.deactivate();
  } else {
    controller.value.activate();
  }
};

onMounted(() => {
  controller.value.activate();
  document.addEventListener("visibilitychange", onVisibilityChange);
});

onUnmounted(() => {
  controller.value.deactivate();
  document.removeEventListener("visibilitychange", onVisibilityChange);
});
</script>

<style scoped>
.memory-vector-sync-panel {
  border: 1px solid #ccc;
  padding: 16px;
  margin-bottom: 16px;
  border-radius: 4px;
}
.switch-container {
  margin-bottom: 12px;
}
.stats-list {
  list-style: none;
  padding: 0;
  margin: 8px 0;
}
.actions-container button {
  margin-right: 8px;
}
.modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}
.modal-content {
  background: white;
  padding: 24px;
  border-radius: 8px;
  max-width: 400px;
}
.modal-actions {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
.error-container {
  margin-top: 16px;
  padding: 12px;
  background: #fee;
  border-left: 4px solid red;
}
.warning-container {
  margin-top: 16px;
  padding: 12px;
  background: #ffeeba;
  border-left: 4px solid #ffc107;
}
</style>