import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

export const APP_LANGUAGES = ['en', 'zh-CN', 'zh-TW'] as const
export type AppLanguage = (typeof APP_LANGUAGES)[number]

const LANGUAGE_STORAGE_KEY = 'cs2vibe.language'

const resources = {
  en: {
    translation: {
      language: { selector: 'Language', english: 'English', simplifiedChinese: 'Simplified Chinese', traditionalChinese: 'Traditional Chinese' },
      common: { notAvailable: '—' },
      errors: { connectionFailed: 'Connection failed', invalidApiAddress: 'Invalid API address', apiHttpOnly: 'The API address only supports HTTP or HTTPS', apiAddressParts: 'The API address cannot include credentials, query parameters, or a fragment', requestFailed: 'Request failed', cannotConnectApi: 'Unable to connect to the API' },
      app: { pageTitle: 'CS2 VibeSignatures Process Dashboard', apiSettings: 'API settings', loadingPage: 'Loading page…' },
      navigation: { runs: 'Analysis Runs', symbols: 'Explore Symbols', gamedata: 'Game Data' },
      settings: { title: 'API connection settings', baseUrl: 'FastAPI Base URL', help: 'Requests from public Pages are made by the current browser. The default address only reaches 127.0.0.1 on this computer, not localhost on another machine.', saveAndReconnect: 'Save and reconnect', disconnect: 'Disconnect' },
      connection: { redisUnavailable: 'FastAPI is running, but Redis is not ready. Check the Redis address and service status.', hint: 'Confirm that FastAPI is running, the Pages origin is in the CORS allowlist, and the browser may access the local network.', title: 'Connect to the local progress API', descriptionBefore: 'This page connects from the current browser to ', descriptionAfter: ' and checks FastAPI and Redis readiness.', connect: 'Connect to local API', changeAddress: 'Change address' },
      status: { queued: 'Queued', starting: 'Starting', pending: 'Pending', running: 'Running', succeeded: 'Succeeded', failed: 'Failed', skipped: 'Skipped', aborted: 'Aborted', stale: 'Stale' },
      phase: { label: 'Phase', preflight: 'Preflight', waiting_for_mcp: 'Waiting for MCP', validating_binary: 'Validating binary', validating_inputs: 'Validating inputs', preprocessing: 'Preprocessing', validating_outputs: 'Validating outputs', agent_fallback: 'Agent fallback', vcall_export: 'Virtual-call export', postprocessing: 'Post-processing', finished: 'Finished' },
      runs: { title: 'Analysis runs', subtitle: 'Redis Process Reporter history and live status', refresh: 'Refresh', run: 'Run', status: 'Status', version: 'Version', agent: 'Agent', progress: 'Progress', currentTask: 'Current task', createdAt: 'Created at', allStatuses: 'All statuses', gameVersion: 'Game version', loadMore: 'Load more', redisUnavailable: 'The Redis status service is unavailable.', error: 'Unable to load the run list. Check the API address, CORS, and local-network access.' },
      detail: { sseConnecting: 'SSE connecting', sseConnected: 'SSE connected', sseReconnecting: 'SSE reconnecting', sseClosed: 'SSE closed', noCurrentTask: 'No task is currently executing', progressSummary: 'Succeeded {{succeeded}} · Failed {{failed}} · Skipped {{skipped}} · Aborted {{aborted}}', refreshSnapshot: 'Refresh snapshot', backToRuns: 'Back to runs', waitingForPlan: 'The task is queued and waiting for ExecutionPlan initialization. This page will keep its SSE connection and refresh automatically.', executionPlanWarnings: 'ExecutionPlan warnings', snapshotError: 'Unable to load the run snapshot. Check the run ID and API status.' },
      filters: { search: 'Search name or task ID', status: 'Status', taskType: 'Task type', allStages: 'All stages', allJobs: 'All jobs' },
      views: { mindMap: 'Mind map', dag: 'Actual DAG', taskList: 'Task list', mindMapHint: 'All Skill descendants are expanded by default. Double-click a node with descendants to collapse or expand its branch.', showStageOrder: 'Show execution-order edges' },
      taskTable: { task: 'Task', description: 'Description', type: 'Type', stage: 'Stage', job: 'Job', updatedAt: 'Updated at', reason: 'Reason' },
      taskDetail: { title: 'Task details', name: 'Name', description: 'Description', taskId: 'Task ID', type: 'Type', status: 'Status', phase: 'Phase', stageJob: 'Stage / Job', attempt: 'Attempt', startedAt: 'Started at', updatedAt: 'Updated at', finishedAt: 'Finished at', duration: 'Duration', reason: 'Reason', message: 'Message', error: 'Error', binaryPath: 'Binary path', expectedInputs: 'Expected inputs', expectedOutputs: 'Expected outputs', executionPlanData: 'ExecutionPlan data', eventPayload: 'Event payload', dependencies: 'Dependencies', dependents: 'Dependents', seconds: '{{count}} sec' },
      graph: { descendants: '{{count}} descendants', noMatchingNodes: 'No matching nodes in the current scope' },
      symbols: {
        title: 'Explore Symbols', subtitle: 'Browse versioned game symbol snapshots and search across modules and platforms.', gameVersion: 'Game version',
        treeTitle: 'Symbol tree', searchTitle: 'Find symbols', allModules: 'All modules', searchPlaceholder: 'Search symbol name or artifact', allPlatforms: 'All platforms',
        windows: 'Windows', linux: 'Linux', symbolName: 'Symbol', kind: 'Kind', module: 'Module', platform: 'Platform', artifact: 'Artifact', sourcePath: 'Snapshot path', aliases: 'Aliases',
        detailTitle: 'Symbol details', payload: 'Snapshot payload', loading: 'Loading symbol data…', indexError: 'Unable to load the symbol version index', datasetError: 'Unable to load this symbol snapshot',
        noSymbols: 'No symbols in this snapshot', noMatches: 'No symbols match the current filters', resultCount: '{{count}} records',
        versionMetadata: 'Last updated {{time}} · {{count}} symbols',
        signature: { func: 'Function Signature', vfunc: 'VirtualCall Signature', global: 'GlobalVariable Signature', structOffset: 'StructMemberOffset Signature' },
        vfuncIndex: 'VirtualFunction EntryIndex', vfuncOffset: 'VirtualFunction TableOffset', memberOffset: 'Struct Member Offset',
        kinds: { function: 'Function', virtualFunction: 'Virtual Function', global: 'Global Variable', vtable: 'VTable', structMember: 'Struct Member', patch: 'Patch', unknown: 'Unknown' },
      },
      gamedata: {
        title: 'Game Data', subtitle: 'Browse generated plugin gamedata by game version and inspect our upstream changes.', gameVersion: 'Game version', versionMetadata: '{{count}} files · {{metadata}} with diff metadata',
        treeTitle: 'Plugin files', viewerTitle: 'Gamedata viewer', viewDiff: 'View diff', download: 'Download', coveredCount: '{{covered}} / {{total}} covered', updatedCount: '{{updated}} updated',
        coveredLegend: 'Covered by our snapshot', updatedLegend: 'Updated from upstream', noMetadata: 'This version or file has no schema-v2 diff metadata.', noFiles: 'No gamedata files in this version.',
        loading: 'Loading gamedata…', indexError: 'Unable to load the gamedata version index', fileError: 'Unable to load this gamedata file', metadataError: 'Unable to load diff metadata',
        unanchoredChanges: '{{count}} deleted changes have no line in the final file.', viewerAria: 'Read-only gamedata viewer for {{file}}',
      },
    },
  },
  'zh-CN': {
    translation: {
      language: { selector: '语言', english: 'English', simplifiedChinese: '简体中文', traditionalChinese: '繁體中文' },
      common: { notAvailable: '—' },
      errors: { connectionFailed: '连接失败', invalidApiAddress: 'API 地址无效', apiHttpOnly: 'API 地址只支持 HTTP 或 HTTPS', apiAddressParts: 'API 地址不能包含账号、密码、查询参数或锚点', requestFailed: '请求失败', cannotConnectApi: '无法连接 API' },
      app: { pageTitle: 'CS2 VibeSignatures 流程面板', apiSettings: 'API 设置', loadingPage: '正在加载页面…' },
      navigation: { runs: '分析任务', symbols: '浏览符号', gamedata: '游戏数据' },
      settings: { title: 'API 连接设置', baseUrl: 'FastAPI Base URL', help: '公网 Pages 中的请求由当前浏览器发起。默认地址只会访问当前电脑的 127.0.0.1，不能访问另一台机器的 localhost。', saveAndReconnect: '保存并重新连接', disconnect: '断开当前连接' },
      connection: { redisUnavailable: 'FastAPI 已启动，但 Redis 尚未就绪。请检查 Redis 地址和服务状态。', hint: '请确认 FastAPI 已启动、Pages Origin 已加入 CORS allowlist，并允许浏览器访问本地网络。', title: '连接本地进度 API', descriptionBefore: '页面将从当前浏览器连接 ', descriptionAfter: '，并检查 FastAPI 与 Redis 可用性。', connect: '连接本地 API', changeAddress: '修改地址' },
      status: { queued: '排队中', starting: '启动中', pending: '等待中', running: '运行中', succeeded: '成功', failed: '失败', skipped: '跳过', aborted: '中止', stale: '失联' },
      phase: { label: '阶段', preflight: '预检', waiting_for_mcp: '等待 MCP', validating_binary: '验证二进制文件', validating_inputs: '验证输入', preprocessing: '预处理', validating_outputs: '验证输出', agent_fallback: 'Agent 回退', vcall_export: '虚函数调用导出', postprocessing: '后处理', finished: '已完成' },
      runs: { title: '分析任务', subtitle: 'Redis Process Reporter 历史与实时状态', refresh: '刷新', run: 'Run', status: '状态', version: '版本', agent: 'Agent', progress: '进度', currentTask: '当前任务', createdAt: '创建时间', allStatuses: '全部状态', gameVersion: 'Game version', loadMore: '加载更多', redisUnavailable: 'Redis 状态服务不可用。', error: '无法读取 Run 列表，请检查 API 地址、CORS 和本地网络访问权限。' },
      detail: { sseConnecting: 'SSE 连接中', sseConnected: 'SSE 已连接', sseReconnecting: 'SSE 重连中', sseClosed: 'SSE 已关闭', noCurrentTask: '当前没有正在执行的任务', progressSummary: '成功 {{succeeded}} · 失败 {{failed}} · 跳过 {{skipped}} · 中止 {{aborted}}', refreshSnapshot: '刷新快照', backToRuns: '返回 Run 列表', waitingForPlan: '任务已排队，等待 ExecutionPlan 初始化；页面会保持 SSE 连接并自动刷新。', executionPlanWarnings: 'ExecutionPlan 警告', snapshotError: '无法读取 Run Snapshot，请检查 Run ID 和 API 状态。' },
      filters: { search: '搜索名称或 Task ID', status: '状态', taskType: '任务类型', allStages: '全部 Stage', allJobs: '全部 Job' },
      views: { mindMap: '思维导图', dag: '真实 DAG', taskList: '任务列表', mindMapHint: '默认展开全部 Skill 子代；双击有后代的节点可折叠或重新展开分支。', showStageOrder: '显示执行顺序边' },
      taskTable: { task: '任务', description: '描述', type: '类型', stage: 'Stage', job: 'Job', updatedAt: '更新时间', reason: '原因' },
      taskDetail: { title: '任务详情', name: '名称', description: '描述', taskId: 'Task ID', type: '类型', status: '状态', phase: '阶段', stageJob: 'Stage / Job', attempt: '尝试次数', startedAt: '开始时间', updatedAt: '更新时间', finishedAt: '结束时间', duration: '耗时', reason: '原因', message: '消息', error: '错误', binaryPath: '二进制路径', expectedInputs: '预期输入', expectedOutputs: '预期输出', executionPlanData: 'ExecutionPlan 数据', eventPayload: '事件载荷', dependencies: '依赖项', dependents: '依赖方', seconds: '{{count}} 秒' },
      graph: { descendants: '{{count}} 个后代', noMatchingNodes: '当前范围没有匹配节点' },
      symbols: {
        title: '浏览符号', subtitle: '浏览按游戏版本保存的符号快照，并按模块和平台查找特定符号。', gameVersion: '游戏版本',
        treeTitle: '符号树', searchTitle: '查找符号', allModules: '全部模块', searchPlaceholder: '搜索符号名或 Artifact', allPlatforms: '全部平台',
        windows: 'Windows', linux: 'Linux', symbolName: '符号名', kind: '类型', module: '模块', platform: '平台', artifact: 'Artifact', sourcePath: '快照路径', aliases: '别名',
        detailTitle: '符号详情', payload: '快照数据', loading: '正在加载符号数据…', indexError: '无法加载符号版本索引', datasetError: '无法加载当前符号快照',
        noSymbols: '当前快照没有符号', noMatches: '没有符号符合当前筛选条件', resultCount: '共 {{count}} 条记录',
        versionMetadata: '最后更新 {{time}} · {{count}} 个符号',
        signature: { func: '函数特征码', vfunc: '间接调用特征码', global: '全局变量特征码', structOffset: '结构偏移特征码' },
        vfuncIndex: '虚表内索引', vfuncOffset: '虚表内偏移', memberOffset: '结构体成员偏移',
        kinds: { function: '函数', virtualFunction: '虚函数', global: '全局变量', vtable: '虚表', structMember: '结构体成员', patch: '补丁', unknown: '未知' },
      },
      gamedata: {
        title: '游戏数据', subtitle: '按游戏版本浏览各插件的 gamedata，并查看我们相对上游所做的修改。', gameVersion: '游戏版本', versionMetadata: '{{count}} 个文件 · {{metadata}} 个带 Diff 元数据',
        treeTitle: '插件文件', viewerTitle: 'Gamedata 查看器', viewDiff: '查看 Diff', download: '下载', coveredCount: '覆盖 {{covered}} / {{total}}', updatedCount: '更新 {{updated}}',
        coveredLegend: '由我们的快照覆盖', updatedLegend: '相对上游已更新', noMetadata: '当前版本或文件没有 schema v2 Diff 元数据。', noFiles: '当前版本没有 gamedata 文件。',
        loading: '正在加载游戏数据…', indexError: '无法加载游戏数据版本索引', fileError: '无法加载当前 gamedata 文件', metadataError: '无法加载 Diff 元数据',
        unanchoredChanges: '{{count}} 个删除项在最终文件中没有可高亮行。', viewerAria: '{{file}} 的只读 gamedata 查看器',
      },
    },
  },
  'zh-TW': {
    translation: {
      language: { selector: '語言', english: 'English', simplifiedChinese: '簡體中文', traditionalChinese: '繁體中文' },
      common: { notAvailable: '—' },
      errors: { connectionFailed: '連線失敗', invalidApiAddress: 'API 位址無效', apiHttpOnly: 'API 位址僅支援 HTTP 或 HTTPS', apiAddressParts: 'API 位址不能包含帳號、密碼、查詢參數或錨點', requestFailed: '請求失敗', cannotConnectApi: '無法連線至 API' },
      app: { pageTitle: 'CS2 VibeSignatures 流程儀表板', apiSettings: 'API 設定', loadingPage: '正在載入頁面…' },
      navigation: { runs: '分析任務', symbols: '瀏覽符號', gamedata: '遊戲資料' },
      settings: { title: 'API 連線設定', baseUrl: 'FastAPI Base URL', help: '公開 Pages 的請求由目前瀏覽器發出。預設位址僅會連到本機的 127.0.0.1，無法連到另一台電腦的 localhost。', saveAndReconnect: '儲存並重新連線', disconnect: '中斷目前連線' },
      connection: { redisUnavailable: 'FastAPI 已啟動，但 Redis 尚未就緒。請檢查 Redis 位址與服務狀態。', hint: '請確認 FastAPI 已啟動、Pages Origin 已加入 CORS allowlist，且瀏覽器獲准存取本機網路。', title: '連線至本機進度 API', descriptionBefore: '頁面將從目前瀏覽器連線至 ', descriptionAfter: '，並檢查 FastAPI 與 Redis 可用性。', connect: '連線至本機 API', changeAddress: '變更位址' },
      status: { queued: '排隊中', starting: '啟動中', pending: '等待中', running: '執行中', succeeded: '成功', failed: '失敗', skipped: '略過', aborted: '中止', stale: '失聯' },
      phase: { label: '階段', preflight: '預檢', waiting_for_mcp: '等待 MCP', validating_binary: '驗證二進位檔', validating_inputs: '驗證輸入', preprocessing: '預先處理', validating_outputs: '驗證輸出', agent_fallback: 'Agent 備援', vcall_export: '虛擬函式呼叫匯出', postprocessing: '後處理', finished: '已完成' },
      runs: { title: '分析任務', subtitle: 'Redis Process Reporter 歷程與即時狀態', refresh: '重新整理', run: 'Run', status: '狀態', version: '版本', agent: 'Agent', progress: '進度', currentTask: '目前任務', createdAt: '建立時間', allStatuses: '所有狀態', gameVersion: 'Game version', loadMore: '載入更多', redisUnavailable: 'Redis 狀態服務無法使用。', error: '無法讀取 Run 清單，請檢查 API 位址、CORS 與本機網路存取權限。' },
      detail: { sseConnecting: 'SSE 連線中', sseConnected: 'SSE 已連線', sseReconnecting: 'SSE 重新連線中', sseClosed: 'SSE 已關閉', noCurrentTask: '目前沒有正在執行的任務', progressSummary: '成功 {{succeeded}} · 失敗 {{failed}} · 略過 {{skipped}} · 中止 {{aborted}}', refreshSnapshot: '重新整理快照', backToRuns: '返回 Run 清單', waitingForPlan: '任務已排隊，等待 ExecutionPlan 初始化；頁面會維持 SSE 連線並自動重新整理。', executionPlanWarnings: 'ExecutionPlan 警告', snapshotError: '無法讀取 Run Snapshot，請檢查 Run ID 與 API 狀態。' },
      filters: { search: '搜尋名稱或 Task ID', status: '狀態', taskType: '任務類型', allStages: '所有 Stage', allJobs: '所有 Job' },
      views: { mindMap: '心智圖', dag: '實際 DAG', taskList: '任務清單', mindMapHint: '預設展開所有 Skill 後代；雙擊有後代的節點可摺疊或重新展開分支。', showStageOrder: '顯示執行順序邊' },
      taskTable: { task: '任務', description: '描述', type: '類型', stage: 'Stage', job: 'Job', updatedAt: '更新時間', reason: '原因' },
      taskDetail: { title: '任務詳情', name: '名稱', description: '描述', taskId: 'Task ID', type: '類型', status: '狀態', phase: '階段', stageJob: 'Stage / Job', attempt: '嘗試次數', startedAt: '開始時間', updatedAt: '更新時間', finishedAt: '結束時間', duration: '耗時', reason: '原因', message: '訊息', error: '錯誤', binaryPath: '二進位檔路徑', expectedInputs: '預期輸入', expectedOutputs: '預期輸出', executionPlanData: 'ExecutionPlan 資料', eventPayload: '事件承載資料', dependencies: '相依項目', dependents: '相依方', seconds: '{{count}} 秒' },
      graph: { descendants: '{{count}} 個後代', noMatchingNodes: '目前範圍沒有符合的節點' },
      symbols: {
        title: '瀏覽符號', subtitle: '瀏覽依遊戲版本保存的符號快照，並依模組和平台查找特定符號。', gameVersion: '遊戲版本',
        treeTitle: '符號樹', searchTitle: '查找符號', allModules: '所有模組', searchPlaceholder: '搜尋符號名稱或 Artifact', allPlatforms: '所有平台',
        windows: 'Windows', linux: 'Linux', symbolName: '符號名稱', kind: '類型', module: '模組', platform: '平台', artifact: 'Artifact', sourcePath: '快照路徑', aliases: '別名',
        detailTitle: '符號詳情', payload: '快照資料', loading: '正在載入符號資料…', indexError: '無法載入符號版本索引', datasetError: '無法載入目前符號快照',
        noSymbols: '目前快照沒有符號', noMatches: '沒有符號符合目前篩選條件', resultCount: '共 {{count}} 筆記錄',
        versionMetadata: '最後更新 {{time}} · {{count}} 個符號',
        signature: { func: '函式特徵碼', vfunc: '間接調用特徵碼', global: '全域變數特徵碼', structOffset: '結構成員偏移量特徵碼' },
        vfuncIndex: '虛擬表內索引', vfuncOffset: '虛擬表內偏移', memberOffset: '結構成員偏移量',
        kinds: { function: '函式', virtualFunction: '虛擬函式', global: '全域變數', vtable: '虛擬表', structMember: '結構成員', patch: '修補', unknown: '未知' },
      },
      gamedata: {
        title: '遊戲資料', subtitle: '依遊戲版本瀏覽各外掛的 gamedata，並查看我們相對上游所做的修改。', gameVersion: '遊戲版本', versionMetadata: '{{count}} 個檔案 · {{metadata}} 個含 Diff 中繼資料',
        treeTitle: '外掛檔案', viewerTitle: 'Gamedata 檢視器', viewDiff: '查看 Diff', download: '下載', coveredCount: '覆蓋 {{covered}} / {{total}}', updatedCount: '更新 {{updated}}',
        coveredLegend: '由我們的快照覆蓋', updatedLegend: '相對上游已更新', noMetadata: '目前版本或檔案沒有 schema v2 Diff 中繼資料。', noFiles: '目前版本沒有 gamedata 檔案。',
        loading: '正在載入遊戲資料…', indexError: '無法載入遊戲資料版本索引', fileError: '無法載入目前 gamedata 檔案', metadataError: '無法載入 Diff 中繼資料',
        unanchoredChanges: '{{count}} 個刪除項目在最終檔案中沒有可標示行。', viewerAria: '{{file}} 的唯讀 gamedata 檢視器',
      },
    },
  },
} as const

export function resolveLanguage(language?: string): AppLanguage {
  const normalized = language?.toLowerCase()
  if (normalized === 'zh-tw' || normalized === 'zh-hk' || normalized === 'zh-mo' || normalized === 'zh-hant') return 'zh-TW'
  if (normalized?.startsWith('zh')) return 'zh-CN'
  return 'en'
}

function initialLanguage(): AppLanguage {
  const saved = localStorage.getItem(LANGUAGE_STORAGE_KEY)
  if (saved) return resolveLanguage(saved)
  return resolveLanguage(navigator.languages?.[0] || navigator.language)
}

function updateDocumentLanguage(language?: string): void {
  document.documentElement.lang = resolveLanguage(language)
  document.title = i18n.t('app.pageTitle')
}

i18n.on('languageChanged', updateDocumentLanguage)

void i18n.use(initReactI18next).init({
  resources,
  lng: initialLanguage(),
  fallbackLng: 'en',
  supportedLngs: APP_LANGUAGES,
  interpolation: { escapeValue: false },
  react: { useSuspense: false },
}).then(() => updateDocumentLanguage(i18n.resolvedLanguage))

export async function changeLanguage(language: AppLanguage): Promise<void> {
  localStorage.setItem(LANGUAGE_STORAGE_KEY, language)
  await i18n.changeLanguage(language)
}

export default i18n
