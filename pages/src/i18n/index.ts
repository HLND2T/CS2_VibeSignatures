import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

export const APP_LANGUAGES = ['en', 'zh-CN', 'zh-TW'] as const
export type AppLanguage = (typeof APP_LANGUAGES)[number]

const LANGUAGE_STORAGE_KEY = 'cs2vibe.language'

const resources = {
  en: {
    translation: {
      language: { selector: 'Language', english: 'English', simplifiedChinese: 'Simplified Chinese', traditionalChinese: 'Traditional Chinese' },
      theme: { toggle: 'Toggle color theme', switchToLight: 'Switch to light mode', switchToDark: 'Switch to dark mode' },
      common: { notAvailable: '—' },
      app: { pageTitle: 'CS2 VibeSignatures', loadingPage: 'Loading page…' },
      navigation: { symbols: 'Explore Symbols', gamedata: 'Game Data' },
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
      theme: { toggle: '切换颜色主题', switchToLight: '切换到浅色模式', switchToDark: '切换到深色模式' },
      common: { notAvailable: '—' },
      app: { pageTitle: 'CS2 VibeSignatures', loadingPage: '正在加载页面…' },
      navigation: { symbols: '浏览符号', gamedata: '游戏数据' },
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
      theme: { toggle: '切換顏色主題', switchToLight: '切換到淺色模式', switchToDark: '切換到深色模式' },
      common: { notAvailable: '—' },
      app: { pageTitle: 'CS2 VibeSignatures', loadingPage: '正在載入頁面…' },
      navigation: { symbols: '瀏覽符號', gamedata: '遊戲資料' },
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
