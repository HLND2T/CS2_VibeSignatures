import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'

const run = {
  run_id: 'run-1', status: 'running', effective_status: 'running', is_stale: false,
  heartbeat_alive: true, gamever: '14141', agent: 'codex', created_at: '2026-07-13T00:00:00Z',
  started_at: null, updated_at: '2026-07-13T00:00:01Z', finished_at: null,
  current_stage_id: null, current_job_id: null, current_skill_id: null, last_event_id: '1-0',
  error_summary: null,
  progress: { total: 0, pending: 0, running: 0, succeeded: 0, failed: 0, skipped: 0, aborted: 0, completed: 0, percent: 0 },
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('cs2vibe.apiConnected:http://127.0.0.1:8000', 'true')
    localStorage.setItem('cs2vibe.language', 'zh-CN')
  })
  await page.route('**/api/v1/runs?**', (route) => route.fulfill({ json: { items: [run], offset: 0, next_offset: null, has_more: false } }))
  await page.route('**/api/v1/runs/run-1/snapshot', (route) => route.fulfill({ json: { run, graph: null, tasks: [], snapshot_event_id: '1-0' } }))
  await page.route('**/api/v1/runs/run-1/stream?**', (route) => route.fulfill({ contentType: 'text/event-stream', body: 'retry: 3000\n\n' }))
  await page.route('**/api/v1/runs/run-1', (route) => route.fulfill({ json: run }))
})

test('loads the run list from the runs route', async ({ page }) => {
  await page.goto('runs')
  await expect(page.getByRole('link', { name: 'run-1' })).toBeVisible()
})

test('loads a run detail through the SPA fallback route', async ({ page }) => {
  await page.goto('runs/run-1')
  await expect(page.getByText('run-1', { exact: true })).toBeVisible()
  await expect(page.getByText(/等待 ExecutionPlan 初始化/)).toBeVisible()
})

test('opens the static symbol browser without a Process API connection', async ({ page }) => {
  const indexResponse = await page.request.get('gamesymbols/index.json')
  expect(indexResponse.ok()).toBeTruthy()
  const index = await indexResponse.json()
  expect(index.schemaVersion).toBe(4)
  const currentVersion = index.versions[0]
  expect(currentVersion.sha256).toMatch(/^[0-9a-f]{64}$/)
  expect(currentVersion.url).toBe(`${currentVersion.gameVersion}.${currentVersion.sha256}.json`)
  expect(currentVersion.size).toBeGreaterThan(0)
  expect(currentVersion.lastPublishTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  const datasetResponse = await page.request.get(`gamesymbols/${currentVersion.url}`)
  expect(datasetResponse.ok()).toBeTruthy()
  const datasetBytes = await datasetResponse.body()
  expect(datasetBytes.byteLength).toBe(currentVersion.size)
  expect(createHash('sha256').update(datasetBytes).digest('hex')).toBe(currentVersion.sha256)
  const dataset = JSON.parse(datasetBytes.toString('utf8'))
  expect(dataset.schemaVersion).toBe(3)
  expect(dataset.source.lastPublishTime).toBe(currentVersion.lastPublishTime)
  expect(Object.keys(dataset.binaries).length).toBeGreaterThan(0)
  const firstBinary = Object.values(Object.values(dataset.binaries)[0] as Record<string, unknown>)[0] as Record<string, unknown>
  expect(firstBinary.sha256).toMatch(/^[0-9a-f]{64}$/)
  expect(firstBinary.md5).toMatch(/^[0-9a-f]{32}$/)
  expect(firstBinary.crc32).toMatch(/^[0-9a-f]{8}$/)
  expect(firstBinary.crc64).toMatch(/^[0-9a-f]{16}$/)
  expect(firstBinary.size).toEqual(expect.any(Number))

  await page.goto('symbols')
  await page.getByRole('button', { name: 'API 设置' }).click()
  await page.getByRole('button', { name: '断开当前连接' }).click()
  await page.keyboard.press('Escape')
  await page.getByRole('tab', { name: '分析任务' }).click()
  await expect(page.getByRole('heading', { name: '连接本地进度 API' })).toBeVisible()
  await page.getByRole('tab', { name: '浏览符号' }).click()
  await expect(page.getByRole('heading', { name: '浏览符号' })).toBeVisible()
  await expect(page.locator('.symbol-version-controls').getByText(currentVersion.gameVersion, { exact: true })).toBeVisible()
  await expect(page.getByText(new RegExp(`最后更新 \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} · ${currentVersion.fileCount} 个符号`))).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByLabel('游戏版本')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy()
})

test('switches the static application between supported languages', async ({ page }) => {
  await page.goto('runs')
  await page.getByLabel('语言').click()
  await page.locator('.ant-select-dropdown').getByText('English', { exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Analysis runs' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')

  await page.getByLabel('Language').click()
  await page.locator('.ant-select-dropdown').getByText('Traditional Chinese', { exact: true }).click()
  await expect(page.getByRole('heading', { name: '分析任務' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-TW')
})

test('switches between graph and list views and opens task details', async ({ page }) => {
  const jobId = 'stage-0000-engine-windows'
  const taskId = `${jobId}/find-target`
  const task = {
    task_id: taskId, task_type: 'skill', name: 'find-target', stage_id: 'stage-0000-engine',
    job_id: jobId, status: 'running', phase: 'preprocessing', reason: null, attempt: null,
    max_attempts: null, started_at: null, updated_at: null, finished_at: null, message: null,
    error: null, payload: {}, event_type: 'task.status_changed', revision: 1,
  }
  const graph = {
    schema_version: 1,
    stages: [{ id: 'stage-0000-engine', stage_index: 0, module_name: 'engine' }],
    jobs: [{ id: jobId, stage_id: 'stage-0000-engine', stage_index: 0, module_name: 'engine', platform: 'windows', binary_path: 'bin/engine2.dll' }],
    nodes: [{ id: taskId, job_id: jobId, stage_id: 'stage-0000-engine', name: 'find-target', node_type: 'skill', order: 0, layer: 0, data: { expected_output: ['target.yaml'] } }],
    edges: [], warnings: [],
  }
  await page.unroute('**/api/v1/runs/run-1/snapshot')
  await page.route('**/api/v1/runs/run-1/snapshot', (route) => route.fulfill({ json: { run: { ...run, current_job_id: jobId, current_skill_id: taskId }, graph, tasks: [task], snapshot_event_id: '1-0' } }))
  await page.route('**/api/v1/runs/run-1/tasks/**', (route) => route.fulfill({ json: { ...task, dependencies: [], dependents: [] } }))
  await page.goto('runs/run-1')
  await expect(page.getByText('思维导图')).toBeVisible()
  await expect(page.getByText('find-target', { exact: true }).first()).toBeVisible()
  await page.getByRole('tab', { name: '真实 DAG' }).click()
  await expect(page.locator('.graph-canvas')).toBeVisible()
  await page.getByRole('tab', { name: '任务列表' }).click()
  await page.getByRole('button', { name: 'find-target' }).click()
  await expect(page.getByText('任务详情')).toBeVisible()
  await expect(page.getByText(taskId, { exact: true })).toBeVisible()
})
