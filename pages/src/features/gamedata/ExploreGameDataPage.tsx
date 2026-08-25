import { DownloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Checkbox, Select, Space, Spin, Tag, Tooltip, Typography } from 'antd'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getGameDataFile, getGameDataIndex, getGameDataMetadata } from './data'
import { buildGameDataDiffLineModel } from './diffModel'
import { GameDataTree } from './GameDataTree'
import { GameDataViewer } from './GameDataViewer'
import type { GameDataFileDescriptor } from './types'

export function ExploreGameDataPage() {
  const { t } = useTranslation()
  const [selectedVersion, setSelectedVersion] = useState<string>()
  const [selectedFileId, setSelectedFileId] = useState<string>()
  const [diffEnabled, setDiffEnabled] = useState(true)
  const indexQuery = useQuery({
    queryKey: ['gamedata', 'index'],
    queryFn: ({ signal }) => getGameDataIndex(signal),
    staleTime: 5 * 60 * 1000,
  })
  const gameVersion = selectedVersion ?? indexQuery.data?.versions[0]?.gameVersion
  const versionEntry = indexQuery.data?.versions.find((version) => version.gameVersion === gameVersion)
  const selectedFile = versionEntry?.files.find((file) => file.id === selectedFileId) ?? versionEntry?.files[0]
  const fileQuery = useQuery({
    queryKey: ['gamedata', gameVersion, selectedFile?.id, selectedFile?.content.url],
    queryFn: ({ signal }) => getGameDataFile(selectedFile!, signal),
    enabled: Boolean(selectedFile),
    staleTime: Infinity,
  })
  const canDiff = selectedFile?.metadata?.schemaVersion === 2
  const lineCount = fileQuery.data?.split('\n').length ?? 0
  const metadataQuery = useQuery({
    queryKey: ['gamedata', gameVersion, selectedFile?.id, selectedFile?.metadata?.url],
    queryFn: ({ signal }) => getGameDataMetadata(selectedFile!, lineCount, gameVersion!, signal),
    enabled: Boolean(diffEnabled && canDiff && fileQuery.data && gameVersion),
    staleTime: Infinity,
  })
  const diffModel = useMemo(
    () => buildGameDataDiffLineModel(diffEnabled ? metadataQuery.data : undefined),
    [diffEnabled, metadataQuery.data],
  )

  function changeVersion(version: string) {
    const nextVersion = indexQuery.data?.versions.find((entry) => entry.gameVersion === version)
    setSelectedVersion(version)
    setSelectedFileId((current) => nextVersion?.files.some((file) => file.id === current) ? current : nextVersion?.files[0]?.id)
    setDiffEnabled(false)
  }

  function selectFile(file: GameDataFileDescriptor) {
    setSelectedFileId(file.id)
    if (file.metadata?.schemaVersion !== 2) setDiffEnabled(false)
  }

  function downloadSelectedFile() {
    if (!selectedFile || !fileQuery.data) return
    const type = selectedFile.language === 'json' || selectedFile.language === 'jsonc' ? 'application/json' : 'text/plain'
    const blob = new Blob([fileQuery.data], { type })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = selectedFile.fileName
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  const diffControl = (
    <Checkbox
      checked={Boolean(diffEnabled && canDiff)}
      disabled={!canDiff}
      onChange={(event) => setDiffEnabled(event.target.checked)}
    >
      {t('gamedata.viewDiff')}
    </Checkbox>
  )

  return (
    <Space orientation="vertical" size="large" className="full-width">
      <div className="page-title-row">
        <div>
          <Typography.Title level={2}>{t('gamedata.title')}</Typography.Title>
          <Typography.Text type="secondary">{t('gamedata.subtitle')}</Typography.Text>
        </div>
        <div className="symbol-version-controls">
          {versionEntry && (
            <Typography.Text type="secondary" className="symbol-version-metadata">
              {t('gamedata.versionMetadata', { count: versionEntry.fileCount, metadata: versionEntry.metadataFileCount })}
            </Typography.Text>
          )}
          <Select
            showSearch
            optionFilterProp="label"
            aria-label={t('gamedata.gameVersion')}
            placeholder={t('gamedata.gameVersion')}
            value={gameVersion}
            loading={indexQuery.isLoading}
            onChange={changeVersion}
            options={indexQuery.data?.versions.map((version) => ({ value: version.gameVersion, label: version.gameVersion }))}
          />
        </div>
      </div>

      {indexQuery.error && <Alert type="error" showIcon message={t('gamedata.indexError')} description={indexQuery.error.message} />}
      {indexQuery.isLoading && <div className="page-spinner"><Spin size="large" tip={t('gamedata.loading')} /></div>}

      {versionEntry && (
        <div className="gamedata-browser-grid">
          <Card title={t('gamedata.treeTitle')} className="gamedata-tree-card">
            <GameDataTree files={versionEntry.files} selectedFileId={selectedFile?.id} onSelect={selectFile} />
          </Card>
          <Card
            title={selectedFile?.id ?? t('gamedata.viewerTitle')}
            className="gamedata-viewer-card"
            extra={selectedFile && (
              <Space wrap size="small">
                <Button
                  size="small"
                  icon={<DownloadOutlined />}
                  disabled={!fileQuery.data}
                  onClick={downloadSelectedFile}
                >
                  {t('gamedata.download')}
                </Button>
                {selectedFile.metadata && (
                  <>
                    <Tag color="blue">{t('gamedata.coveredCount', {
                      covered: selectedFile.metadata.summary.covered,
                      total: selectedFile.metadata.summary.total,
                    })}</Tag>
                    <Tag color="gold">{t('gamedata.updatedCount', { updated: selectedFile.metadata.summary.updated })}</Tag>
                  </>
                )}
                {canDiff ? diffControl : <Tooltip title={t('gamedata.noMetadata')}><span>{diffControl}</span></Tooltip>}
                {metadataQuery.isFetching && <Spin size="small" />}
              </Space>
            )}
          >
            {fileQuery.error && <Alert className="gamedata-inline-alert" type="error" showIcon message={t('gamedata.fileError')} description={fileQuery.error.message} />}
            {fileQuery.isLoading && <div className="page-spinner"><Spin size="large" tip={t('gamedata.loading')} /></div>}
            {metadataQuery.error && <Alert className="gamedata-inline-alert" type="error" showIcon message={t('gamedata.metadataError')} description={metadataQuery.error.message} />}
            {diffEnabled && metadataQuery.data && (
              <div className="gamedata-diff-legend">
                <span><i className="gamedata-covered-swatch" />{t('gamedata.coveredLegend')}</span>
                <span><i className="gamedata-updated-swatch" />{t('gamedata.updatedLegend')}</span>
              </div>
            )}
            {diffModel.unanchoredChanges.length > 0 && (
              <Alert
                className="gamedata-inline-alert"
                type="warning"
                showIcon
                message={t('gamedata.unanchoredChanges', { count: diffModel.unanchoredChanges.length })}
              />
            )}
            {selectedFile && fileQuery.data && (
              <GameDataViewer
                content={fileQuery.data}
                language={selectedFile.language}
                metadata={metadataQuery.data}
                diffEnabled={Boolean(diffEnabled && metadataQuery.data)}
                ariaLabel={t('gamedata.viewerAria', { file: selectedFile.id })}
              />
            )}
          </Card>
        </div>
      )}
    </Space>
  )
}
