import { Empty, Tooltip, Tree } from 'antd'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { GameDataFileDescriptor } from './types'

interface Props {
  files: GameDataFileDescriptor[]
  selectedFileId?: string
  onSelect(file: GameDataFileDescriptor): void
}

export function GameDataTree({ files, selectedFileId, onSelect }: Props) {
  const { t } = useTranslation()
  const filesById = useMemo(() => new Map(files.map((file) => [file.id, file])), [files])
  const treeData = useMemo(() => {
    const plugins = new Map<string, GameDataFileDescriptor[]>()
    for (const file of files) {
      const entries = plugins.get(file.plugin) ?? []
      entries.push(file)
      plugins.set(file.plugin, entries)
    }
    return [...plugins.entries()].map(([plugin, pluginFiles]) => ({
      key: `plugin:${plugin}`,
      title: plugin,
      children: pluginFiles.map((file) => ({
        key: `file:${file.id}`,
        title: <Tooltip title={file.id}>{file.fileName}</Tooltip>,
        isLeaf: true,
      })),
    }))
  }, [files])
  if (files.length === 0) return <Empty description={t('gamedata.noFiles')} />
  return (
    <Tree
      blockNode
      showLine
      defaultExpandAll
      height={620}
      treeData={treeData}
      selectedKeys={selectedFileId ? [`file:${selectedFileId}`] : []}
      onSelect={(_, info) => {
        const key = String(info.node.key)
        if (!key.startsWith('file:')) return
        const file = filesById.get(key.slice('file:'.length))
        if (file) onSelect(file)
      }}
    />
  )
}
