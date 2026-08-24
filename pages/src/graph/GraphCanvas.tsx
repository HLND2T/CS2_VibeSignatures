import { Empty, Spin } from 'antd'
import type { TFunction } from 'i18next'
import { useEffect, useMemo, useState } from 'react'
import { Background, Controls, MarkerType, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react'
import { useTranslation } from 'react-i18next'
import { statusLabel } from '../components/status'
import { useTheme } from '../theme/themeContext'
import { layoutGraph, type NodePosition } from './layout'
import type { VisualEdge, VisualGraph, VisualNode } from './model'

const STATUS_COLORS: Record<string, string> = {
  pending: '#6b7280',
  running: '#2563eb',
  succeeded: '#16a34a',
  skipped: '#ca8a04',
  failed: '#dc2626',
  aborted: '#374151',
  stale: '#ea580c',
  queued: '#64748b',
  starting: '#0284c7',
}

const EDGE_COLORS: Record<string, string> = {
  hierarchy: '#64748b',
  artifact: '#14b8a6',
  prerequisite: '#a855f7',
  cross_stage_artifact: '#f97316',
  stage_order: '#6b7280',
}

function nodeLabel(node: VisualNode, t: TFunction) {
  return (
    <div className="flow-node-label">
      <strong title={node.id}>{node.label}</strong>
      <span>{node.subtitle} · {statusLabel(node.status, t)}</span>
      {node.description && <p className="flow-node-description" title={node.description}>{node.description}</p>}
      {node.descendantCount > 0 && <small>{t('graph.descendants', { count: node.descendantCount })}</small>}
    </div>
  )
}

function flowNode(node: VisualNode, position: NodePosition | undefined, selectedId: string | undefined, related: Set<string>, t: TFunction): Node {
  const color = STATUS_COLORS[node.status] || STATUS_COLORS.pending
  return {
    id: node.id,
    position: position || { x: 0, y: 0 },
    data: { label: nodeLabel(node, t) },
    selected: node.id === selectedId,
    className: node.status === 'running' ? 'flow-node-running' : undefined,
    style: { border: `2px solid ${color}`, borderColor: color, background: 'var(--graph-node-bg)', color: 'var(--graph-node-fg)', width: 220, minHeight: node.description ? 112 : 76, opacity: selectedId && !related.has(node.id) ? 0.3 : 1, boxShadow: node.id === selectedId ? `0 0 0 3px ${color}66` : undefined },
  }
}

function flowEdge(edge: VisualEdge, selectedId?: string): Edge {
  const highlighted = selectedId && [edge.source, edge.target].includes(selectedId)
  const color = EDGE_COLORS[edge.edgeType] || '#64748b'
  return {
    id: edge.id,
    source: edge.source,
    target: edge.target,
    animated: highlighted || edge.edgeType === 'cross_stage_artifact',
    markerEnd: { type: MarkerType.ArrowClosed, color },
    style: { stroke: color, strokeWidth: highlighted ? 3 : edge.secondary ? 1 : 2, strokeDasharray: edge.edgeType === 'stage_order' || edge.secondary ? '6 5' : undefined, opacity: selectedId && !highlighted ? 0.25 : edge.secondary ? 0.55 : 1 },
  }
}

interface Props {
  graph: VisualGraph
  selectedId?: string
  onSelect(id: string): void
  onToggleExpand?(id: string): void
}

export function GraphCanvas({ graph, selectedId, onSelect, onToggleExpand }: Props) {
  const [positions, setPositions] = useState<Record<string, NodePosition>>({})
  const [loading, setLoading] = useState(false)
  const { t } = useTranslation()
  const { theme } = useTheme()
  const topologyKey = useMemo(() => JSON.stringify({ n: graph.nodes.map((node) => node.id), e: graph.edges.filter((edge) => edge.layout).map((edge) => [edge.source, edge.target]) }), [graph])

  useEffect(() => {
    let active = true
    setLoading(true)
    void layoutGraph(graph).then((next) => active && setPositions(next)).finally(() => active && setLoading(false))
    return () => { active = false }
    // Layout depends on topology only; status-only changes must not move nodes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topologyKey])

  if (!graph.nodes.length) return <Empty description={t('graph.noMatchingNodes')} />
  const related = new Set<string>(selectedId ? [selectedId] : [])
  graph.edges.forEach((edge) => {
    if (selectedId && [edge.source, edge.target].includes(selectedId)) {
      related.add(edge.source)
      related.add(edge.target)
    }
  })
  const nodes = graph.nodes.map((node) => flowNode(node, positions[node.id], selectedId, related, t))
  const edges = graph.edges.map((edge) => flowEdge(edge, selectedId))
  return (
    <div className="graph-canvas">
      {loading && <Spin className="graph-loading" />}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        colorMode={theme}
        fitView
        minZoom={0.1}
        maxZoom={1.8}
        onNodeClick={(_, node) => onSelect(node.id)}
        onNodeDoubleClick={(_, node) => onToggleExpand?.(node.id)}
      >
        <MiniMap pannable zoomable nodeColor={(node) => String(node.style?.borderColor || '#64748b')} />
        <Controls />
        <Background gap={20} color="var(--graph-grid)" />
      </ReactFlow>
    </div>
  )
}
