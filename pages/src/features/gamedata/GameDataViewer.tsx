import { defaultHighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { EditorState, type Extension } from '@codemirror/state'
import { Decoration, EditorView, hoverTooltip, lineNumbers, type DecorationSet } from '@codemirror/view'
import { useEffect, useMemo, useRef } from 'react'
import { useTheme } from '../../theme/themeContext'
import { buildGameDataDiffLineModel, formatChangePath, formatChangeValue } from './diffModel'
import { gameDataLanguageExtension } from './languages'
import type { GameDataLanguage, GameDataMetadata } from './types'

interface Props {
  content: string
  language: GameDataLanguage
  metadata?: GameDataMetadata
  diffEnabled: boolean
  ariaLabel: string
}

function lineDecorations(state: EditorState, model: ReturnType<typeof buildGameDataDiffLineModel>): DecorationSet {
  const ranges = []
  for (const lineNumber of model.coveredLines) {
    if (model.updatedLines.has(lineNumber) || lineNumber > state.doc.lines) continue
    ranges.push(Decoration.line({ class: 'gamedata-line-covered' }).range(state.doc.line(lineNumber).from))
  }
  for (const lineNumber of model.updatedLines.keys()) {
    if (lineNumber > state.doc.lines) continue
    ranges.push(Decoration.line({ class: 'gamedata-line-updated' }).range(state.doc.line(lineNumber).from))
  }
  return Decoration.set(ranges, true)
}

function tooltipExtension(model: ReturnType<typeof buildGameDataDiffLineModel>): Extension {
  return hoverTooltip((view, position) => {
    const line = view.state.doc.lineAt(position)
    const changes = model.updatedLines.get(line.number)
    if (!changes?.length) return null
    return {
      pos: line.from,
      end: line.to,
      above: true,
      create() {
        const dom = document.createElement('div')
        dom.className = 'gamedata-diff-tooltip'
        for (const change of changes) {
          const block = document.createElement('div')
          block.className = 'gamedata-diff-change'
          const path = document.createElement('strong')
          path.textContent = formatChangePath(change.path)
          const before = document.createElement('div')
          before.textContent = `− ${formatChangeValue(change.before)}`
          before.className = 'gamedata-diff-before'
          const after = document.createElement('div')
          after.textContent = `+ ${formatChangeValue(change.after)}`
          after.className = 'gamedata-diff-after'
          block.append(path, before, after)
          dom.append(block)
        }
        return { dom }
      },
    }
  }, { hoverTime: 150 })
}

export function GameDataViewer({ content, language, metadata, diffEnabled, ariaLabel }: Props) {
  const host = useRef<HTMLDivElement>(null)
  const { theme } = useTheme()
  const model = useMemo(
    () => buildGameDataDiffLineModel(diffEnabled ? metadata : undefined),
    [diffEnabled, metadata],
  )

  useEffect(() => {
    if (!host.current) return
    const baseExtensions: Extension[] = [
      lineNumbers(),
      EditorState.readOnly.of(true),
      EditorView.editable.of(false),
      gameDataLanguageExtension(language),
      syntaxHighlighting(defaultHighlightStyle),
      EditorView.theme({
        '&': { height: '100%', backgroundColor: 'var(--editor-bg)', color: 'var(--editor-fg)' },
        '.cm-scroller': { overflow: 'auto', fontFamily: '"Cascadia Code", Consolas, monospace', fontSize: '12px' },
        '.cm-content': { minWidth: 'max-content', padding: '12px 0' },
        '.cm-line': { padding: '0 14px' },
        '.cm-gutters': { backgroundColor: 'var(--editor-gutter-bg)', color: 'var(--editor-gutter-fg)', borderRight: '1px solid var(--panel-border)' },
        '.cm-activeLineGutter': { backgroundColor: 'transparent' },
        '&.cm-focused': { outline: 'none' },
      }, { dark: theme === 'dark' }),
    ]
    const state = EditorState.create({ doc: content, extensions: baseExtensions })
    const extensions: Extension[] = [
      ...baseExtensions,
      EditorView.decorations.of(lineDecorations(state, model)),
      tooltipExtension(model),
    ]
    const view = new EditorView({
      state: EditorState.create({ doc: content, extensions }),
      parent: host.current,
    })
    return () => view.destroy()
  }, [content, language, model, theme])

  return <div ref={host} className="gamedata-viewer" role="region" aria-label={ariaLabel} />
}
