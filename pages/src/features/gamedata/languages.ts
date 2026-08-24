import { StreamLanguage, type StreamParser, type StringStream } from '@codemirror/language'
import { json } from '@codemirror/lang-json'
import type { Extension } from '@codemirror/state'
import type { GameDataLanguage } from './types'

interface CommentState {
  blockComment: boolean
}

function quotedString(stream: StringStream): boolean {
  if (stream.peek() !== '"') return false
  stream.next()
  let escaped = false
  while (!stream.eol()) {
    const character = stream.next()
    if (character === '"' && !escaped) break
    escaped = character === '\\' && !escaped
    if (character !== '\\') escaped = false
  }
  return true
}

function commentToken(stream: StringStream, state: CommentState): string | null | undefined {
  if (state.blockComment) {
    if (stream.skipTo('*/')) {
      stream.match('*/')
      state.blockComment = false
    } else {
      stream.skipToEnd()
    }
    return 'comment'
  }
  if (stream.match('//')) {
    stream.skipToEnd()
    return 'comment'
  }
  if (stream.match('/*')) {
    state.blockComment = true
    return commentToken(stream, state)
  }
  return undefined
}

const jsoncParser: StreamParser<CommentState> = {
  startState: () => ({ blockComment: false }),
  token(stream, state) {
    if (stream.eatSpace()) return null
    const comment = commentToken(stream, state)
    if (comment !== undefined) return comment
    if (quotedString(stream)) return 'string'
    if (stream.match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/)) return 'number'
    if (stream.match(/^(?:true|false)\b/)) return 'bool'
    if (stream.match(/^null\b/)) return 'null'
    const punctuation = stream.peek()
    if (punctuation && '{}[],:'.includes(punctuation)) {
      stream.next()
      return 'punctuation'
    }
    stream.next()
    return null
  },
}

const vdfParser: StreamParser<null> = {
  token(stream) {
    if (stream.eatSpace()) return null
    if (stream.match('//')) {
      stream.skipToEnd()
      return 'comment'
    }
    if (quotedString(stream)) return 'string'
    if (stream.match(/^[{}]/)) return 'bracket'
    stream.next()
    return null
  },
}

const flatParser: StreamParser<null> = {
  token(stream) {
    if (stream.eatSpace()) return null
    if (stream.match(/^[a-z0-9_]+(?=\s*=)/i)) return 'propertyName'
    if (stream.match('=')) return 'operator'
    if (stream.match(/^[+-]?\d+/)) return 'number'
    if (stream.match(/^[#;]/)) {
      stream.skipToEnd()
      return 'comment'
    }
    stream.next()
    return null
  },
}

const jsoncLanguage = StreamLanguage.define(jsoncParser)
const vdfLanguage = StreamLanguage.define(vdfParser)
const flatLanguage = StreamLanguage.define(flatParser)

export function gameDataLanguageExtension(language: GameDataLanguage): Extension {
  if (language === 'json') return json()
  if (language === 'jsonc') return jsoncLanguage
  if (language === 'vdf') return vdfLanguage
  return flatLanguage
}
