import { createHash } from 'node:crypto'

export const GAME_VERSION_PATTERN = /^\d{4,10}[a-z]?$/
export const SHA256_PATTERN = /^[0-9a-f]{64}$/

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function compareGameVersions(left: string, right: string): number {
  const leftMatch = /^(\d+)([a-z]?)$/.exec(left)
  const rightMatch = /^(\d+)([a-z]?)$/.exec(right)
  if (!leftMatch || !rightMatch) return right.localeCompare(left)
  const numberDifference = Number(rightMatch[1]) - Number(leftMatch[1])
  if (numberDifference !== 0) return numberDifference
  return rightMatch[2].localeCompare(leftMatch[2])
}

export function sha256Bytes(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

export function sendBytes(
  response: import('node:http').ServerResponse,
  bytes: Uint8Array,
  contentType = 'application/json; charset=utf-8',
): void {
  response.statusCode = 200
  response.setHeader('Content-Type', contentType)
  response.setHeader('Cache-Control', 'no-cache')
  response.setHeader('Content-Length', bytes.byteLength)
  response.end(bytes)
}

export function sendJson(response: import('node:http').ServerResponse, value: unknown): void {
  sendBytes(response, Buffer.from(JSON.stringify(value), 'utf8'))
}
