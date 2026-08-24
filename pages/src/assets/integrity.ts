export interface IntegrityReference {
  sha256: string
  size: number
}

export async function requestJson(url: string, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(url, { signal, cache: 'no-cache' })
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`)
  return response.json() as Promise<unknown>
}

export async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(bytes))
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, '0')).join('')
}

export async function fetchVerifiedBytes(
  url: string,
  reference: IntegrityReference,
  signal?: AbortSignal,
): Promise<ArrayBuffer> {
  const response = await fetch(url, { signal })
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`)
  const bytes = await response.arrayBuffer()
  if (bytes.byteLength !== reference.size) {
    throw new Error(`Asset size mismatch: expected ${reference.size}, received ${bytes.byteLength}`)
  }
  const actualSha256 = await sha256Hex(bytes)
  if (actualSha256 !== reference.sha256) {
    throw new Error(`Asset SHA-256 mismatch: expected ${reference.sha256}, received ${actualSha256}`)
  }
  return bytes
}

export function decodeUtf8(bytes: ArrayBuffer): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
}
