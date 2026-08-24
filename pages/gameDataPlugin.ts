import { readFile, readdir } from 'node:fs/promises'
import { basename, extname, join, relative, sep } from 'node:path'
import type { Plugin } from 'vite'
import { validateGameDataIndex, validateGameDataMetadata } from './src/features/gamedata/schema'
import type {
  GameDataFileDescriptor,
  GameDataIndex,
  GameDataIndexVersion,
  GameDataLanguage,
} from './src/features/gamedata/types'
import {
  compareGameVersions,
  GAME_VERSION_PATTERN,
  sendBytes,
  sendJson,
  sha256Bytes,
} from './staticAssetPluginUtils'

const METADATA_SUFFIX = '.metadata.json'
const PAYLOAD_SUFFIXES = new Set(['.json', '.jsonc', '.txt'])

interface EncodedAsset {
  bytes: Uint8Array
  sha256: string
  size: number
  url: string
}

interface LoadedGameData {
  index: GameDataIndex
  assets: Map<string, EncodedAsset>
  sourceFiles: string[]
}

function posixRelative(root: string, path: string): string {
  return relative(root, path).split(sep).join('/')
}

async function walkFiles(root: string): Promise<string[]> {
  const result: string[] = []
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error(`${path}: symbolic links are not allowed in gamedata assets`)
      if (entry.isDirectory()) await visit(path)
      else if (entry.isFile()) result.push(path)
      else throw new Error(`${path}: unsupported filesystem entry`)
    }
  }
  await visit(root)
  return result
}

function decodeUtf8(bytes: Uint8Array, source: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch (error) {
    throw new Error(`${source}: payload is not valid UTF-8`, { cause: error })
  }
}

function detectLanguage(fileName: string, text: string): GameDataLanguage {
  if (fileName.endsWith('.json')) return 'json'
  if (fileName.endsWith('.jsonc')) return 'jsonc'
  return text.trimStart().startsWith('"') || text.trimStart().startsWith('{') ? 'vdf' : 'flat'
}

function encodeAsset(bytes: Uint8Array, url: string): EncodedAsset {
  return { bytes, sha256: sha256Bytes(bytes), size: bytes.byteLength, url }
}

function addAsset(assets: Map<string, EncodedAsset>, asset: EncodedAsset): void {
  const existing = assets.get(asset.url)
  if (existing && !Buffer.from(existing.bytes).equals(Buffer.from(asset.bytes))) {
    throw new Error(`${asset.url}: content-address collision`)
  }
  assets.set(asset.url, existing ?? asset)
}

function payloadUrl(bytes: Uint8Array, suffix: string): string {
  return `payloads/${sha256Bytes(bytes)}${suffix}`
}

function metadataUrl(bytes: Uint8Array): string {
  return `metadata/${sha256Bytes(bytes)}.json`
}

export async function loadGameDataAssets(gamedataDirectory: string): Promise<LoadedGameData> {
  const rootEntries = await readdir(gamedataDirectory, { withFileTypes: true })
  const versionDirectories = rootEntries
    .filter((entry) => entry.isDirectory() && GAME_VERSION_PATTERN.test(entry.name))
    .map((entry) => ({ gameVersion: entry.name, path: join(gamedataDirectory, entry.name) }))
    .sort((left, right) => compareGameVersions(left.gameVersion, right.gameVersion))
  if (versionDirectories.length === 0) throw new Error(`${gamedataDirectory}: no versioned gamedata directories found`)

  const assets = new Map<string, EncodedAsset>()
  const sourceFiles: string[] = []
  const versions: GameDataIndexVersion[] = []
  for (const version of versionDirectories) {
    const files = await walkFiles(version.path)
    sourceFiles.push(...files)
    const relativeFiles = new Map(files.map((path) => [posixRelative(version.path, path), path]))
    const payloadPaths = [...relativeFiles.keys()].filter((path) => !path.endsWith(METADATA_SUFFIX))
    const metadataPaths = [...relativeFiles.keys()].filter((path) => path.endsWith(METADATA_SUFFIX))
    for (const path of metadataPaths) {
      if (!relativeFiles.has(path.slice(0, -METADATA_SUFFIX.length))) {
        throw new Error(`${version.gameVersion}/${path}: orphan metadata companion`)
      }
    }

    const descriptors: GameDataFileDescriptor[] = []
    for (const id of payloadPaths.sort((left, right) => left.localeCompare(right))) {
      const sourcePath = relativeFiles.get(id)!
      const suffix = extname(id).toLowerCase()
      if (!PAYLOAD_SUFFIXES.has(suffix)) throw new Error(`${version.gameVersion}/${id}: unsupported gamedata suffix`)
      const bytes = await readFile(sourcePath)
      if (bytes.byteLength === 0) throw new Error(`${version.gameVersion}/${id}: empty gamedata payload`)
      const text = decodeUtf8(bytes, sourcePath)
      const content = encodeAsset(bytes, payloadUrl(bytes, suffix))
      addAsset(assets, content)

      const parts = id.split('/')
      const descriptor: GameDataFileDescriptor = {
        id,
        plugin: parts[0]!,
        fileName: basename(id),
        language: detectLanguage(id, text),
        content: { url: content.url, sha256: content.sha256, size: content.size },
      }
      const companionId = `${id}${METADATA_SUFFIX}`
      const companionPath = relativeFiles.get(companionId)
      if (companionPath) {
        const metadataBytes = await readFile(companionPath)
        const metadataText = decodeUtf8(metadataBytes, companionPath)
        let metadata: unknown
        try {
          metadata = JSON.parse(metadataText)
        } catch (error) {
          throw new Error(`${companionPath}: invalid metadata JSON`, { cause: error })
        }
        validateGameDataMetadata(metadata, {
          gameVersion: version.gameVersion,
          fileId: id,
          lineCount: text.split('\n').length,
          source: companionPath,
        })
        const metadataAsset = encodeAsset(metadataBytes, metadataUrl(metadataBytes))
        addAsset(assets, metadataAsset)
        descriptor.metadata = {
          url: metadataAsset.url,
          sha256: metadataAsset.sha256,
          size: metadataAsset.size,
          schemaVersion: metadata.schema_version,
          summary: metadata.summary,
        }
      }
      descriptors.push(descriptor)
    }
    versions.push({
      gameVersion: version.gameVersion,
      fileCount: descriptors.length,
      metadataFileCount: descriptors.filter((file) => file.metadata !== undefined).length,
      files: descriptors,
    })
  }

  const index: GameDataIndex = { schemaVersion: 1, versions }
  validateGameDataIndex(index)
  return { index, assets, sourceFiles }
}

export function gameDataPlugin(gamedataDirectory: string): Plugin {
  return {
    name: 'gamedata-assets',
    configureServer(server) {
      server.watcher.add(gamedataDirectory)
      server.middlewares.use(async (request, response, next) => {
        const pathname = new URL(request.url ?? '/', 'http://localhost').pathname
        if (!pathname.includes('/gamedata/')) {
          next()
          return
        }
        try {
          const loaded = await loadGameDataAssets(gamedataDirectory)
          if (pathname.endsWith('/gamedata/index.json')) {
            sendJson(response, loaded.index)
            return
          }
          const match = /\/gamedata\/(payloads\/[0-9a-f]{64}\.(?:json|jsonc|txt)|metadata\/[0-9a-f]{64}\.json)$/.exec(pathname)
          if (!match) {
            next()
            return
          }
          const asset = loaded.assets.get(match[1])
          if (!asset) {
            response.statusCode = 404
            response.end()
            return
          }
          const contentType = match[1].endsWith('.json') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8'
          sendBytes(response, asset.bytes, contentType)
        } catch (error) {
          next(error instanceof Error ? error : new Error(String(error)))
        }
      })
    },
    async buildStart() {
      const loaded = await loadGameDataAssets(gamedataDirectory)
      loaded.sourceFiles.forEach((path) => this.addWatchFile(path))
    },
    async generateBundle() {
      const loaded = await loadGameDataAssets(gamedataDirectory)
      for (const asset of loaded.assets.values()) {
        this.emitFile({ type: 'asset', fileName: `gamedata/${asset.url}`, source: asset.bytes })
      }
      this.emitFile({ type: 'asset', fileName: 'gamedata/index.json', source: JSON.stringify(loaded.index) })
    },
  }
}
