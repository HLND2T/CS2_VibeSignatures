import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { attachAliasesToDataset, buildConfigAliasIndex, createGameSymbolIndex, encodeGameSymbolAsset, normalizeGameSymbolSnapshot } from './gameSymbolsPlugin'

function snapshot(files: Record<string, Record<string, unknown>>, gameVersion = '14168b') {
  return {
    schema_version: 5,
    last_publish_time: '2026-01-02T03:04:05Z',
    binaries: {
      server: {
        windows: {
          path: 'game/bin/win64/server.dll',
          sha256: '1'.repeat(64),
          md5: '2'.repeat(32),
          crc32: '3'.repeat(8),
          crc64: '4'.repeat(16),
          size: 123,
        },
        linux: {
          path: 'game/bin/linuxsteamrt64/libserver.so',
          sha256: '3'.repeat(64),
          md5: '4'.repeat(32),
          crc32: '5'.repeat(8),
          crc64: '6'.repeat(16),
          size: 456,
        },
      },
    },
    config_digest_version: 2,
    analysis_output_contract_version: 1,
    config_sha256: 'sha256:test',
    file_count: Object.keys(files).length,
    files,
    game_version: gameVersion,
  }
}

describe('gameSymbolsPlugin normalization', () => {
  it('normalizes module, platform, kind, and display names', () => {
    const dataset = normalizeGameSymbolSnapshot(snapshot({
      'server/CBaseEntity_Teleport.windows.yaml': { func_name: 'CBaseEntity_Teleport', func_rva: '0x123' },
      'server/CBaseEntity_m_iHealth.linux.yaml': { struct_name: 'CBaseEntity', member_name: 'm_iHealth', offset: '0x344' },
      'client/CEntityInstance_vtable.windows.yaml': { vtable_class: 'CEntityInstance', vtable_entries: { 0: '0x1' } },
    }), '14168b', 'snapshot.yaml')

    expect(dataset.source.gameVersion).toBe('14168b')
    expect(dataset.schemaVersion).toBe(3)
    expect(dataset.source.lastPublishTime).toBe('2026-01-02T03:04:05Z')
    expect(dataset.binaries.server.windows).toEqual({
      path: 'game/bin/win64/server.dll',
      sha256: '1'.repeat(64),
      md5: '2'.repeat(32),
      crc32: '3'.repeat(8),
      crc64: '4'.repeat(16),
      size: 123,
    })
    expect(dataset.modules).toEqual([
      { name: 'client', count: 1, windowsCount: 1, linuxCount: 0 },
      { name: 'server', count: 2, windowsCount: 1, linuxCount: 1 },
    ])
    expect(dataset.records).toEqual(expect.arrayContaining([
      expect.objectContaining({ module: 'server', platform: 'windows', kind: 'function', symbolName: 'CBaseEntity_Teleport' }),
      expect.objectContaining({ module: 'server', platform: 'linux', kind: 'structMember', symbolName: 'CBaseEntity.m_iHealth' }),
      expect.objectContaining({ module: 'client', kind: 'vtable', symbolName: 'CEntityInstance' }),
    ]))
  })

  it('rejects inconsistent file counts and game versions', () => {
    const value = snapshot({ 'server/Test.windows.yaml': { func_name: 'Test' } })
    expect(() => normalizeGameSymbolSnapshot({ ...value, file_count: 2 }, '14168b', 'snapshot.yaml')).toThrow(/file_count/)
    expect(() => normalizeGameSymbolSnapshot(value, '14169', 'snapshot.yaml')).toThrow(/does not match filename/)
    expect(() => normalizeGameSymbolSnapshot(snapshot({ 'server\\nested/Test.windows.yaml': { func_name: 'Test' } }), '14168b', 'snapshot.yaml')).toThrow(/invalid symbol path/)
    expect(() => normalizeGameSymbolSnapshot({ ...value, last_publish_time: 'invalid' }, '14168b', 'snapshot.yaml')).toThrow(/last_publish_time/)
    expect(() => normalizeGameSymbolSnapshot({ ...value, schema_version: 4 }, '14168b', 'snapshot.yaml')).toThrow(/schema_version/)
    expect(() => normalizeGameSymbolSnapshot({ ...value, binaries: { server: { windows: { path: 'server.dll', sha256: 'A'.repeat(64), md5: '2'.repeat(32), crc32: '3'.repeat(8), crc64: '4'.repeat(16), size: 1 } } } }, '14168b', 'snapshot.yaml')).toThrow(/sha256/)
    expect(() => normalizeGameSymbolSnapshot({ ...value, binaries: { server: { windows: { path: 'server.dll', sha256: '1'.repeat(64), md5: '2'.repeat(32), crc32: 'A'.repeat(8), crc64: '4'.repeat(16), size: 1 } } } }, '14168b', 'snapshot.yaml')).toThrow(/crc32/)
    expect(() => normalizeGameSymbolSnapshot({ ...value, binaries: { server: { windows: { path: 'server.dll', sha256: '1'.repeat(64), md5: '2'.repeat(32), crc32: '3'.repeat(8), crc64: '4'.repeat(16), size: -1 } } } }, '14168b', 'snapshot.yaml')).toThrow(/size/)
  })

  it('sorts versions newest first without treating suffixes as numbers', () => {
    const older = normalizeGameSymbolSnapshot(snapshot({}, '14168'), '14168', '14168.yaml')
    const revision = normalizeGameSymbolSnapshot(snapshot({}, '14168b'), '14168b', '14168b.yaml')
    const latest = normalizeGameSymbolSnapshot(snapshot({}, '14169'), '14169', '14169.yaml')
    const index = createGameSymbolIndex([older, latest, revision].map(encodeGameSymbolAsset))
    expect(index.schemaVersion).toBe(4)
    expect(index.versions.map((entry) => entry.gameVersion)).toEqual(['14169', '14168b', '14168'])
    expect(index.versions[0]).toEqual(expect.objectContaining({
      lastPublishTime: '2026-01-02T03:04:05Z',
      fileCount: 0,
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      size: expect.any(Number),
    }))
    expect(index.versions[0].url).toBe(`${index.versions[0].gameVersion}.${index.versions[0].sha256}.json`)
  })

  it('hashes and emits the exact UTF-8 snapshot bytes under a content-addressed name', () => {
    const dataset = normalizeGameSymbolSnapshot(snapshot({
      'server/Test.windows.yaml': { func_name: 'Test', note: '最终字节' },
    }, '14172'), '14172', 'snapshot.yaml')
    const asset = encodeGameSymbolAsset(dataset)
    const expectedBytes = Buffer.from(JSON.stringify(dataset), 'utf8')

    expect(Buffer.from(asset.bytes)).toEqual(expectedBytes)
    expect(asset.size).toBe(expectedBytes.byteLength)
    expect(asset.size).toBeGreaterThan(JSON.stringify(dataset).length)
    expect(asset.sha256).toBe(createHash('sha256').update(expectedBytes).digest('hex'))
    expect(asset.url).toBe(`14172.${asset.sha256}.json`)

    const changed = encodeGameSymbolAsset({
      ...dataset,
      records: dataset.records.map((record) => ({ ...record, payload: { ...record.payload, note: '内容变化' } })),
    })
    expect(changed.url).not.toBe(asset.url)
    expect(changed.url).toMatch(/^14172\.[0-9a-f]{64}\.json$/)
  })
})

describe('config alias attachment', () => {
  it('builds an alias index keyed by module/symbol-name and merges repeated modules', () => {
    const config = {
      modules: [
        { name: 'networksystem', symbols: [
          { name: 'CNetworkMessages_RegisterNetworkCategory', category: 'vfunc', alias: ['CNetworkMessages::RegisterNetworkCategory'] },
          { name: 'CNetworkMessages_NoAlias', category: 'vfunc' },
        ] },
        { name: 'networksystem', symbols: [
          { name: 'CNetworkMessages_RegisterNetworkCategory', category: 'vfunc', alias: ['CNetworkMessages::RegisterNetworkCategoryAlt'] },
        ] },
        { name: 'emptymodule' },
        { name: 'no-symbols-array', symbols: 'oops' },
      ],
    }
    const index = buildConfigAliasIndex(config, 'config.yaml')
    expect(index.aliases.get('networksystem/CNetworkMessages_RegisterNetworkCategory')).toEqual([
      'CNetworkMessages::RegisterNetworkCategory',
      'CNetworkMessages::RegisterNetworkCategoryAlt',
    ])
    expect(index.aliases.has('networksystem/CNetworkMessages_NoAlias')).toBe(false)
  })

  it('attaches aliases to matching records by module and artifact across both platforms', () => {
    const dataset = normalizeGameSymbolSnapshot(snapshot({
      'networksystem/CNetworkMessages_RegisterNetworkCategory.windows.yaml': { func_name: 'CNetworkMessages_RegisterNetworkCategory', vfunc_index: 0 },
      'networksystem/CNetworkMessages_RegisterNetworkCategory.linux.yaml': { func_name: 'CNetworkMessages_RegisterNetworkCategory', vfunc_index: 0 },
      'networksystem/CNetworkMessages_Unaliased.windows.yaml': { func_name: 'CNetworkMessages_Unaliased', vfunc_index: 1 },
    }, '14172'), '14172', 'snapshot.yaml')
    const index = buildConfigAliasIndex({
      modules: [{ name: 'networksystem', symbols: [{ name: 'CNetworkMessages_RegisterNetworkCategory', category: 'vfunc', alias: ['CNetworkMessages::RegisterNetworkCategory'] }] }],
    }, 'config.yaml')
    const aliased = attachAliasesToDataset(dataset, index)
    expect(aliased.records).toEqual(expect.arrayContaining([
      expect.objectContaining({ platform: 'windows', aliases: ['CNetworkMessages::RegisterNetworkCategory'] }),
      expect.objectContaining({ platform: 'linux', aliases: ['CNetworkMessages::RegisterNetworkCategory'] }),
    ]))
    expect(aliased.records.find((record) => record.artifact === 'CNetworkMessages_Unaliased')).not.toHaveProperty('aliases')
  })

  it('returns the same dataset instance when the alias index is empty', () => {
    const dataset = normalizeGameSymbolSnapshot(snapshot({ 'networksystem/F.windows.yaml': { func_name: 'F' } }, '14172'), '14172', 'snapshot.yaml')
    const index = buildConfigAliasIndex({ modules: [] }, 'config.yaml')
    expect(attachAliasesToDataset(dataset, index)).toBe(dataset)
  })
})
