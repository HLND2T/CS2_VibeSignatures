# CS2 VibeSignatures Process Dashboard

React + TypeScript + Vite implementation of the Process Reporter web dashboard.

## Development

```powershell
npm ci
npm run dev
```

The first visit asks for the Process API address. The default is `http://127.0.0.1:8000`; a different build-time default can be supplied with `VITE_API_BASE_URL`.

Start the local API for Vite development with:

```powershell
$env:CS2VIBE_API_CORS_ORIGINS="http://localhost:5173"
uv run uvicorn process_api:app --host 127.0.0.1 --port 8000
```

## Pages deployment

`esa.jsonc` publishes `dist/` and uses SPA fallback routing. A public Pages application still calls the localhost of the computer running the browser; the CDN cannot reach a different computer's localhost.

Pages development and deployment build only from `PAGES_RELEASE_INPUT_ROOT`, a fresh staging tree hydrated from compatible published immutable GitHub Releases. The hydration step revalidates each direct tag/source binding, canonical Release manifest, exact SHA256SUMS and public asset allowlist, then safely extracts only the manifest-bound gamedata subtree. Repository-root `gamesymbols/` and `gamedata/` are not compatibility inputs; development/build fails closed when the explicit Release staging root is absent.

The Vite build validates each staged schema-5 snapshot and emits index schema v4. Every symbol and gamedata response remains content-addressed. The published Release set replaces the old `pages-snapshots` branch as the historical input, while the browser and deployment workflow continue to verify exact response sizes and SHA-256 digests. After deployment, the workflow fetches the public Pages responses and recomputes their bytes so CDN delivery is checked against the exact build.

For an exact Pages origin:

```powershell
$env:CS2VIBE_API_CORS_ORIGINS="https://status.example.com"
$env:CS2VIBE_API_ALLOW_PRIVATE_NETWORK="true"
uv run uvicorn process_api:app --host 127.0.0.1 --port 8000
```

Do not use a wildcard CORS origin with private-network access.

## Verification

```powershell
npm run lint
npm test
npm run build
npm run verify:gamesymbols
npm run test:e2e
```
