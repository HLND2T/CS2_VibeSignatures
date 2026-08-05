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

The Vite build validates schema-5 `../gamesymbols/*.yaml` snapshots and emits index schema v4. Each binary entry in a version JSON carries raw-byte MD5, SHA-256, CRC-32/ISO-HDLC, CRC-64/XZ, and byte size. Every version entry carries the SHA-256 and byte size of the exact UTF-8 JSON response body, and its URL is strictly `<gameVersion>.<sha256>.json`. The browser verifies those bytes before decoding or parsing the snapshot.

The Pages workflow keeps finalized snapshot bytes in the append-only `pages-snapshots` branch. Its history is required to contain additions only, pushes are non-forced, and an existing digest file must remain byte-identical. A same-version content change therefore adds a new digest file, while every previously archived digest is copied into later Pages artifacts. After deployment, the workflow fetches the public Pages responses and recomputes their size and SHA-256 so CDN delivery is checked against index v4 as well.

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
