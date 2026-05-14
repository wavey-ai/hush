# Hush

Browser-side mel spectrogram and voice activity detection for private ASR
workflows.

Hush converts microphone or WAV input into quantized mel spectrogram segments in
WASM. Audio stays in the browser; only compact TGA mel images need to be sent to
an inference service when an API URL is configured.

## Current Demo

The current app is designed to run from:

```text
https://wavey.ai/code/
```

It is a static Cloudflare Worker asset deployment mounted at `/code`. The Worker
adds the COOP/COEP headers required for `SharedArrayBuffer`, which the WASM
worker and AudioWorklet pipeline need.

## What Runs In The Browser

- `mel-spec` WASM computes STFT, mel frames, quantization, and VAD.
- The browser decodes WAV input into PCM frames before handing it to the WASM
  mel pipeline.
- Web Workers keep mel/WAV processing off the UI thread.
- An AudioWorklet streams microphone samples into a shared ring buffer.
- Captured speech segments are shown as spectrogram images and can optionally be
  POSTed as TGA bytes to an ASR endpoint.

## Build

From the repository root:

```bash
cd web/app
npm install
npm run build
```

The build output is written to `web/app/dist/code`, mirroring the Cloudflare
route path. The build uses a local sibling checkout when present:

- `../mel-spec`

If it is not available, the Makefile clones a shallow copy into `web/app/.deps`.

## Local Run

```bash
cd web/app
npm start
```

Open:

```text
http://127.0.0.1:8181/code/
```

The local server sends the same cross-origin isolation headers as the Cloudflare
Worker.

## Deploy

The repo includes `wrangler.toml` for the `/code` route:

```bash
cd web/app
CLOUDFLARE_EMAIL=jamie@wavey.ai \
CLOUDFLARE_API_KEY="$(tr -d '\n\r' < ~/wavey.ai/.cloudflare-token)" \
npm run deploy
```

Wrangler deploys `cloudflare/worker.js` plus static assets from
`web/app/dist`. The route is configured as:

```toml
route = "wavey.ai/code*"
```

## Optional ASR API

By default, the live page only captures local mel segments. To POST TGA segments
to an API, either set `data-api` on the `<body>` tag or pass an `api` query
parameter:

```text
https://wavey.ai/code/?api=https%3A%2F%2Fapi-hush.wavey.ai
```

The request body is the TGA byte buffer produced from the quantized mel segment.

## Checks

```bash
cd web/app
npm test
npm run build
```

For an end-to-end browser check, run `npm start` and verify:

- `crossOriginIsolated` is true.
- `dist/mel_spec_bg.wasm` loads as `application/wasm`.
- Starting the microphone changes VAD status and frame count.

## Legacy

The historical AWS, S3, CloudFront, Cognito, and GPU API files are still in this
repository for reference. The active web demo path is the Cloudflare/WASM setup
described above.
