# Hush

Browser-side mel spectrogram and voice activity detection for private ASR
workflows.

Hush converts microphone or WAV input into quantized mel spectrogram segments in
WASM. Audio stays in the browser; only compact TGA mel images need to be sent to
an inference service when an API URL is configured.

## Current Demo

The current app is designed to run from:

```text
https://wavey.ai/code/hush/
```

It is a static Cloudflare Worker asset deployment mounted under `/code/hush`.
The top-level `/code` namespace is reserved for the broader Wavey code index and
other project subpaths. The Worker adds the COOP/COEP headers required for
`SharedArrayBuffer`, which the WASM worker and AudioWorklet pipeline need.

## What Runs In The Browser

- `mel-spec` WASM computes STFT, mel frames, quantization, and VAD.
- The browser decodes WAV input into PCM frames before handing it to the WASM
  mel pipeline.
- Web Workers keep mel/WAV processing off the UI thread.
- An AudioWorklet streams microphone samples into a shared ring buffer.
- Captured speech segments are shown as spectrogram images and can optionally be
  POSTed as TGA bytes to an ASR endpoint.

## VAD Tuning Notes

The current Hush demo is tuned around the visible structure in the mel
spectrogram rather than raw audio amplitude. Speech usually shows sustained
lateral bands and ridges across adjacent frames. Short mechanical sounds, such
as key taps, can be very loud and can create sharp edges, but they tend to be
brief, impulsive, and less stable over time.

The browser tuning went through a few useful failure modes:

- A loose structure override made sustained speech easier to catch, but it also
  let key taps and typing through.
- A stricter impulse gate rejected those taps, but missed short/fricative words
  such as "five" even when the Sobel overlay showed clear horizontal speech
  lines.
- The current OK state uses a graded `Impulse gate`: it still blocks obvious
  impulses, but can open when sustained speech-band structure, ridge/edge
  continuity, band balance, and energy agree for several consecutive frames.
  Harmonic spacing is only weak evidence now, because fricatives do not always
  have clean harmonic spacing.

This is still a browser-side heuristic, not a complete learned VAD. It is useful
because the diagnostics are visible: the user can see the mel image, Sobel
overlay, sticky component peaks, and final VAD state together. The live tuning
checkpoint is:

```text
https://wavey.ai/code/hush/?v=20260515-24
```

The next step is to turn the manual tuning loop into a regression harness:

- Record short clips for silence, speech, sustained vowels, fricatives such as
  "five", keyboard taps, typing, desk taps, fan noise, and room noise.
- Replay those clips through the same WASM/browser VAD path and save per-frame
  component scores.
- Track false positives and false negatives by clip type, not just aggregate
  accuracy.
- Compare the heuristic against Silero or another established VAD on the same
  clips, using both accuracy and runtime.
- If the heuristic keeps hitting edge cases, train a small classifier over the
  existing mel-structure components instead of adding more hand-tuned gates.

## Build

From the repository root:

```bash
cd web/app
npm install
npm run build
```

The build output is written to `web/app/dist/code/hush`, mirroring the
Cloudflare route path. The build uses a local sibling checkout when present:

- `../mel-spec`

If it is not available, the Makefile clones a shallow copy into `web/app/.deps`.

## Local Run

```bash
cd web/app
npm start
```

Open:

```text
http://127.0.0.1:8181/code/hush/
```

The local server sends the same cross-origin isolation headers as the Cloudflare
Worker.

## Deploy

The repo includes `wrangler.toml` for the `/code/hush` route:

```bash
cd web/app
CLOUDFLARE_EMAIL=jamie@wavey.ai \
CLOUDFLARE_API_KEY="$(tr -d '\n\r' < ~/wavey.ai/.cloudflare-token)" \
npm run deploy
```

Wrangler deploys `cloudflare/worker.js` plus static assets from
`web/app/dist`. The route is configured as:

```toml
route = "wavey.ai/code/hush*"
```

## Optional ASR API

By default, the live page only captures local mel segments. To POST TGA segments
to an API, either set `data-api` on the `<body>` tag or pass an `api` query
parameter:

```text
https://wavey.ai/code/hush/?api=https%3A%2F%2Fapi-hush.wavey.ai
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
