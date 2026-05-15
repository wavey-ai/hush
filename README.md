# Hush

Browser-side mel spectrogram and voice activity detection for private ASR
workflows.

Hush converts microphone input into quantized mel spectrogram segments in WASM.
Audio stays in the browser. Captured TGA mel images can be transcribed locally
with the bundled Whisper WASM worker, or optionally sent to an ASR endpoint.

## Current Demo

```text
https://wavey.ai/code/hush/
```

## What Runs In The Browser

- `mel-spec` WASM computes STFT, mel frames, quantization, and VAD.
- The browser decodes WAV input into PCM frames before handing it to the WASM
  mel pipeline.
- Web Workers keep mel/WAV processing off the UI thread.
- An AudioWorklet streams microphone samples into a shared ring buffer.
- Captured speech segments are shown as spectrogram images.
- Captured TGA bytes can be POSTed to an ASR endpoint when an API URL is
  configured.
- Without an API URL, the active demo preloads the local Whisper WASM worker and
  transcribes captured mel segments in the browser. Use `?whisper=0` to disable
  that path while testing VAD only.

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
https://wavey.ai/code/hush/?v=20260515-35
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
Cloudflare route path. The build uses local sibling checkouts when present:

- `../mel-spec`
- `../whisper.cpp-upstream`

If they are not available, the Makefile clones shallow copies into
`web/app/.deps`.

## Local Whisper WASM

The active browser app has a working `whisper.cpp` WASM binding for direct mel
input. It loads in a dedicated worker after the spectrogram UI has started, so
the mic path does not depend on main-thread model or WASM startup.

The live `v=20260515-35` path has been verified end to end: the page preloads
the Whisper WASM runtime, fetches/caches the GGML model, accepts the
`mel-spec`-generated mel tensor, calls `whisper_set_mel`, and returns a local
transcript from `whisper_full`.

This uses the direct-mel endpoint/entry point we PR'd against `whisper.cpp`:
`whisper_set_mel(ctx, data, n_frames, 80)`. It is not the stock browser example
that feeds PCM audio into `whisper.wasm`.

The intended path is:

1. Hush uses the Whisper-compatible `mel-spec` log-mel normalization and writes
   the captured segment as a compact 8-bit TGA.
2. The browser decodes that TGA back to an 80-mel `Float32Array`.
3. `whisper-worker.js` loads the custom `hush-whisper.js` Emscripten module.
4. The custom binding calls `whisper_set_mel(ctx, data, n_frames, 80)`
   and then runs `whisper_full`.

Upstream `whisper.cpp` already supports direct mel input; Hush adds a small
browser binding for it.

The default model is:

```text
https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-tiny.en-q5_1.bin
```

The browser caches the model with the Cache API after the first fetch. Useful
query parameters for the experimental worker are:

```text
?whisperModel=https%3A%2F%2Fexample.com%2Fggml-model.bin
?language=en
?whisperThreads=4
```

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

To bypass local Whisper and POST TGA segments to an API, either set `data-api`
on the `<body>` tag or pass an `api` query parameter:

```text
https://wavey.ai/code/hush/?api=https%3A%2F%2Fexample.com%2Fhush-asr
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

## License

MIT. See `LICENSE-MIT`.
