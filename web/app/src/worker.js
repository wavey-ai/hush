const assetUrl = (path) => new URL(path, self.location.href).href;

importScripts(assetUrl("dist/mel_spec.js"));
importScripts(assetUrl("ringbuffer.js"));

const { SpeechToMel } = wasm_bindgen;

const instance = wasm_bindgen(assetUrl("dist/mel_spec_bg.wasm"));
const pendingMessages = [];
let wasmReady = false;
let melBuf;
let pcmBuf;
let mod;

self.onmessage = (event) => {
  if (!wasmReady) {
    pendingMessages.push(event.data);
    return;
  }

  handleMessage(event.data);
};

async function initWasmInWorker() {
  await instance;
  wasmReady = true;

  while (pendingMessages.length > 0) {
    handleMessage(pendingMessages.shift());
  }
}

function handleMessage(opts) {
  if (opts.melBufOpts) {
    mod = createSpeechToMel(opts);
    melBuf = ringbuffer(
      opts.melSab,
      opts.melBufOpts.size,
      opts.melBufOpts.max,
      Uint8ClampedArray,
    );
  }

  if (opts.configureVad) {
    mod = createSpeechToMel(opts);
  }

  if (opts.pcmBufOpts) {
    pcmBuf = ringbuffer(
      opts.pcmSab,
      opts.pcmBufOpts.size,
      opts.pcmBufOpts.max,
      Float32Array,
    );
  }

  if (opts.pop && pcmBuf && melBuf && mod) {
    while (true) {
      const samples = pcmBuf.pop();
      if (!samples) {
        break;
      }

      const res = mod.add(samples, true);
      if (res.ok) {
        const data = new Uint8ClampedArray(res.frame.length + 8);
        data.set(res.frame);
        const float1Bytes = new Uint8Array(new Float32Array([res.min]).buffer);
        const float2Bytes = new Uint8Array(new Float32Array([res.max]).buffer);
        data.set(float1Bytes, 80);
        data.set(float2Bytes, 84);
        data[0] = res.va ? data[0] & ~1 : data[0] | 1;
        melBuf.push(data);
      }
    }
  }
}

function createSpeechToMel(opts) {
  const settings = opts.vadSettings || {};
  if (typeof SpeechToMel.newWithVadSettings === "function") {
    return SpeechToMel.newWithVadSettings(
      opts.fftSize,
      opts.hopSize,
      opts.samplingRate,
      opts.nMels,
      settings.minEnergy ?? 1.0,
      settings.minY ?? 3,
      settings.minX ?? 3,
      settings.minMel ?? 0
    );
  }

  return SpeechToMel.new(
    opts.fftSize,
    opts.hopSize,
    opts.samplingRate,
    opts.nMels
  );
}

initWasmInWorker().catch((error) => {
  self.postMessage({ error: `worker wasm init failed: ${error.message}` });
});
