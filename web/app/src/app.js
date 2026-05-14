const { startup } = wasm_bindgen;

const scriptBase = new URL(".", document.currentScript.src);
const assetUrl = (path) => new URL(path, scriptBase).href;

const canvas = document.getElementById("canvas");
const startButton = document.getElementById("startButton");
const stopButton = document.getElementById("stopButton");
const wasmStatus = document.getElementById("wasmStatus");
const vadStatus = document.getElementById("vadStatus");
const frameCount = document.getElementById("frameCount");
const segmentCount = document.getElementById("segmentCount");
const isolationStatus = document.getElementById("isolationStatus");
const presetStatus = document.getElementById("presetStatus");
const presetButtons = Array.from(document.querySelectorAll("[data-vad-preset]"));

const fftSize = 1024;
const hopSize = 160;
const samplingRate = 16000;
const nMels = 80;

const melBufOpts = { size: nMels + 8, max: 64 };
const micBufOpts = { size: 128, max: 64 };
const fileBufOpts = { size: hopSize, max: 200_000 };

const vadPresets = {
  sensitive: {
    label: "Sensitive",
    wasm: { minEnergy: 0.96, minY: 8, minX: 5, minMel: 4 },
    gate: {
      onFrames: 4,
      offFrames: 6,
      minPatternScore: 0,
      minSpeechFrames: 10,
      minSpeechRatio: 0.05,
      minSegmentFrames: 80,
      maxPreSpeechFrames: 40,
      trailingSilenceFrames: 6,
    },
  },
  balanced: {
    label: "Balanced",
    wasm: { minEnergy: 0.98, minY: 11, minX: 5, minMel: 2 },
    gate: {
      onFrames: 8,
      offFrames: 10,
      minPatternScore: 0.45,
      minSpeechFrames: 28,
      minSpeechRatio: 0.15,
      minSegmentFrames: 100,
      maxPreSpeechFrames: 45,
      trailingSilenceFrames: 10,
    },
  },
  safer: {
    label: "Safer",
    wasm: { minEnergy: 1.0, minY: 14, minX: 8, minMel: 4 },
    gate: {
      onFrames: 12,
      offFrames: 12,
      minPatternScore: 0.6,
      minSpeechFrames: 35,
      minSpeechRatio: 0.22,
      minSegmentFrames: 140,
      maxPreSpeechFrames: 35,
      trailingSilenceFrames: 12,
    },
  },
};

let melSab;
let melBuf;
let micSab;
let fileSab;
let fileBuf;
let pcmWorker;
let audioContext;
let audioStream;
let audioNode;
let framesSeen = 0;
let segmentsSeen = 0;
let activeVadPreset = "safer";
let resetSegmentation = () => {};

const apiUrl =
  document.body.dataset.api ||
  new URLSearchParams(window.location.search).get("api") ||
  "";

function setStatus(element, value) {
  if (element) {
    element.textContent = value;
  }
}

function vadPreset() {
  return vadPresets[activeVadPreset] || vadPresets.safer;
}

function updatePresetUi() {
  const preset = vadPreset();
  setStatus(presetStatus, preset.label);

  for (const button of presetButtons) {
    button.setAttribute(
      "aria-pressed",
      button.dataset.vadPreset === activeVadPreset ? "true" : "false"
    );
  }
}

function configureWorkerVad() {
  if (!pcmWorker) {
    return;
  }

  pcmWorker.postMessage({
    configureVad: true,
    fftSize,
    hopSize,
    samplingRate,
    nMels,
    vadSettings: vadPreset().wasm,
  });
}

function wireVadPresetControls() {
  updatePresetUi();

  for (const button of presetButtons) {
    button.addEventListener("click", () => {
      const key = button.dataset.vadPreset;
      if (!vadPresets[key] || key === activeVadPreset) {
        return;
      }

      activeVadPreset = key;
      updatePresetUi();
      resetSegmentation();
      configureWorkerVad();
    });
  }
}

function assertIsolation() {
  const ready =
    window.crossOriginIsolated &&
    typeof SharedArrayBuffer !== "undefined" &&
    typeof AudioWorkletNode !== "undefined";

  setStatus(
    isolationStatus,
    ready
      ? "Browser isolation ready"
      : "COOP/COEP isolation is required for SharedArrayBuffer"
  );

  if (!ready) {
    startButton.disabled = true;
    setStatus(wasmStatus, "blocked");
  }

  return ready;
}

function sharedBuffers() {
  melSab = sharedbuffer(melBufOpts.size, melBufOpts.max, Uint8ClampedArray);
  melBuf = ringbuffer(
    melSab,
    melBufOpts.size,
    melBufOpts.max,
    Uint8ClampedArray
  );
  micSab = sharedbuffer(micBufOpts.size, micBufOpts.max, Float32Array);
  fileSab = sharedbuffer(fileBufOpts.size, fileBufOpts.max, Float32Array);
  fileBuf = ringbuffer(
    fileSab,
    fileBufOpts.size,
    fileBufOpts.max,
    Float32Array
  );
}

const palettes = {
  cividis: [
    [0.0, 0, 32, 76],
    [0.35, 70, 92, 111],
    [0.7, 160, 145, 96],
    [1.0, 253, 231, 55],
  ],
  plasma: [
    [0.0, 13, 8, 135],
    [0.35, 156, 23, 158],
    [0.7, 237, 121, 83],
    [1.0, 240, 249, 33],
  ],
  winter: [
    [0.0, 0, 0, 255],
    [0.5, 0, 128, 191],
    [1.0, 0, 255, 128],
  ],
};

function colorizeGrayscaleValue(value, colormapName, reverse) {
  const x = Math.max(0, Math.min(1, value / 255));
  const t = reverse ? 1 - x : x;
  const stops = palettes[colormapName] || palettes.cividis;

  for (let i = 0; i < stops.length - 1; i++) {
    const a = stops[i];
    const b = stops[i + 1];
    if (t >= a[0] && t <= b[0]) {
      const span = b[0] - a[0] || 1;
      const p = (t - a[0]) / span;
      return [
        Math.round(a[1] + (b[1] - a[1]) * p),
        Math.round(a[2] + (b[2] - a[2]) * p),
        Math.round(a[3] + (b[3] - a[3]) * p),
      ];
    }
  }

  const last = stops[stops.length - 1];
  return [last[1], last[2], last[3]];
}

let addFrame;

document.addEventListener("DOMContentLoaded", async function() {
  if (!assertIsolation()) {
    return;
  }

  sharedBuffers();
  wireVadPresetControls();
  await startWorker();
  startUi();
  wireFileUpload();
  wireMicControls();
});

function wireFileUpload() {
  const form = document.getElementById("uploadForm");
  const fileInput = document.getElementById("waveFileInput");

  form.addEventListener("submit", async function(event) {
    event.preventDefault();

    const file = fileInput.files[0];
    if (!file) {
      alert("Please select a WAV file.");
      return;
    }

    try {
      setStatus(wasmStatus, "decoding file");
      const samples = await decodeAudioFile(file);
      pcmWorker.postMessage({ pcmSab: fileSab, pcmBufOpts: fileBufOpts });
      pushSamples(fileBuf, samples, fileBufOpts.size);
      setStatus(wasmStatus, "file queued");
    } catch (error) {
      setStatus(wasmStatus, `file error: ${error.message}`);
    }
  });
}

async function decodeAudioFile(file) {
  const bytes = await file.arrayBuffer();
  const context = new AudioContext({ sampleRate: samplingRate });
  const audioBuffer = await context.decodeAudioData(bytes);
  await context.close();
  return resampleToMono16k(audioBuffer);
}

function resampleToMono16k(audioBuffer) {
  const channel = audioBuffer.getChannelData(0);
  if (audioBuffer.sampleRate === samplingRate) {
    return channel;
  }

  const ratio = audioBuffer.sampleRate / samplingRate;
  const outLength = Math.floor(channel.length / ratio);
  const out = new Float32Array(outLength);

  for (let i = 0; i < outLength; i++) {
    const src = i * ratio;
    const lo = Math.floor(src);
    const hi = Math.min(channel.length - 1, lo + 1);
    const frac = src - lo;
    out[i] = channel[lo] * (1 - frac) + channel[hi] * frac;
  }

  return out;
}

function pushSamples(buffer, samples, frameSize) {
  for (let offset = 0; offset < samples.length; offset += frameSize) {
    const frame = new Float32Array(frameSize);
    frame.set(samples.subarray(offset, offset + frameSize));
    buffer.push(frame);
  }
}

function wireMicControls() {
  startButton.addEventListener("click", async () => {
    startButton.disabled = true;
    try {
      audioContext = new AudioContext({ sampleRate: samplingRate });
      await startAudioProcessing(audioContext);
      stopButton.disabled = false;
    } catch (error) {
      setStatus(wasmStatus, `mic error: ${error.message}`);
      startButton.disabled = false;
    }
  });

  stopButton.addEventListener("click", async () => {
    stopAudioProcessing();
  });
}

async function startWorker() {
  setStatus(wasmStatus, "loading");
  await wasm_bindgen();

  pcmWorker = startup(assetUrl("worker.js?v=20260514-4"));
  pcmWorker.onmessage = (event) => {
    if (event.data?.error) {
      setStatus(wasmStatus, event.data.error);
    }
  };
  pcmWorker.onerror = (event) => {
    setStatus(wasmStatus, `worker error: ${event.message}`);
  };
  pcmWorker.postMessage({
    fftSize,
    hopSize,
    samplingRate,
    nMels,
    melSab,
    melBufOpts,
    vadSettings: vadPreset().wasm,
  });

  setInterval(() => {
    pcmWorker.postMessage({ pop: true });
  }, 10);

  setStatus(wasmStatus, "ready");
}

function interleave(columns) {
  const numRows = columns[0].length;
  const numColumns = columns.length;
  const interleavedArray = new Array(numRows * numColumns);

  for (let row = 0; row < numRows; row++) {
    for (let col = 0; col < numColumns; col++) {
      interleavedArray[row * numColumns + col] = columns[col][row];
    }
  }

  return interleavedArray;
}

function clamp01(value) {
  return Math.max(0, Math.min(1, value));
}

function vectorSimilarity(a, b, start, end) {
  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (let i = start; i < end; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  if (normA === 0 || normB === 0) {
    return 0;
  }

  return dot / Math.sqrt(normA * normB);
}

function lateralSpeechScore(history, start, end) {
  if (history.length < 3) {
    return 0;
  }

  let lateralBins = 0;
  for (let bin = start; bin < end; bin++) {
    let run = 0;
    let maxRun = 0;

    for (const frame of history) {
      if (frame[bin] >= 0.42) {
        run++;
        maxRun = Math.max(maxRun, run);
      } else {
        run = 0;
      }
    }

    if (maxRun >= 3) {
      lateralBins++;
    }
  }

  return clamp01((lateralBins - 4) / 16);
}

function continuityScore(history, start, end) {
  const recent = history.slice(-7);
  if (recent.length < 3) {
    return 0;
  }

  let total = 0;
  let count = 0;
  for (let i = 1; i < recent.length; i++) {
    total += vectorSimilarity(recent[i - 1], recent[i], start, end);
    count++;
  }

  return clamp01(total / count);
}

function speechPatternScore(frame, history) {
  const values = Array.from(frame.raw, (value) => value / 255);
  const total = values.reduce((sum, value) => sum + value, 0);
  if (total <= 0) {
    return 0;
  }

  const speechStart = 6;
  const speechEnd = 58;
  const bandSum = (start, end) =>
    values.slice(start, end).reduce((sum, value) => sum + value, 0);
  const speechBandRatio = bandSum(speechStart, speechEnd) / total;
  const highBandRatio = bandSum(speechEnd, values.length) / total;
  const activeBins = values.filter((value) => value >= 0.45).length;
  const centroid =
    values.reduce((sum, value, index) => sum + value * index, 0) /
    (total * (values.length - 1));

  const bandScore =
    clamp01((speechBandRatio - 0.38) / 0.24) *
    clamp01((0.62 - highBandRatio) / 0.28);
  const widthScore =
    activeBins >= 5 && activeBins <= 54
      ? 1
      : clamp01(1 - Math.abs(activeBins - 30) / 30);
  const centroidScore =
    centroid >= 0.12 && centroid <= 0.78
      ? 1
      : clamp01(1 - Math.min(Math.abs(centroid - 0.45), 0.45) / 0.45);
  const lateralScore = lateralSpeechScore(history, speechStart, speechEnd);
  const shapeContinuity = continuityScore(history, speechStart, speechEnd);

  return (
    lateralScore * 0.45 +
    shapeContinuity * 0.25 +
    bandScore * 0.2 +
    widthScore * 0.05 +
    centroidScore * 0.05
  );
}

function startUi() {
  const ctx = canvas.getContext("2d");
  const columnWidth = 1;
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  addFrame = (frame, vad) => {
    if (!frame || frame.length === 0) {
      return;
    }

    const numColumns = Math.ceil(frame.length / nMels);

    ctx.globalCompositeOperation = "copy";
    ctx.drawImage(
      canvas,
      numColumns * columnWidth,
      0,
      canvas.width - numColumns * columnWidth,
      nMels + 18,
      0,
      0,
      canvas.width - numColumns * columnWidth,
      nMels + 18
    );
    ctx.globalCompositeOperation = "source-over";

    for (let col = 0; col < numColumns; col++) {
      const startIdx = col * nMels;
      const endIdx = Math.min(startIdx + nMels, frame.length);
      const columnData = frame.slice(startIdx, endIdx);
      let arr = new Uint8ClampedArray(nMels * 4);

      for (let i = 0; i < columnData.length; i++) {
        const [r, g, b] = colorizeGrayscaleValue(
          columnData[i],
          vad ? "plasma" : "cividis",
          false
        );
        arr[i * 4 + 0] = r;
        arr[i * 4 + 1] = g;
        arr[i * 4 + 2] = b;
        arr[i * 4 + 3] = 255;
      }

      for (let i = 0; i < 2 * (vad ? 6 : 4); i++) {
        arr = new Uint8ClampedArray([...arr, 0, 0, 0, 0]);
      }

      const [pixelR, pixelG, pixelB] = vad ? [225, 34, 71] : [30, 36, 44];
      for (let i = 0; i < 4; i++) {
        arr[arr.length - 4 * (4 - i)] = pixelR;
        arr[arr.length - 4 * (4 - i) + 1] = pixelG;
        arr[arr.length - 4 * (4 - i) + 2] = pixelB;
        arr[arr.length - 4 * (4 - i) + 3] = 255;
      }

      const imageData = new ImageData(arr, 1);
      ctx.putImageData(imageData, canvas.width - numColumns + col, 0);
    }

    ctx.beginPath();
    ctx.arc(canvas.width - 18, 112, 10, 0, 2 * Math.PI);
    ctx.fillStyle = vad ? "#e12247" : "#1e242c";
    ctx.fill();
    ctx.closePath();
  };

  const mels = document.getElementById("mels");
  let frames = [];
  let speechFrames = 0;
  let silenceFrames = 0;
  let rawSpeechRun = 0;
  let rawSilenceRun = 0;
  let gatedVad = false;
  let patternHistory = [];

  resetSegmentation = () => {
    frames = [];
    speechFrames = 0;
    silenceFrames = 0;
    rawSpeechRun = 0;
    rawSilenceRun = 0;
    gatedVad = false;
    patternHistory = [];
    setStatus(vadStatus, "quiet");
  };

  const filterVad = (frame) => {
    const gate = vadPreset().gate;
    patternHistory.push(Array.from(frame.raw, (value) => value / 255));
    if (patternHistory.length > 16) {
      patternHistory.shift();
    }

    const patternScore = speechPatternScore(frame, patternHistory);
    const rawVad =
      frame.vad &&
      (gate.minPatternScore === 0 || patternScore >= gate.minPatternScore);

    if (rawVad) {
      rawSpeechRun++;
      rawSilenceRun = 0;
    } else {
      rawSilenceRun++;
      rawSpeechRun = 0;
    }

    if (!gatedVad && rawSpeechRun >= gate.onFrames) {
      gatedVad = true;
    }

    if (gatedVad && rawSilenceRun >= gate.offFrames) {
      gatedVad = false;
    }

    return gatedVad;
  };

  const accumulateFrame = (frame) => {
    const gate = vadPreset().gate;

    frames.push(frame);
    if (frame.vad) {
      speechFrames++;
      silenceFrames = 0;
      setStatus(vadStatus, "speech");
    } else {
      silenceFrames++;
      setStatus(vadStatus, "quiet");
    }

    if (speechFrames === 0 && frames.length > gate.maxPreSpeechFrames) {
      frames.splice(0, frames.length - gate.maxPreSpeechFrames);
      silenceFrames = 0;
      return;
    }

    if (
      speechFrames > 0 &&
      silenceFrames >= gate.trailingSilenceFrames &&
      frames.length >= gate.minSegmentFrames
    ) {
      const speechRatio = speechFrames / frames.length;
      if (
        speechFrames >= gate.minSpeechFrames &&
        speechRatio >= gate.minSpeechRatio
      ) {
        const dequant = frames.map((a) => a.toF32());
        const normalized = normMel(interleave(dequant));
        const tga = createTGAImage(normalized, nMels);
        newSegment(interleave(frames.map((a) => a.luma)), tga);
      }
      resetSegmentation();
    }
  };

  const newSegment = async (frames, tga) => {
    segmentsSeen += 1;
    setStatus(segmentCount, String(segmentsSeen));

    const numColumns = frames.length / nMels;
    const segmentCanvas = document.createElement("canvas");
    const ctx = segmentCanvas.getContext("2d");
    const imageDataArr = new Uint8ClampedArray(nMels * 4 * numColumns);

    for (let col = 0; col < numColumns; col++) {
      for (let row = 0; row < nMels; row++) {
        const dataIndex = row * numColumns + col;
        const val = frames[dataIndex];
        const [r, g, b] = colorizeGrayscaleValue(val, "winter", false);
        imageDataArr[(row * numColumns + col) * 4 + 0] = r;
        imageDataArr[(row * numColumns + col) * 4 + 1] = g;
        imageDataArr[(row * numColumns + col) * 4 + 2] = b;
        imageDataArr[(row * numColumns + col) * 4 + 3] = 255;
      }
    }

    segmentCanvas.width = numColumns;
    segmentCanvas.height = nMels;
    ctx.putImageData(new ImageData(imageDataArr, numColumns, nMels), 0, 0);

    const liElement = document.createElement("li");
    const imgElement = document.createElement("img");
    imgElement.src = segmentCanvas.toDataURL();
    imgElement.alt = `Mel segment ${segmentsSeen}`;

    const spanElement = document.createElement("span");
    spanElement.textContent = apiUrl
      ? "Transcribing..."
      : `${numColumns} frames captured locally`;

    liElement.appendChild(imgElement);
    liElement.appendChild(spanElement);
    mels.prepend(liElement);

    if (!apiUrl) {
      return;
    }

    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        body: tga.buffer,
      });

      spanElement.textContent = response.ok
        ? await response.text()
        : `API error ${response.status}`;
    } catch (error) {
      spanElement.textContent = `API error: ${error.message}`;
    }
  };

  setInterval(() => {
    while (true) {
      const mel = melBuf.pop();
      if (!mel) {
        break;
      }

      const frame = melFrame(mel);
      frame.vad = filterVad(frame);
      framesSeen += 1;
      setStatus(frameCount, String(framesSeen));
      addFrame(frame.luma, frame.vad);
      accumulateFrame(frame);
    }
  }, 10);
}

async function startAudioProcessing(context) {
  audioStream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const volume = context.createGain();
  const audioInput = context.createMediaStreamSource(audioStream);
  audioInput.connect(volume);

  await context.audioWorklet.addModule(assetUrl("dist/worklet.js?v=20260514-4"));

  audioNode = new AudioWorkletNode(context, "AudioSender");
  volume.connect(audioNode);
  audioNode.connect(context.destination);

  pcmWorker.postMessage({ pcmSab: micSab, pcmBufOpts: micBufOpts });
  audioNode.port.postMessage({
    pcmSab: micSab,
    pcmBufOpts: micBufOpts,
  });

  setStatus(wasmStatus, "mic live");
}

function stopAudioProcessing() {
  if (audioStream) {
    audioStream.getTracks().forEach((track) => track.stop());
    audioStream = null;
  }

  if (audioNode) {
    audioNode.disconnect();
    audioNode = null;
  }

  if (audioContext) {
    audioContext.close();
    audioContext = null;
  }

  stopButton.disabled = true;
  startButton.disabled = false;
  setStatus(wasmStatus, "ready");
}

function melFrame(mel) {
  const vad = !(mel && (mel[0] & 1) === 1);
  const raw = mel.slice(0, 80);
  const luma = raw.slice();
  luma.reverse();

  const minBytes = mel.slice(80, 84);
  const maxBytes = mel.slice(84, 88);
  const min = new DataView(new Uint8Array(minBytes).buffer).getFloat32(0, true);
  const max = new DataView(new Uint8Array(maxBytes).buffer).getFloat32(0, true);
  const toF32 = () => dequantize(raw, { min, max });

  return {
    luma,
    raw,
    range: { min, max },
    vad,
    toF32,
  };
}

function createTGAImage(frames, nMels) {
  const { data, range } = quantize(frames);
  const width = Math.floor(data.length / nMels);
  const height = nMels;

  const tgaHeader = new Uint8Array(26);
  tgaHeader[0] = 8;
  tgaHeader[1] = 0;
  tgaHeader[2] = 3;
  tgaHeader.set(new Uint8Array(5), 3);
  tgaHeader.set(new Uint8Array(4), 8);
  tgaHeader.set(new Uint8Array(new Uint16Array([width]).buffer), 12);
  tgaHeader.set(new Uint8Array(new Uint16Array([height]).buffer), 14);
  tgaHeader[16] = 8;
  tgaHeader[17] = 0;

  const rangeBuffer = new ArrayBuffer(8);
  const rangeView = new DataView(rangeBuffer);
  rangeView.setFloat32(0, range.min, true);
  rangeView.setFloat32(4, range.max, true);
  tgaHeader.set(new Uint8Array(rangeBuffer), 18);

  const tgaImage = new Uint8Array(tgaHeader.length + data.length);
  tgaImage.set(tgaHeader);
  tgaImage.set(data, tgaHeader.length);

  return tgaImage;
}

function quantize(frame) {
  const result = new Uint8Array(frame.length);
  const min = Math.min(...frame);
  const max = Math.max(...frame);

  if (!Number.isFinite(min) || !Number.isFinite(max) || max === min) {
    return { data: result, range: { min: 0, max: 0 } };
  }

  const scale = 255.0 / (max - min);
  for (let i = 0; i < frame.length; i++) {
    result[i] = Math.round((frame[i] - min) * scale);
  }

  return { data: result, range: { min, max } };
}

function dequantize(data, range) {
  if (range.max === range.min) {
    return Array.from(data, () => range.min);
  }

  const result = [];
  const scale = (range.max - range.min) / 255.0;

  for (const value of data) {
    result.push(value * scale + range.min);
  }

  return result;
}

function normMel(frame) {
  const mmax = frame.reduce((acc, x) => Math.max(acc, x), -Infinity);
  return frame.map((x) => (Math.min(x, mmax) + 4.0) / 4.0);
}
