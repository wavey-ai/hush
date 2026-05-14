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

const fftSize = 1024;
const hopSize = 160;
const samplingRate = 16000;
const nMels = 80;

const melBufOpts = { size: nMels + 8, max: 64 };
const micBufOpts = { size: 128, max: 64 };
const fileBufOpts = { size: hopSize, max: 200_000 };

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

const apiUrl =
  document.body.dataset.api ||
  new URLSearchParams(window.location.search).get("api") ||
  "";

function setStatus(element, value) {
  if (element) {
    element.textContent = value;
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

  pcmWorker = startup(assetUrl("worker.js"));
  pcmWorker.postMessage({
    fftSize,
    hopSize,
    samplingRate,
    nMels,
    melSab,
    melBufOpts,
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
  const minFrames = 150;
  const trailingSilenceFrames = 8;

  const accumulateFrame = (frame) => {
    frames.push(frame);
    if (frame.vad) {
      speechFrames++;
      silenceFrames = 0;
      setStatus(vadStatus, "speech");
    } else {
      silenceFrames++;
      setStatus(vadStatus, "quiet");
    }

    if (speechFrames === 0 && frames.length > minFrames) {
      frames = [];
      silenceFrames = 0;
      return;
    }

    if (
      speechFrames > 0 &&
      silenceFrames >= trailingSilenceFrames &&
      frames.length >= minFrames
    ) {
      const dequant = frames.map((a) => a.toF32());
      const normalized = normMel(interleave(dequant));
      const tga = createTGAImage(normalized, nMels);
      newSegment(interleave(frames.map((a) => a.luma)), tga);
      frames = [];
      speechFrames = 0;
      silenceFrames = 0;
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

  await context.audioWorklet.addModule(assetUrl("dist/worklet.js"));

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
  const luma = mel.slice(0, 80);
  luma.reverse();

  const minBytes = mel.slice(80, 84);
  const maxBytes = mel.slice(84, 88);
  const min = new DataView(new Uint8Array(minBytes).buffer).getFloat32(0, true);
  const max = new DataView(new Uint8Array(maxBytes).buffer).getFloat32(0, true);
  const toF32 = () => dequantize(mel.slice(0, 80), { min, max });

  return {
    luma,
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
