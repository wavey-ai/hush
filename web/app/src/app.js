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
const componentScoreElements = {
  pattern: document.getElementById("patternScore"),
  edges: document.getElementById("edgeScore"),
  ridges: document.getElementById("ridgeScore"),
  harmonic: document.getElementById("harmonicScore"),
  continuity: document.getElementById("continuityScore"),
  flux: document.getElementById("fluxScore"),
  bands: document.getElementById("bandScore"),
  energy: document.getElementById("energyScore"),
  noise: document.getElementById("noiseScore"),
};

const fftSize = 1024;
const hopSize = 160;
const samplingRate = 16000;
const nMels = 80;

const melBufOpts = { size: nMels + 8, max: 64 };
const micBufOpts = { size: 128, max: 64 };
const fileBufOpts = { size: hopSize, max: 200_000 };

const vadSettings = {
  minEnergy: 1.0,
  minY: 6,
  minX: 6,
  minMel: 1,
};

const vadGate = {
  onFrames: 2,
  offFrames: 12,
  minPatternScore: 0.28,
  minEnergyScore: 0.25,
  minHorizontalBands: 2,
  targetHorizontalBands: 3,
  minSpeechFrames: 35,
  minSpeechRatio: 0.22,
  minSegmentFrames: 140,
  maxPreSpeechFrames: 35,
  trailingSilenceFrames: 12,
};

const speechBand = {
  start: 4,
  end: 72,
};

const sobelOverlayThreshold = 0.12;

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

  pcmWorker = startup(assetUrl("worker.js?v=20260515-6"));
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
    vadSettings,
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

function emptyPatternComponents() {
  return {
    pattern: 0,
    edges: 0,
    ridges: 0,
    harmonic: 0,
    continuity: 0,
    flux: 0,
    bands: 0,
    centroid: 0,
    noise: 0,
    energy: 0,
  };
}

function updateComponentScores(components) {
  for (const [key, element] of Object.entries(componentScoreElements)) {
    const value = components[key];
    const formatted =
      key === "bands"
        ? String(Math.round(Number.isFinite(value) ? value : 0))
        : Number.isFinite(value)
          ? value.toFixed(2)
          : "0.00";
    setStatus(element, formatted);
  }
}

function vectorSimilarity(a, b) {
  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  if (normA === 0 || normB === 0) {
    return 0;
  }

  return dot / Math.sqrt(normA * normB);
}

function frameEnergyScore(frame) {
  if (!frame?.range || !Number.isFinite(frame.range.max)) {
    return 0;
  }

  return clamp01((frame.range.max + 4.5) / 2.0);
}

function hasAcousticEnergy(frame) {
  return frameEnergyScore(frame) >= vadGate.minEnergyScore;
}

function frequencyEdges(values, start, end) {
  const edges = [];

  for (let i = start + 2; i < end - 2; i++) {
    const near = Math.abs(values[i + 1] - values[i - 1]);
    const wide = Math.abs(values[i + 2] - values[i - 2]);
    edges.push(near * 0.7 + wide * 0.3);
  }

  return edges;
}

function sobelEdgesForTriplet(prev, mid, next, start, end) {
  const edges = Array.from({ length: nMels }, () => null);
  const from = Math.max(start + 1, 1);
  const to = Math.min(end - 1, nMels - 1);

  for (let i = from; i < to; i++) {
    const timeGradient =
      next[i - 1] +
      2 * next[i] +
      next[i + 1] -
      (prev[i - 1] + 2 * prev[i] + prev[i + 1]);
    const frequencyGradient =
      prev[i + 1] +
      2 * mid[i + 1] +
      next[i + 1] -
      (prev[i - 1] + 2 * mid[i - 1] + next[i - 1]);
    const temporal = clamp01(Math.abs(timeGradient) / 4);
    const horizontal = clamp01(Math.abs(frequencyGradient) / 4);
    const magnitude = clamp01(Math.hypot(timeGradient, frequencyGradient) / 4);

    if (magnitude >= sobelOverlayThreshold) {
      edges[i] = {
        magnitude,
        horizontal,
        temporal,
      };
    }
  }

  return edges;
}

function sobelEdgeColumn(history, start, end) {
  if (history.length < 3) {
    return [];
  }

  return sobelEdgesForTriplet(
    history[history.length - 3],
    history[history.length - 2],
    history[history.length - 1],
    start,
    end
  );
}

function sustainedSobelStructure(history, start, end) {
  const columns = [];
  const from = Math.max(2, history.length - 10);

  for (let i = from; i < history.length; i++) {
    columns.push(
      sobelEdgesForTriplet(
        history[i - 2],
        history[i - 1],
        history[i],
        start,
        end
      )
    );
  }

  if (columns.length < 4) {
    return { bins: [], score: 0 };
  }

  const sustainedBins = [];
  for (let bin = start + 1; bin < end - 1; bin++) {
    let run = 0;
    let maxRun = 0;

    for (const column of columns) {
      const edge = column[bin];
      const isHorizontal =
        edge &&
        edge.horizontal >= 0.075 &&
        edge.horizontal >= edge.temporal * 0.55;

      if (isHorizontal) {
        run++;
        maxRun = Math.max(maxRun, run);
      } else {
        run = 0;
      }
    }

    if (maxRun >= 3) {
      sustainedBins.push(bin);
    }
  }

  return {
    bins: sustainedBins,
    score: clamp01((sustainedBins.length - 2) / 8),
  };
}

function sustainedEdgeStructure(history, start, end) {
  const recent = history.slice(-10);
  if (recent.length < 4) {
    return { bins: [], score: 0 };
  }

  const edgeMaps = recent.map((frame) => frequencyEdges(frame, start, end));
  const sustainedBins = [];

  for (let bin = 0; bin < edgeMaps[0].length; bin++) {
    let run = 0;
    let maxRun = 0;

    for (const edgeMap of edgeMaps) {
      if (edgeMap[bin] >= 0.14) {
        run++;
        maxRun = Math.max(maxRun, run);
      } else {
        run = 0;
      }
    }

    if (maxRun >= 3) {
      sustainedBins.push(start + bin + 2);
    }
  }

  return {
    bins: sustainedBins,
    score: clamp01((sustainedBins.length - 3) / 12),
  };
}

function localRidgeMap(values, start, end) {
  const ridges = [];

  for (let i = start + 2; i < end - 2; i++) {
    const value = values[i];
    const left = Math.max(values[i - 2], values[i - 1]);
    const right = Math.max(values[i + 1], values[i + 2]);
    const shoulder = Math.max(left, right);
    const prominence = value - shoulder;
    ridges.push(value >= 0.16 && prominence >= 0.012 ? prominence : 0);
  }

  return ridges;
}

function sustainedRidgeStructure(history, start, end) {
  const recent = history.slice(-10);
  if (recent.length < 4) {
    return { bins: [], score: 0 };
  }

  const ridgeMaps = recent.map((frame) => localRidgeMap(frame, start, end));
  const sustainedBins = [];

  for (let bin = 0; bin < ridgeMaps[0].length; bin++) {
    let run = 0;
    let maxRun = 0;

    for (const ridgeMap of ridgeMaps) {
      const strength = Math.max(
        ridgeMap[bin - 1] || 0,
        ridgeMap[bin],
        ridgeMap[bin + 1] || 0
      );

      if (strength >= 0.03) {
        run++;
        maxRun = Math.max(maxRun, run);
      } else {
        run = 0;
      }
    }

    if (maxRun >= 3) {
      sustainedBins.push(start + bin + 2);
    }
  }

  return {
    bins: sustainedBins,
    score: clamp01((sustainedBins.length - 2) / 10),
  };
}

function groupBins(bins, maxGap = 2) {
  const groups = [];
  for (const bin of bins) {
    const group = groups[groups.length - 1];
    if (group && bin - group[group.length - 1] <= maxGap) {
      group.push(bin);
    } else {
      groups.push([bin]);
    }
  }

  return groups;
}

function groupCenter(group) {
  return group.reduce((sum, value) => sum + value, 0) / group.length;
}

function mergeCenters(centers, maxGap = 2.5) {
  if (centers.length === 0) {
    return [];
  }

  const sorted = centers.slice().sort((a, b) => a.center - b.center);
  const groups = [];

  for (const center of sorted) {
    const group = groups[groups.length - 1];
    if (group && center.center - group[group.length - 1].center <= maxGap) {
      group.push(center);
    } else {
      groups.push([center]);
    }
  }

  return groups.map((group) => {
    const totalStrength = group.reduce((sum, item) => sum + item.strength, 0);
    return {
      center:
        group.reduce((sum, item) => sum + item.center * item.strength, 0) /
        (totalStrength || group.length),
      strength: totalStrength / group.length,
    };
  });
}

function harmonicSpacingScore(bins) {
  if (bins.length < 3) {
    return 0;
  }

  const groups = groupBins(bins);
  return clamp01((groups.length - 2) / 6) * clamp01((12 - groups.length) / 8);
}

function horizontalSobelCenters(column, start, end) {
  const bins = [];
  const strengths = new Map();

  for (let bin = start + 1; bin < end - 1; bin++) {
    const edge = column[bin];
    const isHorizontal =
      edge &&
      edge.horizontal >= 0.08 &&
      edge.horizontal >= edge.temporal * 0.75;

    if (isHorizontal) {
      bins.push(bin);
      strengths.set(bin, edge.horizontal);
    }
  }

  return groupBins(bins, 2)
    .map((group) => ({
      center: groupCenter(group),
      strength:
        group.reduce((sum, bin) => sum + (strengths.get(bin) || 0), 0) /
        group.length,
    }))
    .filter((center) => center.strength >= 0.09);
}

function ridgeCenters(values, start, end) {
  const ridgeMap = localRidgeMap(values, start, end);
  const bins = [];
  const strengths = new Map();

  for (let i = 0; i < ridgeMap.length; i++) {
    if (ridgeMap[i] >= 0.012) {
      const bin = start + i + 2;
      bins.push(bin);
      strengths.set(bin, ridgeMap[i]);
    }
  }

  return groupBins(bins, 2).map((group) => ({
    center: groupCenter(group),
    strength:
      group.reduce((sum, bin) => sum + (strengths.get(bin) || 0), 0) /
      group.length,
  }));
}

function trackFrequencyCenters(
  columns,
  {
    maxDrift = 3.5,
    maxGap = 2,
    minRun = 4,
    minHits = 4,
    minStrength = 0.05,
    scoreOffset = 1,
    scoreSpan = 3,
    mergeGap = 3.5,
  } = {}
) {
  if (columns.length < minRun) {
    return { count: 0, score: 0, bins: [] };
  }

  const tracks = [];

  for (const centers of columns) {
    for (const track of tracks) {
      track.matched = false;
      track.gap += 1;
    }

    for (const center of centers
      .slice()
      .sort((a, b) => b.strength - a.strength)) {
      let bestTrack = null;
      let bestDistance = Infinity;

      for (const track of tracks) {
        const distance = Math.abs(track.center - center.center);
        if (!track.matched && track.gap <= maxGap && distance <= maxDrift) {
          if (distance < bestDistance) {
            bestDistance = distance;
            bestTrack = track;
          }
        }
      }

      if (bestTrack) {
        bestTrack.center = bestTrack.center * 0.72 + center.center * 0.28;
        bestTrack.hits += 1;
        bestTrack.run += 1;
        bestTrack.maxRun = Math.max(bestTrack.maxRun, bestTrack.run);
        bestTrack.strength += center.strength;
        bestTrack.gap = 0;
        bestTrack.matched = true;
      } else {
        tracks.push({
          center: center.center,
          hits: 1,
          run: 1,
          maxRun: 1,
          strength: center.strength,
          gap: 0,
          matched: true,
        });
      }
    }

    for (const track of tracks) {
      if (!track.matched && track.gap > maxGap - 1) {
        track.run = 0;
      }
    }
  }

  const bins = mergeCenters(
    tracks
      .filter(
        (track) =>
          track.maxRun >= minRun &&
          track.hits >= minHits &&
          track.strength / track.hits >= minStrength
      )
      .map((track) => ({
        center: track.center,
        strength: track.strength / track.hits,
      })),
    mergeGap
  ).map((track) => Math.round(track.center));

  return {
    count: bins.length,
    score: clamp01((bins.length - scoreOffset) / scoreSpan),
    bins,
  };
}

function countTrackedHorizontalBands(history, start, end) {
  if (history.length < 4) {
    return { count: 0, score: 0, bins: [] };
  }

  const columns = [];
  const from = Math.max(2, history.length - 12);

  for (let i = from; i < history.length; i++) {
    const sobel = sobelEdgesForTriplet(
      history[i - 2],
      history[i - 1],
      history[i],
      start,
      end
    );
    columns.push(
      mergeCenters(
        horizontalSobelCenters(sobel, start, end),
        2.5
      )
    );
  }

  return trackFrequencyCenters(columns, {
    maxDrift: 3.5,
    maxGap: 2,
    minRun: 4,
    minHits: 4,
    minStrength: 0.09,
  });
}

function countTrackedRidgeBands(history, start, end) {
  if (history.length < 4) {
    return { count: 0, score: 0, bins: [] };
  }

  const columns = [];
  const from = Math.max(0, history.length - 12);

  for (let i = from; i < history.length; i++) {
    columns.push(mergeCenters(ridgeCenters(history[i], start, end), 2.5));
  }

  return trackFrequencyCenters(columns, {
    maxDrift: 3.0,
    maxGap: 1,
    minRun: 4,
    minHits: 4,
    minStrength: 0.014,
  });
}

function mergeBandBins(bins, maxGap = 3.5) {
  return mergeCenters(
    bins.map((bin) => ({
      center: bin,
      strength: 1,
    })),
    maxGap
  ).map((track) => Math.round(track.center));
}

function spectralFluxStability(history, start, end) {
  const recent = history.slice(-8);
  if (recent.length < 4) {
    return 0;
  }

  let diff = 0;
  let energy = 0;

  for (let t = 1; t < recent.length; t++) {
    for (let i = start; i < end; i++) {
      diff += Math.abs(recent[t][i] - recent[t - 1][i]);
      energy += Math.max(recent[t][i], recent[t - 1][i]);
    }
  }

  if (energy <= 0) {
    return 0;
  }

  const flux = diff / energy;
  return clamp01((0.62 - flux) / 0.38);
}

function broadbandRejection(values, start, end) {
  const active = values
    .slice(start, end)
    .filter((value) => value >= 0.32).length;
  const ratio = active / (end - start);
  const enoughStructure = clamp01((ratio - 0.08) / 0.12);
  const notBroadband = clamp01((0.72 - ratio) / 0.22);
  return {
    ratio,
    score: enoughStructure * notBroadband,
  };
}

function edgeContinuityScore(history, start, end) {
  const recent = history.slice(-7);
  if (recent.length < 4) {
    return 0;
  }

  const edgeMaps = recent.map((frame) => frequencyEdges(frame, start, end));
  let total = 0;
  let count = 0;

  for (let i = 1; i < edgeMaps.length; i++) {
    total += vectorSimilarity(edgeMaps[i - 1], edgeMaps[i]);
    count++;
  }

  return clamp01(total / count);
}

function speechPatternComponents(frame, history) {
  const energy = frameEnergyScore(frame);
  const values = Array.from(frame.raw, (value) => value / 255);
  const total = values.reduce((sum, value) => sum + value, 0);
  if (total <= 0) {
    return { ...emptyPatternComponents(), energy };
  }

  const bandSum = (start, end) =>
    values.slice(start, end).reduce((sum, value) => sum + value, 0);
  const speechBandRatio = bandSum(speechBand.start, speechBand.end) / total;
  const highBandRatio = bandSum(speechBand.end, values.length) / total;
  const centroid =
    values.reduce((sum, value, index) => sum + value * index, 0) /
    (total * (values.length - 1));

  const bandScore =
    clamp01((speechBandRatio - 0.3) / 0.28) *
    clamp01((0.75 - highBandRatio) / 0.35);
  const centroidScore =
    centroid >= 0.12 && centroid <= 0.78
      ? 1
      : clamp01(1 - Math.min(Math.abs(centroid - 0.45), 0.45) / 0.45);
  const sustainedEdges = sustainedEdgeStructure(
    history,
    speechBand.start,
    speechBand.end
  );
  const sustainedSobel = sustainedSobelStructure(
    history,
    speechBand.start,
    speechBand.end
  );
  const sustainedRidges = sustainedRidgeStructure(
    history,
    speechBand.start,
    speechBand.end
  );
  const trackedSobelBands = countTrackedHorizontalBands(
    history,
    speechBand.start,
    speechBand.end
  );
  const trackedRidgeBands = countTrackedRidgeBands(
    history,
    speechBand.start,
    speechBand.end
  );
  const trackedBands = {
    bins: mergeBandBins([
      ...trackedSobelBands.bins,
      ...trackedRidgeBands.bins,
      ...sustainedRidges.bins,
    ]),
  };
  trackedBands.count = trackedBands.bins.length;
  trackedBands.score = Math.max(
    trackedSobelBands.score,
    trackedRidgeBands.score,
    clamp01((trackedBands.count - 1) / 3)
  );
  const harmonicScore = Math.max(
    harmonicSpacingScore(sustainedEdges.bins),
    harmonicSpacingScore(sustainedRidges.bins),
    harmonicSpacingScore(sustainedSobel.bins),
    harmonicSpacingScore(trackedBands.bins)
  );
  const edgeContinuity = edgeContinuityScore(
    history,
    speechBand.start,
    speechBand.end
  );
  const fluxStability = spectralFluxStability(
    history,
    speechBand.start,
    speechBand.end
  );
  const broadbandGate = broadbandRejection(
    values,
    speechBand.start,
    speechBand.end
  );
  const horizontalBands = trackedBands.count;
  const horizontalBandScore = clamp01(
    (horizontalBands - vadGate.minHorizontalBands + 1) /
      (vadGate.targetHorizontalBands - vadGate.minHorizontalBands + 1)
  );

  const structureScore =
    Math.max(
      sustainedEdges.score,
      sustainedRidges.score,
      sustainedSobel.score,
      trackedSobelBands.score,
      trackedRidgeBands.score,
      trackedBands.score
    ) * 0.35 +
    harmonicScore * 0.2 +
    horizontalBandScore * 0.2 +
    edgeContinuity * 0.1 +
    fluxStability * 0.05 +
    bandScore * 0.05 +
    centroidScore * 0.05;

  return {
    pattern: structureScore * broadbandGate.score,
    edges: Math.max(
      sustainedEdges.score,
      sustainedSobel.score,
      trackedSobelBands.score
    ),
    ridges: Math.max(sustainedRidges.score, trackedRidgeBands.score),
    harmonic: harmonicScore,
    continuity: edgeContinuity,
    flux: fluxStability,
    bands: horizontalBands,
    bandBalance: bandScore,
    centroid: centroidScore,
    noise: broadbandGate.score,
    energy,
    activeRatio: broadbandGate.ratio,
  };
}

function startUi() {
  const ctx = canvas.getContext("2d");
  const columnWidth = 1;
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  addFrame = (frame, vad, edgeOverlay) => {
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
      const meterRows = 2 * (vad ? 6 : 4);
      const arr = new Uint8ClampedArray((nMels + meterRows) * 4);

      for (let i = 0; i < columnData.length; i++) {
        const [r, g, b] = colorizeGrayscaleValue(
          columnData[i],
          vad ? "plasma" : "cividis",
          false
        );
        const edge = edgeOverlay?.[nMels - 1 - i];
        const overlayAlpha = edge
          ? clamp01((edge.magnitude - sobelOverlayThreshold) / 0.22)
          : 0;
        const overlayColor =
          edge && edge.horizontal >= edge.temporal * 0.7
            ? [0, 241, 255]
            : [255, 190, 64];
        arr[i * 4 + 0] = Math.round(
          r * (1 - overlayAlpha) + overlayColor[0] * overlayAlpha
        );
        arr[i * 4 + 1] = Math.round(
          g * (1 - overlayAlpha) + overlayColor[1] * overlayAlpha
        );
        arr[i * 4 + 2] = Math.round(
          b * (1 - overlayAlpha) + overlayColor[2] * overlayAlpha
        );
        arr[i * 4 + 3] = 255;
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
    updateComponentScores(emptyPatternComponents());
  };

  const filterVad = (frame) => {
    patternHistory.push(Array.from(frame.raw, (value) => value / 255));
    if (patternHistory.length > 16) {
      patternHistory.shift();
    }

    const components = speechPatternComponents(frame, patternHistory);
    frame.sobelEdges = sobelEdgeColumn(
      patternHistory,
      speechBand.start,
      speechBand.end
    );
    if (!hasAcousticEnergy(frame)) {
      updateComponentScores({
        ...emptyPatternComponents(),
        energy: components.energy,
      });
      rawSilenceRun++;
      rawSpeechRun = 0;
      if (gatedVad && rawSilenceRun >= 2) {
        gatedVad = false;
      }
      return false;
    }

    updateComponentScores(components);
    const enoughSpeechBands =
      components.bands >= vadGate.targetHorizontalBands ||
      (components.bands >= vadGate.minHorizontalBands &&
        components.edges >= 0.3 &&
        components.noise >= 0.4);
    const rawVad =
      enoughSpeechBands &&
      (vadGate.minPatternScore === 0 ||
        components.pattern >= vadGate.minPatternScore ||
        components.edges >= 0.5 ||
        components.ridges >= 0.5);

    if (rawVad) {
      rawSpeechRun++;
      rawSilenceRun = 0;
    } else {
      rawSilenceRun++;
      rawSpeechRun = 0;
    }

    if (!gatedVad && rawSpeechRun >= vadGate.onFrames) {
      gatedVad = true;
    }

    if (gatedVad && rawSilenceRun >= vadGate.offFrames) {
      gatedVad = false;
    }

    return gatedVad;
  };

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

    if (speechFrames === 0 && frames.length > vadGate.maxPreSpeechFrames) {
      frames.splice(0, frames.length - vadGate.maxPreSpeechFrames);
      silenceFrames = 0;
      return;
    }

    if (
      speechFrames > 0 &&
      silenceFrames >= vadGate.trailingSilenceFrames &&
      frames.length >= vadGate.minSegmentFrames
    ) {
      const speechRatio = speechFrames / frames.length;
      if (
        speechFrames >= vadGate.minSpeechFrames &&
        speechRatio >= vadGate.minSpeechRatio
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
      addFrame(frame.luma, frame.vad, frame.sobelEdges);
      accumulateFrame(frame);
    }
  }, 10);
}

async function startAudioProcessing(context) {
  audioStream = await navigator.mediaDevices.getUserMedia({
    audio: {
      autoGainControl: false,
      echoCancellation: false,
      noiseSuppression: false,
      channelCount: 1,
      sampleRate: samplingRate,
    },
  });
  const volume = context.createGain();
  const audioInput = context.createMediaStreamSource(audioStream);
  audioInput.connect(volume);

  await context.audioWorklet.addModule(assetUrl("dist/worklet.js?v=20260515-6"));

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
  let min = Infinity;
  let max = -Infinity;

  for (let i = 0; i < frame.length; i++) {
    const value = frame[i];
    if (value < min) {
      min = value;
    }
    if (value > max) {
      max = value;
    }
  }

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
