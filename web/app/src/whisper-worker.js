let moduleUrl = "";
let modelUrl = "";
let language = "en";
let nThreads = 4;
let whisperModule = null;
let whisperInstance = 0;
let initPromise = null;

function postStatus(message) {
  postMessage({ type: "status", message });
}

async function cachedFetchBytes(url) {
  let cache = null;
  if ("caches" in self) {
    try {
      cache = await caches.open("hush-whisper-models-v1");
      const cached = await cache.match(url);
      if (cached) {
        postStatus("Whisper model loaded from browser cache.");
        return new Uint8Array(await cached.arrayBuffer());
      }
    } catch (error) {
      postStatus(`Whisper cache unavailable: ${error.message}`);
      cache = null;
    }
  }

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`model fetch failed: ${response.status}`);
  }

  const bytes = new Uint8Array(await response.clone().arrayBuffer());
  if (cache) {
    try {
      await cache.put(url, response);
    } catch (error) {
      postStatus(`Whisper model cache write skipped: ${error.message}`);
    }
  }
  return bytes;
}

async function initWhisper() {
  if (whisperInstance) {
    return;
  }

  postStatus("Loading Whisper WASM.");
  importScripts(moduleUrl);
  whisperModule = await whisper_factory({
    print: (text) => postMessage({ type: "log", message: text }),
    printErr: (text) => postMessage({ type: "log", message: text }),
    setStatus: postStatus,
  });

  postStatus("Fetching Whisper model.");
  const model = await cachedFetchBytes(modelUrl);
  try {
    whisperModule.FS_unlink("whisper.bin");
  } catch (_) {
    // The file does not exist on first load.
  }
  whisperModule.FS_createDataFile("/", "whisper.bin", model, true, true);

  postStatus("Initializing Whisper model.");
  whisperInstance = whisperModule.init("whisper.bin");
  if (!whisperInstance) {
    throw new Error("Whisper model initialization failed");
  }

  postMessage({ type: "ready" });
}

async function ensureInit() {
  if (!initPromise) {
    initPromise = initWhisper();
  }
  await initPromise;
}

async function transcribe(job) {
  await ensureInit();
  const started = performance.now();
  const text = whisperModule.full_default_mel(
    whisperInstance,
    job.mel,
    job.nMels,
    language,
    nThreads,
    false
  );
  const elapsedMs = Math.round(performance.now() - started);

  if (typeof text === "string" && text.startsWith("ERROR:")) {
    postMessage({ type: "error", id: job.id, message: text });
    return;
  }

  postMessage({
    type: "result",
    id: job.id,
    text: String(text || "").trim(),
    elapsedMs,
  });
}

self.onmessage = (event) => {
  const message = event.data || {};

  if (message.type === "init") {
    moduleUrl = message.moduleUrl;
    modelUrl = message.modelUrl;
    language = message.language || "en";
    nThreads = message.nThreads || 4;
    ensureInit().catch((error) =>
      postMessage({ type: "fatal", message: error.message })
    );
    return;
  }

  if (message.type === "transcribe") {
    transcribe(message).catch((error) =>
      postMessage({ type: "error", id: message.id, message: error.message })
    );
  }
};
