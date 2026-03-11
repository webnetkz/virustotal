const VT_API_BASE = "https://www.virustotal.com/api/v3";
const VT_FILE_INLINE_UPLOAD_MAX = 32 * 1024 * 1024;
const POLL_INTERVAL_MS = 3000;
const POLL_MAX_ATTEMPTS = 20;
const ENABLE_DEBUG_LOGS = false;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then((result) => safeSendResponse(sendResponse, { ok: true, result }))
    .catch((error) => {
      logError("VirusTotal extension error:", error);
      safeSendResponse(sendResponse, { ok: false, error: toPublicErrorMessage(error) });
    });

  return true;
});

function safeSendResponse(sendResponse, payload) {
  try {
    sendResponse(payload);
  } catch (_error) {
    // Popup can be closed before async response arrives.
  }
}

function logError(...args) {
  if (ENABLE_DEBUG_LOGS) {
    console.error(...args);
  }
}

function toPublicErrorMessage(error) {
  const message = String(error?.message || "Unknown error");
  if (message === "Failed to fetch" || message.includes("NetworkError")) {
    return "Network request failed. Check internet connection and try again.";
  }

  return message;
}

async function handleMessage(message) {
  if (!message || !message.type) {
    throw new Error("Invalid message payload.");
  }

  if (message.type === "checkUrl") {
    return checkUrl(message.url);
  }

  if (message.type === "checkFile") {
    return checkFile(message.file);
  }

  throw new Error(`Unsupported message type: ${message.type}`);
}

async function getApiKey() {
  const data = await chrome.storage.sync.get(["vtApiKey"]);
  const key = (data.vtApiKey || "").trim();

  if (!key) {
    throw new Error("API key not set. Open extension options and add your VirusTotal API key.");
  }

  return key;
}

async function vtFetch(path, apiKey, options = {}) {
  let response;
  try {
    response = await fetch(`${VT_API_BASE}${path}`, {
      ...options,
      headers: {
        "x-apikey": apiKey,
        ...(options.headers || {})
      }
    });
  } catch (_error) {
    throw new Error("Network request failed. Check internet connection and try again.");
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch (_error) {
    payload = null;
  }

  if (!response.ok) {
    const detail = payload?.error?.message || `HTTP ${response.status}`;
    const error = new Error(`VirusTotal API error: ${detail}`);
    error.status = response.status;
    throw error;
  }

  return payload;
}

function toBase64Url(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function checkUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") {
    throw new Error("No URL provided.");
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_error) {
    throw new Error("Invalid URL format.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only http/https URLs are supported.");
  }

  const apiKey = await getApiKey();
  const urlId = toBase64Url(parsed.href);

  try {
    const report = await vtFetch(`/urls/${urlId}`, apiKey);
    return formatUrlReport(parsed.href, report, "report");
  } catch (error) {
    if (error.status !== 404) {
      throw error;
    }
  }

  const form = new URLSearchParams();
  form.append("url", parsed.href);
  const submitResponse = await vtFetch("/urls", apiKey, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: form
  });

  const analysisId = submitResponse?.data?.id;
  if (!analysisId) {
    throw new Error("VirusTotal returned an invalid URL analysis response.");
  }

  const analysis = await pollAnalysis(analysisId, apiKey);
  return formatAnalysis(parsed.href, analysis, "url");
}

async function checkFile(file) {
  if (!file) {
    throw new Error("No file selected.");
  }

  const apiKey = await getApiKey();
  const hash = await sha256(file);

  try {
    const report = await vtFetch(`/files/${hash}`, apiKey);
    return formatFileReport(file.name, hash, report, "report");
  } catch (error) {
    if (error.status !== 404) {
      throw error;
    }
  }

  const analysisId = await uploadFileAndGetAnalysisId(file, apiKey);
  const analysis = await pollAnalysis(analysisId, apiKey);

  return formatAnalysis(file.name, analysis, "file", hash);
}

async function uploadFileAndGetAnalysisId(file, apiKey) {
  const form = new FormData();
  form.append("file", file, file.name || "upload.bin");

  if (file.size <= VT_FILE_INLINE_UPLOAD_MAX) {
    const uploadResponse = await vtFetch("/files", apiKey, {
      method: "POST",
      body: form
    });
    const analysisId = uploadResponse?.data?.id;

    if (!analysisId) {
      throw new Error("VirusTotal returned an invalid file upload response.");
    }

    return analysisId;
  }

  const uploadUrlResponse = await vtFetch("/files/upload_url", apiKey, { method: "GET" });
  const uploadUrl = uploadUrlResponse?.data;

  if (!uploadUrl) {
    throw new Error("VirusTotal did not provide an upload URL for a large file.");
  }

  let response;
  try {
    response = await fetch(uploadUrl, {
      method: "POST",
      headers: {
        "x-apikey": apiKey
      },
      body: form
    });
  } catch (_error) {
    throw new Error("Network request failed. Check internet connection and try again.");
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch (_error) {
    payload = null;
  }

  if (!response.ok) {
    const detail = payload?.error?.message || `HTTP ${response.status}`;
    throw new Error(`VirusTotal upload error: ${detail}`);
  }

  const analysisId = payload?.data?.id;
  if (!analysisId) {
    throw new Error("VirusTotal returned an invalid large-file upload response.");
  }

  return analysisId;
}

async function pollAnalysis(analysisId, apiKey) {
  for (let attempt = 0; attempt < POLL_MAX_ATTEMPTS; attempt += 1) {
    const analysis = await vtFetch(`/analyses/${analysisId}`, apiKey);
    const status = analysis?.data?.attributes?.status;

    if (status === "completed") {
      return analysis;
    }

    await sleep(POLL_INTERVAL_MS);
  }

  throw new Error("Timed out waiting for VirusTotal analysis to complete.");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sha256(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function formatStats(stats = {}) {
  return {
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    undetected: Number(stats.undetected || 0),
    harmless: Number(stats.harmless || 0),
    timeout: Number(stats.timeout || 0)
  };
}

function formatUrlReport(url, report, source) {
  const attrs = report?.data?.attributes || {};
  return {
    kind: "url",
    source,
    target: url,
    stats: formatStats(attrs.last_analysis_stats),
    lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    vtLink: `https://www.virustotal.com/gui/url/${report?.data?.id || ""}`
  };
}

function formatFileReport(fileName, hash, report, source) {
  const attrs = report?.data?.attributes || {};

  return {
    kind: "file",
    source,
    target: fileName,
    sha256: hash,
    stats: formatStats(attrs.last_analysis_stats),
    lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    vtLink: `https://www.virustotal.com/gui/file/${report?.data?.id || hash}`
  };
}

function formatAnalysis(target, analysis, kind, hash = null) {
  const attrs = analysis?.data?.attributes || {};

  return {
    kind,
    source: "analysis",
    target,
    sha256: hash,
    stats: formatStats(attrs.stats),
    lastAnalysisDate: new Date().toISOString(),
    vtLink: null
  };
}
