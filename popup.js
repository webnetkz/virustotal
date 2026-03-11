const checkSiteBtn = document.getElementById("check-site-btn");
const checkFileBtn = document.getElementById("check-file-btn");
const chooseFileBtn = document.getElementById("choose-file-btn");
const fileInput = document.getElementById("file-input");
const fileNameEl = document.getElementById("file-name");
const statusEl = document.getElementById("status");
const humanResultEl = document.getElementById("human-result");
const humanTitleEl = document.getElementById("human-title");
const humanTextEl = document.getElementById("human-text");
const humanStatsEl = document.getElementById("human-stats");
const humanLinkEl = document.getElementById("human-link");
const resultEl = document.getElementById("result");
const loadingOverlayEl = document.getElementById("loading-overlay");
const loadingTextEl = document.getElementById("loading-text");
const SITE_SCAN_TIMEOUT_MS = 90_000;
const FILE_SCAN_TIMEOUT_MS = 180_000;
const ENABLE_DEBUG_LOGS = false;

checkSiteBtn.addEventListener("click", onCheckSite);
checkFileBtn.addEventListener("click", onCheckFile);
chooseFileBtn.addEventListener("click", onChooseFile);
fileInput.addEventListener("change", syncSelectedFileName);

init();

async function init() {
  try {
    const data = await chrome.storage.sync.get(["vtApiKey"]);
    if (!data.vtApiKey) {
      setStatus("API key is not set. Open extension settings.", "error");
      renderErrorSummary("Add your API key in settings before running a scan.");
      renderErrorDetails("API key is missing.");
    }
  } catch (error) {
    logError(error);
    setStatus("Failed to read settings.", "error");
    renderErrorSummary("Could not load extension settings.");
    renderErrorDetails("Could not load extension settings.");
  }
}

async function onCheckSite() {
  lockUI(true, "Scanning current site...");
  setStatus("Detecting active tab URL...", "info");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
      throw new Error("Could not get the current tab URL.");
    }

    setStatus("Checking site in VirusTotal...", "info");
    const response = await withTimeout(
      sendMessage({ type: "checkUrl", url: tab.url }),
      SITE_SCAN_TIMEOUT_MS,
      "Site check timed out. Please try again."
    );

    if (!response.ok) {
      throw new Error(response.error || "Unknown error");
    }

    renderResult(response.result);
    setStatus("Site check completed.", "success");
  } catch (error) {
    logError(error);
    const message = error.message || "Error while checking the site.";
    setStatus(message, "error");
    renderErrorSummary(message);
    renderErrorDetails(message);
  } finally {
    lockUI(false);
  }
}

async function onCheckFile() {
  lockUI(true, "Uploading and scanning file...");

  try {
    const file = fileInput.files?.[0];
    if (!file) {
      throw new Error("Файл не выбран.");
    }

    setStatus("Uploading file and requesting VirusTotal analysis...", "info");
    const response = await withTimeout(
      sendMessage({ type: "checkFile", file }),
      FILE_SCAN_TIMEOUT_MS,
      "File check timed out. Please try again."
    );

    if (!response.ok) {
      throw new Error(response.error || "Unknown error");
    }

    renderResult(response.result);
    setStatus("File check completed.", "success");
  } catch (error) {
    logError(error);
    const message = error.message || "Error while checking the file.";
    setStatus(message, "error");
    renderErrorSummary(message);
    renderErrorDetails(message);
  } finally {
    lockUI(false);
  }
}

function sendMessage(message) {
  return chrome.runtime.sendMessage(message);
}

function withTimeout(promise, timeoutMs, timeoutMessage) {
  let timeoutId = null;

  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(timeoutMessage));
    }, timeoutMs);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  });
}

function lockUI(locked, loadingText) {
  checkSiteBtn.disabled = locked;
  checkFileBtn.disabled = locked;
  chooseFileBtn.disabled = locked;
  fileInput.disabled = locked;

  if (locked) {
    setLoadingText(loadingText);
    loadingOverlayEl.classList.remove("hidden");
  } else {
    setLoadingText("Scanning in progress...");
    loadingOverlayEl.classList.add("hidden");
  }
}

function onChooseFile() {
  if (fileInput.disabled) {
    return;
  }

  fileInput.click();
}

function syncSelectedFileName() {
  const file = fileInput.files?.[0];
  fileNameEl.textContent = file ? truncateFileName(file.name) : "Файл не выбран";
}

function setLoadingText(text) {
  if (!loadingTextEl) {
    return;
  }

  loadingTextEl.textContent = text || "Scanning in progress...";
}

function logError(error) {
  if (ENABLE_DEBUG_LOGS) {
    console.error(error);
  }
}

function setStatus(message, kind = "info") {
  statusEl.textContent = message;
  statusEl.classList.remove("info", "error", "success");
  if (kind) {
    statusEl.classList.add(kind);
  }
}

function renderResult(result) {
  if (!result) {
    renderEmptySummary();
    resultEl.textContent = "No details yet.";
    return;
  }

  const verdict = makeVerdict(result.stats);
  const output = {
    type: result.kind,
    source: result.source,
    target: result.target,
    sha256: result.sha256 || undefined,
    verdict,
    stats: result.stats,
    lastAnalysisDate: result.lastAnalysisDate,
    link: result.vtLink || "Unavailable"
  };

  renderHumanSummary(result, verdict);
  resultEl.textContent = JSON.stringify(output, null, 2);
}

function makeVerdict(stats = {}) {
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);

  if (malicious > 0) {
    return "malicious";
  }

  if (suspicious > 0) {
    return "suspicious";
  }

  return "clean_or_undetected";
}

function renderHumanSummary(result, verdict) {
  const stats = normalizeStats(result.stats);
  const targetType = result.kind === "file" ? "file" : "site";
  const targetName = shortenTarget(result.target);

  let stateClass = "safe";
  let title = "No malicious detections found.";
  let text = `This ${targetType} looks clean based on current VirusTotal checks.`;

  if (verdict === "malicious") {
    stateClass = "danger";
    title = `High risk: ${stats.malicious} engines flagged this as malicious.`;
    text = `Treat this ${targetType} as unsafe until you verify it manually.`;
  } else if (verdict === "suspicious") {
    stateClass = "warning";
    title = `Caution: ${stats.suspicious} engines flagged this as suspicious.`;
    text = `Use extra caution before opening or visiting this ${targetType}.`;
  }

  const timeoutPart = stats.timeout > 0 ? `, Timeout: ${stats.timeout}` : "";
  const statsLine =
    `Target: ${targetName}\n` +
    `Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}, Harmless: ${stats.harmless}, Undetected: ${stats.undetected}${timeoutPart}`;

  humanTitleEl.textContent = title;
  humanTextEl.textContent = text;
  humanStatsEl.textContent = statsLine;

  humanResultEl.classList.remove("neutral", "safe", "warning", "danger");
  humanResultEl.classList.add(stateClass);

  if (result.vtLink) {
    humanLinkEl.href = result.vtLink;
    humanLinkEl.classList.remove("hidden");
  } else {
    humanLinkEl.removeAttribute("href");
    humanLinkEl.classList.add("hidden");
  }
}

function renderEmptySummary() {
  humanResultEl.classList.remove("safe", "warning", "danger");
  humanResultEl.classList.add("neutral");
  humanTitleEl.textContent = "No scan yet";
  humanTextEl.textContent = "Run a scan to get a simple verdict.";
  humanStatsEl.textContent = "No statistics yet.";
  humanLinkEl.removeAttribute("href");
  humanLinkEl.classList.add("hidden");
}

function renderErrorSummary(message) {
  humanResultEl.classList.remove("neutral", "safe", "warning");
  humanResultEl.classList.add("danger");
  humanTitleEl.textContent = "Could not complete the scan.";
  humanTextEl.textContent = message;
  humanStatsEl.textContent = "Fix the issue and run the scan again.";
  humanLinkEl.removeAttribute("href");
  humanLinkEl.classList.add("hidden");
}

function renderErrorDetails(message) {
  resultEl.textContent = JSON.stringify(
    {
      ok: false,
      error: message
    },
    null,
    2
  );
}

function normalizeStats(stats = {}) {
  return {
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0)
  };
}

function shortenTarget(value) {
  if (!value || typeof value !== "string") {
    return "Unknown target";
  }

  if (value.length <= 60) {
    return value;
  }

  return `${value.slice(0, 57)}...`;
}

function truncateFileName(value) {
  if (!value || typeof value !== "string") {
    return "Файл не выбран";
  }

  if (value.length <= 44) {
    return value;
  }

  return `${value.slice(0, 41)}...`;
}
