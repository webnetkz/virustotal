const apiKeyInput = document.getElementById("api-key");
const saveBtn = document.getElementById("save-btn");
const statusEl = document.getElementById("status");
const ENABLE_DEBUG_LOGS = false;

saveBtn.addEventListener("click", save);
load();

async function load() {
  try {
    const data = await chrome.storage.sync.get(["vtApiKey"]);
    apiKeyInput.value = data.vtApiKey || "";
    setStatus("Ready.", "info");
  } catch (error) {
    logError(error);
    setStatus("Could not load saved API key.", "error");
  }
}

async function save() {
  const value = apiKeyInput.value.trim();

  if (!value) {
    setStatus("Enter an API key before saving.", "error");
    return;
  }

  saveBtn.disabled = true;
  setStatus("Saving...", "info");

  try {
    await chrome.storage.sync.set({ vtApiKey: value });
    setStatus("Saved.", "success");
  } catch (error) {
    logError(error);
    setStatus("Failed to save API key.", "error");
  } finally {
    saveBtn.disabled = false;
  }
}

function setStatus(message, kind = "info") {
  statusEl.textContent = message;
  statusEl.classList.remove("info", "error", "success");
  statusEl.classList.add(kind);
}

function logError(error) {
  if (ENABLE_DEBUG_LOGS) {
    console.error(error);
  }
}
