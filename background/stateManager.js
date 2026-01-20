// /background/stateManager.js

const MAX_LOGS = 500;
let logs = [];

// Note: The original plan asked for exporting a `state` object.
// While direct export of a `let` binding isn't possible,
// we can export functions that provide access to the state, which is a cleaner pattern.

/**
 * Adds a new log entry to the in-memory log store.
 * The store is capped at MAX_LOGS entries.
 * @param {object} logEntry - The log object to add.
 */
export function addLog(logEntry) {
  logs.unshift(logEntry); // Add to the beginning for most recent first
  if (logs.length > MAX_LOGS) {
    logs.length = MAX_LOGS; // Cap the array size by trimming the end
  }
}

/**
 * Clears all logs from the in-memory store.
 */
export function clearLogs() {
  logs = [];
}

/**
 * Retrieves the current array of log entries.
 * @returns {Array<object>}
 */
export function getLogs() {
  return logs;
}

/**
 * Retrieves the current monitoring status from chrome.storage.local.
 * Defaults to `true` if the value is not set.
 * @returns {Promise<boolean>} A promise that resolves to the monitoring status.
 */
export async function getMonitoringStatus() {
  return new Promise((resolve) => {
    chrome.storage.local.get("isMonitoringEnabled", (result) => {
      // Default to true if it's undefined
      resolve(result.isMonitoringEnabled !== false);
    });
  });
}

/**
 * Sets the monitoring status in chrome.storage.local.
 * @param {boolean} isEnabled - The new monitoring status.
 * @returns {Promise<void>} A promise that resolves when the value is set.
 */
export async function setMonitoringStatus(isEnabled) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ isMonitoringEnabled: isEnabled }, () => {
        resolve();
    });
  });
}
