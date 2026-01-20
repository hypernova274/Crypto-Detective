// /background/messageRouter.js

import * as stateManager from './stateManager.js';

let uiPorts = [];

/**
 * Broadcasts a message to all connected UI components (Popup, DevTools Panel).
 * @param {object} message - The message to send.
 */
function broadcastToUI(message) {
  // Make a copy of the array to avoid issues if a port disconnects during iteration
  const portsToNotify = [...uiPorts];
  portsToNotify.forEach(port => {
    try {
      port.postMessage(message);
    } catch (e) {
      console.error("Failed to post message to a UI port, it may have been disconnected.", e);
      // The onDisconnect listener below will handle the actual removal.
    }
  });
}

/**
 * Handles incoming connections from UI components.
 * @param {chrome.runtime.Port} port - The port from the connecting UI.
 */
function handleConnection(port) {
  // We'll give our UI ports a specific name to identify them.
  if (port.name === 'crypto-detective-ui') {
    uiPorts.push(port);
    port.onDisconnect.addListener(() => {
      uiPorts = uiPorts.filter(p => p !== port);
    });
  }
}

/**
 * Handles one-off messages from content scripts or UI components.
 * This function acts as the main router for incoming requests.
 * @param {object} message - The incoming message.
 * @param {chrome.runtime.MessageSender} sender - The sender of the message.
 * @param {function} sendResponse - The function to call to send a response.
 * @returns {boolean} - Returns true to indicate the response will be sent asynchronously.
 */
function handleMessage(message, sender, sendResponse) {
  // Using an async IIFE to handle async operations within the sync listener
  (async () => {
    switch (message.type) {
      case "CRYPTO_OPERATION":
        const isMonitoring = await stateManager.getMonitoringStatus();
        if (isMonitoring) {
          stateManager.addLog(message.payload);
          // 更新徽章计数
          try {
            const count = stateManager.getLogs().length;
            if (chrome.action && chrome.action.setBadgeText) {
              chrome.action.setBadgeText({ text: String(Math.min(count, 999)) });
              chrome.action.setBadgeBackgroundColor && chrome.action.setBadgeBackgroundColor({ color: '#0052cc' });
            }
          } catch (e) {}
          broadcastToUI({ type: "NEW_LOG", payload: message.payload });
        }
        break;

      case "GET_INITIAL_DATA":
        const status = await stateManager.getMonitoringStatus();
        const logs = stateManager.getLogs();
        sendResponse({ status, logs });
        break;

      case "TOGGLE_MONITORING":
        await stateManager.setMonitoringStatus(message.isEnabled);
        // We can broadcast this change if UIs need to react instantly, e.g., disable their view.
        broadcastToUI({ type: "MONITORING_STATUS_CHANGED", payload: { isEnabled: message.isEnabled } });
        break;

      case "CLEAR_LOGS":
        stateManager.clearLogs();
        try {
          if (chrome.action && chrome.action.setBadgeText) {
            chrome.action.setBadgeText({ text: '' });
          }
        } catch (e) {}
        broadcastToUI({ type: "LOGS_CLEARED" });
        break;
    }
  })();

  // Return true to indicate that we will be calling sendResponse asynchronously.
  // This is crucial for cases like GET_INITIAL_DATA.
  return true;
}

/**
 * Sets up the primary message and connection listeners for the extension.
 * This should be called once when the service worker starts.
 */
export function setupListeners() {
  chrome.runtime.onConnect.addListener(handleConnection);
  chrome.runtime.onMessage.addListener(handleMessage);
}
