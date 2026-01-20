// /background/background.js

import { setupListeners } from './messageRouter.js';
import { setMonitoringStatus } from './stateManager.js';

// Initialize the message routing system. This sets up all the listeners
// for messages from content scripts and connections from UI components.
setupListeners();

/**
 * Handles the initial setup when the extension is installed.
 * We use this to set a default value for our monitoring status.
 */
chrome.runtime.onInstalled.addListener((details) => {
  // On first installation, default the monitoring to be enabled.
  if (details.reason === 'install') {
    // We use the stateManager function for consistency.
    setMonitoringStatus(true);
    try {
      chrome.action && chrome.action.setBadgeText && chrome.action.setBadgeText({ text: '' });
      chrome.action && chrome.action.setBadgeBackgroundColor && chrome.action.setBadgeBackgroundColor({ color: '#0052cc' });
    } catch (e) {}
  }
});

// A simple log to confirm the service worker is running, useful for debugging.
console.log("Crypto Detective service worker started.");
