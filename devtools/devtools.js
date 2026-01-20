// /devtools/devtools.js

// This script is executed in the context of the DevTools window.
// Its primary purpose is to create the "Crypto Detective" panel.

try {
  chrome.devtools.panels.create(
    'Crypto Detective',      // Title of the panel
    'icons/icon16.png',      // Icon for the panel tab
    'panel/panel.html',      // HTML page to load into the panel's iframe
    (panel) => {
      // A callback that runs after the panel has been created.
      // We could add listeners here for when the panel is shown or hidden,
      // but for now, a simple confirmation is enough.
      panel.onShown.addListener(() => console.log('Crypto Detective panel shown.'));
      panel.onHidden.addListener(() => console.log('Crypto Detective panel hidden.'));
    }
  );
} catch (e) {
  console.error("Error creating Crypto Detective devtools panel:", e);
}
