// /content/hooks/jsEncryptHook.js

/**
 * Helper to safely extract a summary of the key from a JSEncrypt instance for logging.
 * It tries to get the first line of the public or private PEM.
 * @param {object} jsEncryptInstance - The `this` context of the encrypt/decrypt call.
 * @returns {string} A brief string representation of the key.
 */
function getJSEncryptKeySummary(jsEncryptInstance) {
  if (!jsEncryptInstance || !jsEncryptInstance.key) return 'N/A';

  try {
    // The `key` object is typically a `jsbn.RSAKey` instance.
    // JSEncrypt doesn't directly expose the PEM on the key object,
    // but the instance itself has methods to get them.
    if (typeof jsEncryptInstance.getPublicKeyPEM === 'function') {
      const pem = jsEncryptInstance.getPublicKeyPEM();
      if (pem) return pem.split('\\n')[0].split('\n')[0]; // Handle literal and actual newlines
    }
    if (typeof jsEncryptInstance.getPrivateKeyPEM === 'function') {
      const pem = jsEncryptInstance.getPrivateKeyPEM();
      if (pem) return pem.split('\\n')[0].split('\n')[0];
    }
    return 'Key Found (Could not get PEM)';
  } catch (e) {
    return 'Key Found (Error getting PEM)';
  }
}

/**
 * Initializes hooks for the JSEncrypt library by wrapping its prototype methods.
 * @param {function} callback - The function to call with captured crypto data.
 */
export function initJsEncryptHooks(callback) {
  // JSEncrypt is typically exposed as a class on the window object.
  if (typeof window.JSEncrypt === 'undefined' || !window.JSEncrypt.prototype) {
    return;
  }

  const JSEncryptPrototype = window.JSEncrypt.prototype;

  // --- Hook Encryption ---
  if (typeof JSEncryptPrototype.encrypt === 'function') {
    const originalEncrypt = JSEncryptPrototype.encrypt;
    JSEncryptPrototype.encrypt = function(...args) {
      const result = originalEncrypt.apply(this, args);

      // JSEncrypt returns `false` if encryption fails.
      if (result) {
        callback({
          library: 'JSEncrypt',
          method: 'encrypt',
          data: {
            plaintext: String(args[0]),
            key_summary: getJSEncryptKeySummary(this),
            result_ciphertext_b64: result
          }
        });
      }
      return result;
    };
  }

  // --- Hook Decryption ---
  if (typeof JSEncryptPrototype.decrypt === 'function') {
    const originalDecrypt = JSEncryptPrototype.decrypt;
    JSEncryptPrototype.decrypt = function(...args) {
      const result = originalDecrypt.apply(this, args);

      // JSEncrypt returns `false` if decryption fails.
      if (result) {
        callback({
          library: 'JSEncrypt',
          method: 'decrypt',
          data: {
            ciphertext_b64: String(args[0]),
            key_summary: getJSEncryptKeySummary(this),
            result_plaintext: result
          }
        });
      }
      return result;
    };
  }
}
