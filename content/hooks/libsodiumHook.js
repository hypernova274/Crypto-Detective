// /content/hooks/libsodiumHook.js

import { addStackTrace, checkWeakCrypto, perfMonitor } from './hookUtils.js';

/**
 * Helper to convert Sodium.js types to readable strings.
 */
function sodiumDataToString(data) {
  if (!data) return 'N/A';
  if (typeof data === 'string') return data;

  // Check if it's a Uint8Array
  if (data instanceof Uint8Array) {
    return Array.from(data)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Check if it has toString method
  if (typeof data.toString === 'function') {
    try {
      return data.toString();
    } catch (e) {
      // Fall through
    }
  }

  return '[Non-stringable data]';
}

/**
 * Initializes hooks for libsodium.js (NaCl) library.
 * @param {function} callback - The function to call with captured crypto data.
 */
export function initLibsodiumHooks(callback) {
  if (typeof window.sodium === 'undefined' && typeof window._sodium === 'undefined') {
    return; // libsodium not found
  }

  // Get sodium instance (could be window.sodium or window._sodium)
  const sodium = window.sodium || window._sodium;
  if (!sodium) return;

  const library = 'libsodium.js';

  // --- Hook crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt ---
  if (sodium.crypto_aead_xchacha20poly1305_ietf_encrypt) {
    const original = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt;
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = function(...args) {
      const opId = `${library}-xchacha20-encrypt-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'XChaCha20-Poly1305-IETF',
        message_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        additional_data: args[1] ? 'present' : 'none',
        nonce_preview: args[2] instanceof Uint8Array ? `${args[2].length} bytes` : 'unknown',
        key_preview: '***', // Don't log the actual key
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_aead_xchacha20poly1305_ietf_encrypt',
        data: captureData
      });

      return result;
    };
  }

  if (sodium.crypto_aead_xchacha20poly1305_ietf_decrypt) {
    const original = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt;
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt = function(...args) {
      const opId = `${library}-xchacha20-decrypt-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'XChaCha20-Poly1305-IETF',
        ciphertext_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        additional_data: args[1] ? 'present' : 'none',
        nonce_preview: args[2] instanceof Uint8Array ? `${args[2].length} bytes` : 'unknown',
        key_preview: '***',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_aead_xchacha20poly1305_ietf_decrypt',
        data: captureData
      });

      return result;
    };
  }

  // --- Hook crypto_box (public key encryption) ---
  if (sodium.crypto_box_easy) {
    const original = sodium.crypto_box_easy;
    sodium.crypto_box_easy = function(...args) {
      const opId = `${library}-box-encrypt-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'crypto_box (Curve25519-XSalsa20-Poly1305)',
        message_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        nonce_preview: args[1] instanceof Uint8Array ? `${args[1].length} bytes` : 'unknown',
        public_key_preview: args[2] instanceof Uint8Array ? args[2].subarray(0, 8).toString('hex') + '...' : 'unknown',
        secret_key_preview: '***',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_box_easy',
        data: captureData
      });

      return result;
    };
  }

  if (sodium.crypto_box_open_easy) {
    const original = sodium.crypto_box_open_easy;
    sodium.crypto_box_open_easy = function(...args) {
      const opId = `${library}-box-decrypt-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'crypto_box',
        ciphertext_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        nonce_preview: args[1] instanceof Uint8Array ? `${args[1].length} bytes` : 'unknown',
        public_key_preview: args[2] instanceof Uint8Array ? args[2].subarray(0, 8).toString('hex') + '...' : 'unknown',
        secret_key_preview: '***',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_box_open_easy',
        data: captureData
      });

      return result;
    };
  }

  // --- Hook crypto_sign (Ed25519 signatures) ---
  if (sodium.crypto_sign) {
    const original = sodium.crypto_sign;
    sodium.crypto_sign = function(...args) {
      const opId = `${library}-sign-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'Ed25519',
        message_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        secret_key_preview: '***',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_sign',
        data: captureData
      });

      return result;
    };
  }

  if (sodium.crypto_sign_open) {
    const original = sodium.crypto_sign_open;
    sodium.crypto_sign_open = function(...args) {
      const opId = `${library}-verify-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'Ed25519',
        signed_message_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        public_key_preview: args[1] instanceof Uint8Array ? args[1].subarray(0, 8).toString('hex') + '...' : 'unknown',
        verification_result: 'valid',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_sign_open',
        data: captureData
      });

      return result;
    };
  }

  // --- Hook crypto_scalarmult (ECDH key exchange) ---
  if (sodium.crypto_scalarmult) {
    const original = sodium.crypto_scalarmult;
    sodium.crypto_scalarmult = function(...args) {
      const opId = `${library}-scalarmult-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'Curve25519 scalar multiplication',
        secret_key_preview: '***',
        public_key_preview: args[1] instanceof Uint8Array ? args[1].subarray(0, 8).toString('hex') + '...' : 'unknown',
        shared_secret_preview: result instanceof Uint8Array ? result.subarray(0, 8).toString('hex') + '...' : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_scalarmult (ECDH)',
        data: captureData
      });

      return result;
    };
  }

  // --- Hook crypto_generichash (BLAKE2) ---
  if (sodium.crypto_generichash) {
    const original = sodium.crypto_generichash;
    sodium.crypto_generichash = function(...args) {
      const opId = `${library}-blake2-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'BLAKE2b',
        message_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        output_length: result instanceof Uint8Array ? result.length : 'unknown',
        result_hash_hex: result instanceof Uint8Array ? sodiumDataToString(result) : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_generichash',
        data: captureData
      });

      return result;
    };
  }

  // --- Hook crypto_pwhash (Argon2) ---
  if (sodium.crypto_pwhash) {
    const original = sodium.crypto_pwhash;
    sodium.crypto_pwhash = function(...args) {
      const opId = `${library}-argon2-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'Argon2',
        output_length: args[0] || 'unknown',
        password_length: args[1] instanceof Uint8Array ? args[1].length : 'unknown',
        salt_preview: args[2] instanceof Uint8Array ? args[2].subarray(0, 8).toString('hex') + '...' : 'unknown',
        opslimit: args[3],
        memlimit: args[4],
        algorithm: args[5] === sodium.crypto_pwhash_ALG_ARGON2ID13 ? 'Argon2ID-13' : 'unknown',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      // Check if opslimit is too low
      if (args[3] && args[3] < 2) {
        captureData.warning = '⚠️ Argon2 opslimit is very low. Consider using at least 2.';
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_pwhash',
        data: captureData
      });

      return result;
    };
  }

  // --- Hook crypto_secretbox (symmetric encryption) ---
  if (sodium.crypto_secretbox_easy) {
    const original = sodium.crypto_secretbox_easy;
    sodium.crypto_secretbox_easy = function(...args) {
      const opId = `${library}-secretbox-encrypt-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'XSalsa20-Poly1305 (SecretBox)',
        message_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        nonce_preview: args[1] instanceof Uint8Array ? `${args[1].length} bytes` : 'unknown',
        key_preview: '***',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_secretbox_easy',
        data: captureData
      });

      return result;
    };
  }

  if (sodium.crypto_secretbox_open_easy) {
    const original = sodium.crypto_secretbox_open_easy;
    sodium.crypto_secretbox_open_easy = function(...args) {
      const opId = `${library}-secretbox-decrypt-${Date.now()}`;
      perfMonitor.start(opId);

      const result = original.apply(this, args);

      const duration = perfMonitor.end(opId);
      let captureData = {
        algorithm: 'XSalsa20-Poly1305 (SecretBox)',
        ciphertext_preview: args[0] instanceof Uint8Array ? `${args[0].length} bytes` : 'unknown',
        nonce_preview: args[1] instanceof Uint8Array ? `${args[1].length} bytes` : 'unknown',
        key_preview: '***',
        result_length: result instanceof Uint8Array ? result.length : 'unknown',
      };

      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      captureData = addStackTrace(captureData, 3);

      callback({
        library,
        method: 'crypto_secretbox_open_easy',
        data: captureData
      });

      return result;
    };
  }
}
