// /content/hooks/webCryptoHook.js

import { addStackTrace, checkWeakCrypto, perfMonitor } from './hookUtils.js';

/**
 * Converts an ArrayBuffer or TypedArray to a hexadecimal string.
 * @param {ArrayBuffer | TypedArray} buffer - The buffer to convert.
 * @returns {string} The hex string representation, or 'N/A' if input is invalid.
 */
function bufferToHex(buffer) {
  if (!buffer || typeof buffer.byteLength !== 'number') return 'N/A';
  // Create a Uint8Array view of the buffer
  const view = new Uint8Array(buffer);
  return Array.from(view)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Safely stringifies an object, handling potential circular references.
 * @param {object} obj - The object to stringify.
 * @returns {string} The JSON string.
 */
function safeStringify(obj) {
    try {
        return JSON.stringify(obj);
    } catch (e) {
        return '[Unserializable]';
    }
}

/**
 * Initializes hooks for the standard Web Crypto API (window.crypto.subtle).
 * It wraps the encrypt and decrypt methods to intercept their usage.
 * @param {function} callback - The function to call with captured crypto data.
 */
export function initWebCryptoHooks(callback) {
  if (!window.crypto || !window.crypto.subtle) {
    return; // Web Crypto API not available
  }

  const subtle = window.crypto.subtle;
  const originalEncrypt = subtle.encrypt;
  const originalDecrypt = subtle.decrypt;
  const originalSign = subtle.sign;
  const originalDigest = subtle.digest;

  // Wrap the 'encrypt' method
  subtle.encrypt = function(...args) {
    const [algorithm, key, data] = args;
    const opId = `crypto-${Date.now()}-${Math.random()}`;

    const promise = originalEncrypt.apply(this, args);

    // Intercept the successful result of the promise
    promise.then(result => {
      let captureData = {
        algorithm: algorithm.name || safeStringify(algorithm),
        key_type: key.algorithm?.name || 'Unknown',
        key_extractable: key.extractable,
        input_data_hex: bufferToHex(data),
        result_ciphertext_hex: bufferToHex(result),
      };

      // Add performance monitoring
      const duration = perfMonitor.end(opId);
      if (duration !== null) {
        captureData.execution_time_ms = duration.toFixed(2);
      }

      // Add stack trace
      captureData = addStackTrace(captureData, 4);

      // Check for weak crypto
      const weakWarning = checkWeakCrypto('Web Crypto API', algorithm.name || '', captureData);
      if (weakWarning) {
        captureData.warning = weakWarning;
      }

      callback({
        library: 'Web Crypto API',
        method: 'encrypt',
        data: captureData
      });
    }).catch(err => {
      perfMonitor.end(opId); // Clean up on error
    });

    // Start performance monitoring
    perfMonitor.start(opId);

    return promise;
  };

  // Wrap the 'decrypt' method
  subtle.decrypt = function(...args) {
    const [algorithm, key, data] = args;
    const promise = originalDecrypt.apply(this, args);

    // Intercept the successful result of the promise
    promise.then(result => {
      callback({
        library: 'Web Crypto API',
        method: 'decrypt',
        data: {
          algorithm: algorithm.name || safeStringify(algorithm),
          key_type: key.algorithm?.name || 'Unknown',
          key_extractable: key.extractable,
          input_ciphertext_hex: bufferToHex(data),
          result_plaintext_hex: bufferToHex(result),
        }
      });
    }).catch(err => {
      // We don't log errors.
    });

    return promise;
  };

  // Wrap the 'sign' method
  if (typeof originalSign === 'function') {
    subtle.sign = function(...args) {
      const [algorithm, key, data] = args;
      const promise = originalSign.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'sign',
          data: {
            algorithm: algorithm?.name || safeStringify(algorithm),
            key_type: key?.algorithm?.name || 'Unknown',
            key_extractable: key?.extractable,
            input_data_hex: bufferToHex(data),
            result_signature_hex: bufferToHex(result),
          }
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'digest' method
  if (typeof originalDigest === 'function') {
    subtle.digest = function(...args) {
      const [algorithm, data] = args;
      const promise = originalDigest.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'digest',
          data: {
            algorithm: algorithm?.name || safeStringify(algorithm),
            input_data_hex: bufferToHex(data),
            result_digest_hex: bufferToHex(result),
          }
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'deriveKey' method
  if (typeof subtle.deriveKey === 'function') {
    const originalDeriveKey = subtle.deriveKey;
    subtle.deriveKey = function(...args) {
      const [algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages] = args;
      const promise = originalDeriveKey.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'deriveKey',
          data: {
            derivation_algorithm: algorithm?.name || safeStringify(algorithm),
            base_key_type: baseKey?.algorithm?.name || 'Unknown',
            base_key_extractable: baseKey?.extractable,
            base_key_usages: baseKey?.usages || [],
            derived_key_type: derivedKeyAlgorithm?.name || 'Unknown',
            derived_key_length: derivedKeyAlgorithm?.length || 'N/A',
            extractable: extractable,
            key_usages: keyUsages || [],
            result_key_handle: result.extractable ? 'exportable' : 'non-exportable'
          }
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'deriveBits' method
  if (typeof subtle.deriveBits === 'function') {
    const originalDeriveBits = subtle.deriveBits;
    subtle.deriveBits = function(...args) {
      const [algorithm, baseKey, lengthBits] = args;
      const promise = originalDeriveBits.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'deriveBits',
          data: {
            derivation_algorithm: algorithm?.name || safeStringify(algorithm),
            base_key_type: baseKey?.algorithm?.name || 'Unknown',
            base_key_extractable: baseKey?.extractable,
            length_bits: lengthBits || 'N/A',
            result_bits_hex: bufferToHex(result)
          }
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'verify' method
  if (typeof subtle.verify === 'function') {
    const originalVerify = subtle.verify;
    subtle.verify = function(...args) {
      const [algorithm, key, signature, data] = args;
      const promise = originalVerify.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'verify',
          data: {
            algorithm: algorithm?.name || safeStringify(algorithm),
            key_type: key?.algorithm?.name || 'Unknown',
            key_extractable: key?.extractable,
            signature_hex: bufferToHex(signature),
            input_data_hex: bufferToHex(data),
            verification_result: result // true if signature is valid
          }
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'generateKey' method (bonus)
  if (typeof subtle.generateKey === 'function') {
    const originalGenerateKey = subtle.generateKey;
    subtle.generateKey = function(...args) {
      const [algorithm, extractable, keyUsages] = args;
      const promise = originalGenerateKey.apply(this, args);

      promise.then(result => {
        // Handle both SecretKey and CryptoKeyPair
        const keyData = {
          algorithm: algorithm?.name || safeStringify(algorithm),
          extractable: extractable,
          key_usages: keyUsages || []
        };

        if (result.type === 'private') {
          // CryptoKeyPair (public/private key pair)
          keyData.key_type = 'key_pair';
          keyData.public_key_type = result.publicKey?.algorithm?.name || 'Unknown';
          keyData.private_key_type = result.privateKey?.algorithm?.name || 'Unknown';
          keyData.private_key_extractable = result.privateKey?.extractable;
        } else {
          // Single SecretKey
          keyData.key_type = result.type || 'secret';
          keyData.algorithm_name = result.algorithm?.name || 'Unknown';
        }

        callback({
          library: 'Web Crypto API',
          method: 'generateKey',
          data: keyData
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'importKey' method (bonus)
  if (typeof subtle.importKey === 'function') {
    const originalImportKey = subtle.importKey;
    subtle.importKey = function(...args) {
      const [format, keyData, algorithm, extractable, keyUsages] = args;
      const promise = originalImportKey.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'importKey',
          data: {
            format: format,
            algorithm: algorithm?.name || safeStringify(algorithm),
            extractable: extractable,
            key_usages: keyUsages || [],
            key_type: result?.type || 'Unknown',
            algorithm_name: result?.algorithm?.name || 'Unknown',
            key_data_preview: format === 'raw' ? bufferToHex(keyData) : '[non-raw format]'
          }
        });
      }).catch(() => {});

      return promise;
    };
  }

  // Wrap the 'exportKey' method (bonus)
  if (typeof subtle.exportKey === 'function') {
    const originalExportKey = subtle.exportKey;
    subtle.exportKey = function(...args) {
      const [format, key] = args;
      const promise = originalExportKey.apply(this, args);

      promise.then(result => {
        callback({
          library: 'Web Crypto API',
          method: 'exportKey',
          data: {
            format: format,
            key_type: key?.type || 'Unknown',
            algorithm_name: key?.algorithm?.name || 'Unknown',
            extractable: key?.extractable,
            result_data_hex: bufferToHex(result)
          }
        });
      }).catch(() => {});

      return promise;
    };
  }
}
