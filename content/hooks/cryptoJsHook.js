// /content/hooks/cryptoJsHook.js

/**
 * Helper to convert various data types from CryptoJS to a readable string for logging.
 * @param {*} data - The data to convert (e.g., WordArray, string, CipherParams).
 * @returns {string} A string representation of the data.
 */
function cryptoJsDataToString(data) {
  if (data === undefined || data === null) return 'N/A';
  if (typeof data === 'string') return data;
  if (typeof data.toString !== 'function') return '[Unstringifiable Object]';

  // CryptoJS WordArrays can be converted to different encodings.
  // We try Utf8 first, as it's common for plaintext.
  try {
    // Check if it's a WordArray by looking for the `words` property.
    if (Array.isArray(data.words) && typeof data.sigBytes === 'number') {
        const utf8String = data.toString(window.CryptoJS.enc.Utf8);
        if (utf8String) return utf8String;

        // If Utf8 is empty, it's likely binary data, so represent as hex.
        const hexString = data.toString(window.CryptoJS.enc.Hex);
        return hexString ? `0x${hexString}` : '(Empty WordArray)';
    }
  } catch (e) {
    // Fallback if encoding fails
  }

  // Fallback for other objects with a toString method, like CipherParams or simple objects.
  try {
    return data.toString();
  } catch (err) {
    return '[Unrepresentable Data]';
  }
}

/**
 * Extracts mode and padding information from CryptoJS configuration object.
 * @param {*} cfg - The configuration object passed to encrypt/decrypt.
 * @returns {object} Extracted mode and padding info.
 */
function extractCryptoJsConfig(cfg) {
  const info = {
    mode: null, // Changed to null to distinguish "not set" from "default"
    padding: 'default',
    iv: 'N/A'
  };

  if (!cfg || typeof cfg !== 'object') {
    return info;
  }

  // Extract mode - CryptoJS mode objects need special handling
  if (cfg.mode) {
    if (typeof cfg.mode === 'string') {
      // String mode name
      info.mode = cfg.mode.toUpperCase().replace('MODE_', '');
    } else if (typeof cfg.mode === 'object') {
      // CryptoJS mode object - try to extract the mode name
      let detectedMode = null;

      // Method 1: Try constructor name
      if (cfg.mode.constructor && cfg.mode.constructor.name) {
        const ctorName = cfg.mode.constructor.name.toUpperCase();
        // Handle various CryptoJS constructor name formats
        if (ctorName.includes('CBC')) {
          detectedMode = 'CBC';
        } else if (ctorName.includes('ECB')) {
          detectedMode = 'ECB';
        } else if (ctorName.includes('GCM')) {
          detectedMode = 'GCM';
        } else if (ctorName.includes('CFB')) {
          detectedMode = 'CFB';
        } else if (ctorName.includes('CTR')) {
          detectedMode = 'CTR';
        } else if (ctorName.includes('OFB')) {
          detectedMode = 'OFB';
        } else {
          // Try removing common prefixes
          detectedMode = ctorName.replace(/^MODE_/, '').replace(/_MODE$/, '');
        }
      }

      // Method 2: Try toString() if constructor didn't work
      if (!detectedMode && typeof cfg.mode.toString === 'function') {
        const strResult = cfg.mode.toString();
        if (strResult && strResult !== '[object Object]' && strResult !== 'OBJECT') {
          const upperStr = strResult.toUpperCase().replace('MODE_', '');
          if (['CBC', 'ECB', 'GCM', 'CFB', 'CTR', 'OFB'].includes(upperStr)) {
            detectedMode = upperStr;
          }
        }
      }

      // Method 3: Try to detect from object properties
      if (!detectedMode) {
        const keys = Object.keys(cfg.mode);
        for (const key of keys) {
          const keyUpper = key.toUpperCase();
          if (['CBC', 'ECB', 'GCM', 'CFB', 'CTR', 'OFB'].includes(keyUpper)) {
            detectedMode = keyUpper;
            break;
          }
        }
      }

      info.mode = detectedMode || 'CBC'; // Default to CBC if we can't detect
    }
  }

  // Extract padding
  if (cfg.padding) {
    if (typeof cfg.padding === 'string') {
      info.padding = cfg.padding;
    } else if (cfg.padding.constructor && cfg.padding.constructor.name) {
      info.padding = cfg.padding.constructor.name;
    }
  }

  // Extract IV
  if (cfg.iv) {
    try {
      info.iv = cryptoJsDataToString(cfg.iv);
    } catch (e) {
      info.iv = '[Could not extract IV]';
    }
  }

  return info;
}

/**
 * Initializes hooks for the CryptoJS library by wrapping common encryption and hashing functions.
 * @param {function} callback - The function to call with captured crypto data.
 */
export function initCryptoJsHooks(callback) {
  if (typeof window.CryptoJS === 'undefined') {
    return; // CryptoJS not found on the page.
  }

  // --- Hook AES Encryption/Decryption ---
  if (window.CryptoJS.AES) {
    const originalEncrypt = window.CryptoJS.AES.encrypt;
    window.CryptoJS.AES.encrypt = function(...args) {
      const result = originalEncrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'AES.encrypt',
        data: {
          message: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          mode: config.mode,
          padding: config.padding,
          iv: config.iv,
          result_ciphertext: result.toString()
        }
      });
      return result;
    };

    const originalDecrypt = window.CryptoJS.AES.decrypt;
    window.CryptoJS.AES.decrypt = function(...args) {
      const result = originalDecrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'AES.decrypt',
        data: {
          ciphertext: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          mode: config.mode,
          padding: config.padding,
          iv: config.iv,
          result_plaintext: cryptoJsDataToString(result)
        }
      });
      return result;
    };
  }

  // --- Hook DES Encryption/Decryption ---
  if (window.CryptoJS.DES) {
    const originalDESEncrypt = window.CryptoJS.DES.encrypt;
    window.CryptoJS.DES.encrypt = function(...args) {
      const result = originalDESEncrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'DES.encrypt',
        data: {
          message: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          mode: config.mode,
          padding: config.padding,
          iv: config.iv,
          result_ciphertext: result.toString()
        }
      });
      return result;
    };

    const originalDESDecrypt = window.CryptoJS.DES.decrypt;
    window.CryptoJS.DES.decrypt = function(...args) {
      const result = originalDESDecrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'DES.decrypt',
        data: {
          ciphertext: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          mode: config.mode,
          padding: config.padding,
          iv: config.iv,
          result_plaintext: cryptoJsDataToString(result)
        }
      });
      return result;
    };
  }

  // --- Hook TripleDES Encryption/Decryption ---
  if (window.CryptoJS.TripleDES) {
    const original3DESEncrypt = window.CryptoJS.TripleDES.encrypt;
    window.CryptoJS.TripleDES.encrypt = function(...args) {
      const result = original3DESEncrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'TripleDES.encrypt',
        data: {
          message: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          mode: config.mode,
          padding: config.padding,
          iv: config.iv,
          result_ciphertext: result.toString()
        }
      });
      return result;
    };

    const original3DESDecrypt = window.CryptoJS.TripleDES.decrypt;
    window.CryptoJS.TripleDES.decrypt = function(...args) {
      const result = original3DESDecrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'TripleDES.decrypt',
        data: {
          ciphertext: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          mode: config.mode,
          padding: config.padding,
          iv: config.iv,
          result_plaintext: cryptoJsDataToString(result)
        }
      });
      return result;
    };
  }

  // --- Hook Rabbit Encryption/Decryption ---
  if (window.CryptoJS.Rabbit) {
    const originalRabbitEncrypt = window.CryptoJS.Rabbit.encrypt;
    window.CryptoJS.Rabbit.encrypt = function(...args) {
      const result = originalRabbitEncrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'Rabbit.encrypt',
        data: {
          message: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          iv: config.iv,
          result_ciphertext: result.toString()
        }
      });
      return result;
    };

    const originalRabbitDecrypt = window.CryptoJS.Rabbit.decrypt;
    window.CryptoJS.Rabbit.decrypt = function(...args) {
      const result = originalRabbitDecrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'Rabbit.decrypt',
        data: {
          ciphertext: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          iv: config.iv,
          result_plaintext: cryptoJsDataToString(result)
        }
      });
      return result;
    };
  }

  // --- Hook RC4 Encryption/Decryption ---
  if (window.CryptoJS.RC4) {
    const originalRC4Encrypt = window.CryptoJS.RC4.encrypt;
    window.CryptoJS.RC4.encrypt = function(...args) {
      const result = originalRC4Encrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'RC4.encrypt',
        data: {
          message: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          result_ciphertext: result.toString()
        }
      });
      return result;
    };

    const originalRC4Decrypt = window.CryptoJS.RC4.decrypt;
    window.CryptoJS.RC4.decrypt = function(...args) {
      const result = originalRC4Decrypt.apply(this, args);
      const config = extractCryptoJsConfig(args[2]);

      callback({
        library: 'CryptoJS',
        method: 'RC4.decrypt',
        data: {
          ciphertext: cryptoJsDataToString(args[0]),
          key: cryptoJsDataToString(args[1]),
          result_plaintext: cryptoJsDataToString(result)
        }
      });
      return result;
    };
  }

  // --- Hook Common Hashing Algorithms ---
  const hashers = ['MD5', 'SHA1', 'SHA256', 'SHA3', 'SHA512', 'RIPEMD160'];
  hashers.forEach(hasherName => {
    if (typeof window.CryptoJS[hasherName] === 'function') {
      const originalHasher = window.CryptoJS[hasherName];
      window.CryptoJS[hasherName] = function(...args) {
        const result = originalHasher.apply(this, args);
        callback({
          library: 'CryptoJS',
          method: hasherName,
          data: {
            message: cryptoJsDataToString(args[0]),
            result_hash: result.toString() // Hashes also have a clean toString()
          }
        });
        return result;
      };
    }
  });

  // --- Hook HMAC Algorithms ---
  // HMAC is typically accessed via CryptoJS.HmacMD5, CryptoJS.HmacSHA1, etc.
  const hmacAlgorithms = ['MD5', 'SHA1', 'SHA256', 'SHA3', 'SHA512', 'RIPEMD160'];
  hmacAlgorithms.forEach(hasherName => {
    const hmacName = `Hmac${hasherName}`;
    if (window.CryptoJS[hmacName]) {
      // Check if it's in the algo object (CryptoJS 4.x) or directly on CryptoJS (CryptoJS 3.x)
      const hmacTarget = window.CryptoJS.algo?.[hmacName] || window.CryptoJS[hmacName];

      if (hmacTarget && typeof hmacTarget.create === 'function') {
        const originalCreate = hmacTarget.create;
        hmacTarget.create = function(...args) {
          const hmac = originalCreate.apply(this, args);
          const originalInit = hmac.init;
          const originalFinalize = hmac.finalize;
          let capturedKey = null;

          // Wrap init to capture the key
          hmac.init = function(key) {
            try {
              capturedKey = cryptoJsDataToString(key);
            } catch (e) {
              capturedKey = '[Could not capture key]';
            }
            return originalInit.apply(this, arguments);
          };

          // Wrap finalize to capture the data and result
          hmac.finalize = function(data) {
            const result = originalFinalize.call(this, data);
            callback({
              library: 'CryptoJS',
              method: hmacName,
              data: {
                key: capturedKey || '[Key not set via init]',
                message: cryptoJsDataToString(data),
                result_hmac: result.toString()
              }
            });
            return result;
          };

          return hmac;
        };
      }
    }
  });

  // --- Hook PBKDF2 ---
  if (window.CryptoJS.PBKDF2) {
    const originalPBKDF2 = window.CryptoJS.PBKDF2;
    window.CryptoJS.PBKDF2 = function(...args) {
      const [password, salt, cfg] = args;
      const result = originalPBKDF2.apply(this, args);

      // Extract configuration details
      const config = cfg || {};
      const iterations = config.iterations || 'default';
      const keySize = config.keySize || 'default';

      callback({
        library: 'CryptoJS',
        method: 'PBKDF2',
        data: {
          password: cryptoJsDataToString(password),
          salt: cryptoJsDataToString(salt),
          iterations: typeof iterations === 'number' ? iterations : iterations,
          key_size: keySize,
          result_key: result.toString()
        }
      });

      return result;
    };
  }

  // --- Hook EvpKDF (OpenSSL key derivation) ---
  if (window.CryptoJS.EvpKDF) {
    const originalEvpKDF = window.CryptoJS.EvpKDF;
    window.CryptoJS.EvpKDF = function(...args) {
      const [password, salt, cfg] = args;
      const result = originalEvpKDF.apply(this, args);

      const config = cfg || {};
      const keySize = config.keySize || 'default';
      const iterations = config.iterations || 1;

      callback({
        library: 'CryptoJS',
        method: 'EvpKDF',
        data: {
          password: cryptoJsDataToString(password),
          salt: cryptoJsDataToString(salt),
          iterations: iterations,
          key_size: keySize,
          result_key: result.toString()
        }
      });

      return result;
    };
  }
}
