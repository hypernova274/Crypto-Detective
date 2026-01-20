// /content/hooks/forgeHook.js

/**
 * Helper to convert various Forge data types (like ByteBuffers or strings) to a readable string.
 * @param {*} data - The data to convert.
 * @returns {string} A string representation of the data, typically hex for buffers.
 */
function forgeDataToString(data) {
  if (typeof data === 'string') return data;
  // Check for Forge's ByteBuffer
  if (data && typeof data.toHex === 'function') {
    return `0x${data.toHex()}`;
  }
  // Fallback for other types
  if (data && typeof data.toString === 'function') {
      return data.toString();
  }
  return 'N/A';
}

/**
 * Initializes hooks for the Forge.js library.
 * @param {function} callback - The function to call with captured crypto data.
 */
export function initForgeHooks(callback) {
  if (typeof window.forge === 'undefined') {
    return; // Forge.js not found on the page.
  }

  const forge = window.forge;

  // --- Hook Ciphers (AES, 3DES, etc.) ---
  if (forge.cipher && typeof forge.cipher.createCipher === 'function' && typeof forge.cipher.createDecipher === 'function') {
    const wrapCipherCreator = (creatorFunction, operationType) => {
      return function(algorithm, key) {
        const cipher = creatorFunction.apply(this, arguments);
        const originalStart = cipher.start;
        const originalFinish = cipher.finish;
        let iv = 'N/A';

        // Wrap start() to capture the IV
        cipher.start = function(options) {
          if (options && options.iv) {
            iv = forgeDataToString(options.iv);
          }
          return originalStart.apply(this, arguments);
        };

        // Wrap finish() to capture the final result
        cipher.finish = function() {
          const inputBuffer = this.input; // Capture input before finish() clears it
          const result = originalFinish.apply(this, arguments);

          if (result) { // `finish` returns true on success
            callback({
              library: 'Forge.js',
              method: operationType, // 'encrypt' or 'decrypt'
              data: {
                algorithm: algorithm,
                key: forgeDataToString(key),
                iv: iv,
                input_data: forgeDataToString(inputBuffer),
                output_data: forgeDataToString(this.output)
              }
            });
          }
          return result;
        };
        return cipher;
      };
    };

    forge.cipher.createCipher = wrapCipherCreator(forge.cipher.createCipher, 'encrypt');
    forge.cipher.createDecipher = wrapCipherCreator(forge.cipher.createDecipher, 'decrypt');
  }

  // --- Hook Hashes ---
  if (forge.md) {
    const hashAlgorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
    hashAlgorithms.forEach(alg => {
      if (forge.md[alg] && typeof forge.md[alg].create === 'function') {
        const originalCreate = forge.md[alg].create;
        forge.md[alg].create = function() {
          const md = originalCreate.apply(this, arguments);
          const originalUpdate = md.update;
          const originalDigest = md.digest;
          let fullMessage = '';

          // Wrap update() to try and capture the full message being hashed.
          // This is an approximation as encoding can vary.
          md.update = function(msg, encoding) {
            if (typeof msg === 'string') {
                fullMessage += msg;
            }
            return originalUpdate.apply(this, arguments);
          };

          // Wrap digest() to capture the final hash.
          md.digest = function() {
            const result = originalDigest.apply(this, arguments);
            callback({
              library: 'Forge.js',
              method: `hash (${alg})`,
              data: {
                message_captured: fullMessage || '[Non-string or empty]',
                result_hash: result.toHex()
              }
            });
            return result;
          };
          return md;
        };
      }
    });
  }

  // --- Hook PBKDF2 ---
  if (forge.pbkdf2) {
    const originalPBKDF2 = forge.pbkdf2;
    forge.pbkdf2 = function(...args) {
      const result = originalPBKDF2.apply(this, args);
      const [password, salt, iterations, keySize, md] = args;

      callback({
        library: 'Forge.js',
        method: 'PBKDF2',
        data: {
          password_captured: typeof password === 'string' ? '[REDACTED]' : 'binary_data',
          salt: forgeDataToString(salt),
          iterations: iterations || 'default',
          key_size_bits: keySize || 'N/A',
          digest_algorithm: md?.algorithm || 'unknown',
          result_key_hex: typeof result === 'string' ? result : forgeDataToString(result)
        }
      });

      return result;
    };
  }

  // --- Hook HMAC ---
  if (forge.hmac) {
    const originalCreate = forge.hmac.create;
    if (typeof originalCreate === 'function') {
      forge.hmac.create = function() {
        const hmac = originalCreate.apply(this, arguments);
        const originalStart = hmac.start;
        const originalUpdate = hmac.update;
        const originalDigest = hmac.digest;
        let capturedKey = null;
        let capturedAlgorithm = null;

        // Wrap start() to capture the key
        hmac.start = function(md, key) {
          try {
            capturedAlgorithm = md?.algorithm || (typeof md === 'string' ? md : 'unknown');
            capturedKey = forgeDataToString(key);
          } catch (e) {
            capturedKey = '[Could not capture key]';
          }
          return originalStart.apply(this, arguments);
        };

        // Wrap digest() to capture the final result
        hmac.digest = function() {
          const result = originalDigest.apply(this, arguments);
          callback({
            library: 'Forge.js',
            method: 'HMAC',
            data: {
              algorithm: capturedAlgorithm || 'unknown',
              key: capturedKey || '[Key not set]',
              message_captured: hmac.output?.bytes ? 'binary_data' : 'unknown',
              result_hmac_hex: result?.toHex ? result.toHex() : forgeDataToString(result)
            }
          });
          return result;
        };

        return hmac;
      };
    }
  }

  // --- Hook RSA Public Key Encryption/Decryption ---
  if (forge.pki && forge.pki.publicKey) {
    const proto = forge.pki.publicKey.prototype;

    // Hook encrypt
    if (typeof proto.encrypt === 'function') {
      const originalEncrypt = proto.encrypt;
      proto.encrypt = function(...args) {
        const [data, scheme, options] = args;
        const result = originalEncrypt.apply(this, args);

        callback({
          library: 'Forge.js',
          method: 'RSA.encrypt',
          data: {
            input_data: typeof data === 'string' ? data : forgeDataToString(data),
            scheme: scheme?.scheme || scheme || 'unknown',
            key_bits: this.n?.bitLength ? this.n.bitLength() : 'N/A',
            result_ciphertext: result
          }
        });

        return result;
      };
    }

    // Hook decrypt
    if (typeof proto.decrypt === 'function') {
      const originalDecrypt = proto.decrypt;
      proto.decrypt = function(...args) {
        const [data, scheme, options] = args;
        const result = originalDecrypt.apply(this, args);

        callback({
          library: 'Forge.js',
          method: 'RSA.decrypt',
          data: {
            input_ciphertext: forgeDataToString(data),
            scheme: scheme?.scheme || scheme || 'unknown',
            key_bits: this.n?.bitLength ? this.n.bitLength() : 'N/A',
            result_plaintext: typeof result === 'string' ? result : forgeDataToString(result)
          }
        });

        return result;
      };
    }
  }

  // --- Hook RSA Private Key Operations ---
  if (forge.pki && forge.pki.privateKey) {
    const proto = forge.pki.privateKey.prototype;

    // Hook sign
    if (typeof proto.sign === 'function') {
      const originalSign = proto.sign;
      proto.sign = function(...args) {
        const [md, scheme] = args;
        const result = originalSign.apply(this, args);

        callback({
          library: 'Forge.js',
          method: 'RSA.sign',
          data: {
            md_algorithm: md?.algorithm || 'unknown',
            scheme: scheme?.scheme || scheme || 'unknown',
            key_bits: this.n?.bitLength ? this.n.bitLength() : 'N/A',
            result_signature: result
          }
        });

        return result;
      };
    }

    // Hook verify
    if (typeof proto.verify === 'function') {
      const originalVerify = proto.verify;
      proto.verify = function(...args) {
        const [digest, signature, scheme] = args;
        const result = originalVerify.apply(this, args);

        callback({
          library: 'Forge.js',
          method: 'RSA.verify',
          data: {
            digest: forgeDataToString(digest),
            scheme: scheme?.scheme || scheme || 'unknown',
            key_bits: this.n?.bitLength ? this.n.bitLength() : 'N/A',
            verification_result: result
          }
        });

        return result;
      };
    }
  }

  // --- Hook Random (for debugging) ---
  if (forge.random && typeof forge.random.getBytes === 'function') {
    const originalGetBytes = forge.random.getBytes;
    forge.random.getBytes = function(count) {
      const result = originalGetBytes.apply(this, arguments);

      callback({
        library: 'Forge.js',
        method: 'random.getBytes',
        data: {
          byte_count: count,
          result_hex: forge.util.bytesToHex(result)
        }
      });

      return result;
    };
  }

  // --- Hook TLS (basic connection tracking) ---
  if (forge.tls && typeof forge.tls.createConnection === 'function') {
    const originalCreateConnection = forge.tls.createConnection;
    forge.tls.createConnection = function(options) {
      const connection = originalCreateConnection.apply(this, arguments);

      callback({
        library: 'Forge.js',
        method: 'TLS.createConnection',
        data: {
          server: options?.server || 'N/A',
          tls_version: options?.version || 'default',
          cipher_suites: options?.cipherSuites || 'default'
        }
      });

      return connection;
    };
  }
}
