// /panel/galaxyGenerator.js

/**
 * Galaxy Script Generator - Algorithm Detection and Aggregation
 * Analyzes captured crypto logs to extract algorithm patterns
 */

/**
 * Algorithm mapping from Crypto-Detective to Galaxy format
 */
const ALGORITHM_MAP = {
  // CryptoJS mappings
  'CryptoJS': {
    'AES': {
      'CBC': 'AES/CBC/PKCS5Padding',
      'ECB': 'AES/ECB/PKCS5Padding',
      'GCM': 'AES/GCM/NoPadding',
      'CFB': 'AES/CFB/PKCS5Padding',
      'CTR': 'AES/CTR/NoPadding',
      'OFB': 'AES/OFB/PKCS5Padding'
    },
    'DES': {
      'CBC': 'DES/CBC/PKCS5Padding',
      'ECB': 'DES/ECB/PKCS5Padding'
    },
    'TripleDES': {
      'CBC': 'DESede/CBC/PKCS5Padding',
      'ECB': 'DESede/ECB/PKCS5Padding'
    }
  },
  // JSEncrypt mappings
  'JSEncrypt': {
    'encrypt': 'RSA/ECB/PKCS1Padding',
    'decrypt': 'RSA/ECB/PKCS1Padding'
  },
  // Web Crypto API mappings
  'Web Crypto API': {
    'AES-CBC': 'AES/CBC/PKCS5Padding',
    'AES-ECB': 'AES/ECB/PKCS5Padding',
    'AES-GCM': 'AES/GCM/NoPadding',
    'AES-CTR': 'AES/CTR/NoPadding',
    'RSA-OAEP': 'RSA/ECB/OAEPWithSHA-1AndMGF1Padding',
    'RSA-PKCS1-v1_5': 'RSA/ECB/PKCS1Padding'
  },
  // SM algorithms (Chinese national cryptography standards)
  'SM2': {
    'encrypt': 'SM2',
    'decrypt': 'SM2'
  },
  'SM4': {
    'CBC': 'SM4/CBC/PKCS5Padding',
    'ECB': 'SM4/ECB/PKCS5Padding',
    'GCM': 'SM4/GCM/NoPadding',
    'CTR': 'SM4/CTR/NoPadding'
  }
};

/**
 * Extract algorithm signature from a log entry
 * @param {Object} log - Captured crypto operation log
 * @returns {Object|null} - Algorithm signature or null if not applicable
 */
function extractAlgorithmSignature(log) {
  const { library, method, data } = log;

  try {
    switch (library) {
      case 'CryptoJS':
        return extractCryptoJSSignature(method, data);
      case 'JSEncrypt':
        return extractJSEncryptSignature(method, data);
      case 'Web Crypto API':
        return extractWebCryptoSignature(method, data);
      case 'Forge.js':
        return extractForgeSignature(method, data);
      default:
        return null;
    }
  } catch (e) {
    console.warn('Failed to extract algorithm signature:', e);
    return null;
  }
}

/**
 * Extract CryptoJS algorithm signature
 */
function extractCryptoJSSignature(method, data) {
  console.log('[GalaxyGenerator] extractCryptoJSSignature called with:', { method, data });

  const [cipher, operation] = method.split('.');

  if (!operation || (operation !== 'encrypt' && operation !== 'decrypt')) {
    console.warn('[GalaxyGenerator] Invalid operation:', operation);
    return null;
  }

  // Handle different mode formats
  let mode = null; // Start with null instead of default to detect if we found it
  if (data.mode) {
    // Handle mode as object (CryptoJS mode objects)
    if (typeof data.mode === 'object') {
      console.log('[GalaxyGenerator] mode is object:', data.mode);
      console.log('[GalaxyGenerator] mode constructor:', data.mode.constructor?.name);

      // Try to extract mode name from object properties
      // CryptoJS mode objects have specific internal structure
      const modeStr = JSON.stringify(data.mode);
      console.log('[GalaxyGenerator] mode JSON:', modeStr);

      // Check for known mode patterns in the object
      // Try constructor name first
      if (data.mode.constructor && data.mode.constructor.name) {
        const ctorName = data.mode.constructor.name.toUpperCase().replace('MODE_', '');
        console.log('[GalaxyGenerator] Checking constructor name:', ctorName);
        if (['CBC', 'ECB', 'GCM', 'CFB', 'CTR', 'OFB'].includes(ctorName)) {
          mode = ctorName;
          console.log('[GalaxyGenerator] Extracted mode from constructor:', mode);
        }
      }

      // If constructor didn't work, try to detect from string representation
      if (!mode) {
        // CryptoJS mode objects might have internal properties
        const keys = Object.keys(data.mode);
        console.log('[GalaxyGenerator] mode object keys:', keys);

        // Try checking the object's string representation
        const objString = Object.prototype.toString.call(data.mode);
        console.log('[GalaxyGenerator] Object.prototype.toString:', objString);

        // Try to detect mode from known patterns
        // Check if any mode name appears in the keys or values
        for (const key of keys) {
          const keyUpper = key.toUpperCase();
          if (['CBC', 'ECB', 'GCM', 'CFB', 'CTR', 'OFB'].includes(keyUpper)) {
            mode = keyUpper;
            console.log('[GalaxyGenerator] Found mode in keys:', mode);
            break;
          }
        }
      }

      // Last resort: try toString but only for specific known patterns
      if (!mode) {
        const strResult = data.mode.toString();
        console.log('[GalaxyGenerator] mode.toString() result:', strResult);

        // Check if toString() gives us something useful (not "OBJECT" or "[object Object]")
        if (strResult && strResult !== 'OBJECT' && strResult !== '[object Object]') {
          const extractedMode = strResult.toUpperCase().replace('MODE_', '');
          if (['CBC', 'ECB', 'GCM', 'CFB', 'CTR', 'OFB'].includes(extractedMode)) {
            mode = extractedMode;
            console.log('[GalaxyGenerator] Extracted mode from toString:', mode);
          }
        }
      }

      console.log('[GalaxyGenerator] Final detected mode:', mode);
    } else if (typeof data.mode === 'string') {
      mode = data.mode.toUpperCase().replace('MODE_', '');
      console.log('[GalaxyGenerator] mode from string:', mode);
    }
  }

  // If no mode was detected, try to infer from common patterns
  if (!mode) {
    console.warn('[GalaxyGenerator] Could not detect mode from data.mode, using CBC as default');
    mode = 'CBC'; // Default to CBC for CryptoJS
  }

  // Normalize common mode names
  const modeMap = {
    'CBC': 'CBC',
    'ECB': 'ECB',
    'GCM': 'GCM',
    'CFB': 'CFB',
    'CTR': 'CTR',
    'OFB': 'OFB'
  };
  mode = modeMap[mode] || mode;

  // Map to Galaxy format
  const algorithmKey = cipher.toUpperCase();
  let galaxyAlgorithm = null;

  console.log('[GalaxyGenerator] Looking up algorithm:', algorithmKey, 'mode:', mode);

  if (ALGORITHM_MAP.CryptoJS && ALGORITHM_MAP.CryptoJS[algorithmKey]) {
    galaxyAlgorithm = ALGORITHM_MAP.CryptoJS[algorithmKey][mode] || null;
  }

  if (!galaxyAlgorithm) {
    console.warn('[GalaxyGenerator] No mapping found for', algorithmKey, mode);
    console.warn('[GalaxyGenerator] Available modes for this cipher:', ALGORITHM_MAP.CryptoJS[algorithmKey] ? Object.keys(ALGORITHM_MAP.CryptoJS[algorithmKey]) : 'N/A (cipher not found)');
    return null;
  }

  console.log('[GalaxyGenerator] Found algorithm:', galaxyAlgorithm);

  return {
    library: 'CryptoJS',
    algorithm: galaxyAlgorithm,
    cipher: cipher,
    mode: mode,
    operation: operation,
    key: data.key || null,
    iv: data.iv || null,
    hasSample: !!(data.message || data.ciphertext || data.result_ciphertext || data.result_plaintext),
    data: data
  };
}

/**
 * Extract JSEncrypt algorithm signature
 */
function extractJSEncryptSignature(method, data) {
  if (method !== 'encrypt' && method !== 'decrypt') {
    return null;
  }

  return {
    library: 'JSEncrypt',
    algorithm: 'RSA/ECB/PKCS1Padding',
    cipher: 'RSA',
    mode: 'ECB',
    operation: method,
    key: data.key_summary || null,
    iv: null,
    hasSample: !!(data.plaintext || data.ciphertext_b64 || data.result_ciphertext_b64 || data.result_plaintext),
    data: data
  };
}

/**
 * Extract Web Crypto API algorithm signature
 */
function extractWebCryptoSignature(method, data) {
  if (method !== 'encrypt' && method !== 'decrypt') {
    return null;
  }

  const algorithmName = data.algorithm || '';
  let galaxyAlgorithm = null;

  // Map algorithm name
  for (const [key, value] of Object.entries(ALGORITHM_MAP['Web Crypto API'])) {
    if (algorithmName.includes(key)) {
      galaxyAlgorithm = value;
      break;
    }
  }

  if (!galaxyAlgorithm) {
    // Try to extract from algorithm name directly
    if (algorithmName.includes('AES') && algorithmName.includes('CBC')) {
      galaxyAlgorithm = 'AES/CBC/PKCS5Padding';
    } else if (algorithmName.includes('AES') && algorithmName.includes('ECB')) {
      galaxyAlgorithm = 'AES/ECB/PKCS5Padding';
    } else if (algorithmName.includes('AES') && algorithmName.includes('GCM')) {
      galaxyAlgorithm = 'AES/GCM/NoPadding';
    }
  }

  if (!galaxyAlgorithm) {
    return null;
  }

  return {
    library: 'Web Crypto API',
    algorithm: galaxyAlgorithm,
    cipher: galaxyAlgorithm.split('/')[0],
    mode: galaxyAlgorithm.split('/')[1],
    operation: method,
    key: data.key_type || null,
    iv: null, // Web Crypto IV is usually in the algorithm params
    hasSample: !!(data.input_data_hex || data.input_ciphertext_hex || data.result_ciphertext_hex || data.result_plaintext_hex),
    data: data
  };
}

/**
 * Extract Forge algorithm signature
 */
function extractForgeSignature(method, data) {
  // Basic Forge support - can be extended
  if (!method.includes('encrypt') && !method.includes('decrypt')) {
    return null;
  }

  // Try to detect cipher from method or data
  let cipher = null;
  let mode = 'CBC';

  if (method.includes('AES') || data.cipher?.includes('AES')) {
    cipher = 'AES';
  } else if (method.includes('DES') || data.cipher?.includes('DES')) {
    cipher = 'DES';
  }

  if (!cipher) {
    return null;
  }

  const galaxyAlgorithm = `${cipher}/${mode}/PKCS5Padding`;

  return {
    library: 'Forge.js',
    algorithm: galaxyAlgorithm,
    cipher: cipher,
    mode: mode,
    operation: method.includes('encrypt') ? 'encrypt' : 'decrypt',
    key: data.key || null,
    iv: data.iv || null,
    hasSample: !!(data.input || data.output),
    data: data
  };
}

/**
 * Aggregate logs by algorithm pattern
 * @param {Array} logs - Array of captured crypto logs
 * @returns {Array} - Array of detected algorithm patterns
 */
function aggregateAlgorithms(logs) {
  console.log('[GalaxyGenerator] aggregateAlgorithms called with', logs.length, 'logs');

  const patterns = new Map();
  let processedCount = 0;
  let skippedCount = 0;

  logs.forEach((log, index) => {
    const signature = extractAlgorithmSignature(log);
    if (!signature) {
      skippedCount++;
      if (skippedCount <= 3) {
        console.log('[GalaxyGenerator] Skipped log', index, ':', log.library, log.method);
      }
      return;
    }

    processedCount++;
    console.log('[GalaxyGenerator] Processed log', index, ':', signature.library, signature.algorithm, signature.operation);

    // Create a unique key for this algorithm pattern
    const patternKey = `${signature.library}:${signature.algorithm}:${signature.operation}`;

    if (!patterns.has(patternKey)) {
      patterns.set(patternKey, {
        id: patternKey,
        library: signature.library,
        algorithm: signature.algorithm,
        cipher: signature.cipher,
        mode: signature.mode,
        operation: signature.operation,
        key: signature.key,
        iv: signature.iv,
        sampleCount: 0,
        samples: [],
        hasKey: !!signature.key,
        hasIV: !!signature.iv,
        supportLevel: 'unknown'
      });
    }

    const pattern = patterns.get(patternKey);
    pattern.sampleCount++;

    // Collect up to 3 samples
    if (pattern.samples.length < 3 && signature.hasSample) {
      pattern.samples.push(extractSampleData(signature));
    }

    // Update key/IV if we found them
    if (signature.key && !pattern.key) {
      pattern.key = signature.key;
      pattern.hasKey = true;
    }
    if (signature.iv && !pattern.iv) {
      pattern.iv = signature.iv;
      pattern.hasIV = true;
    }
  });

  console.log('[GalaxyGenerator] Processed:', processedCount, 'Skipped:', skippedCount, 'Patterns found:', patterns.size);

  // Determine support level for each pattern
  patterns.forEach(pattern => {
    pattern.supportLevel = determineSupportLevel(pattern);
  });

  const result = Array.from(patterns.values());
  console.log('[GalaxyGenerator] Returning patterns:', result);
  return result;
}

/**
 * Extract sample data from signature
 */
function extractSampleData(signature) {
  const data = signature.data;
  const sample = {
    operation: signature.operation
  };

  // Try to extract plaintext/ciphertext based on operation
  if (signature.operation === 'encrypt') {
    sample.plaintext = data.message || data.input_data || '';
    sample.ciphertext = data.result_ciphertext || data.result_ciphertext_b64 || data.output || '';
  } else {
    sample.ciphertext = data.ciphertext || data.ciphertext_b64 || data.input_ciphertext || data.input_data || '';
    sample.plaintext = data.result_plaintext || data.output || '';
  }

  return sample;
}

/**
 * Determine support level for an algorithm pattern
 */
function determineSupportLevel(pattern) {
  // High confidence: we have the key
  if (pattern.hasKey) {
    return 'high';
  }

  // Medium confidence: common algorithm with samples
  if (pattern.sampleCount >= 3) {
    return 'medium';
  }

  // Low confidence: limited samples
  if (pattern.sampleCount >= 1) {
    return 'low';
  }

  return 'unknown';
}

/**
 * Generate a human-readable display name for an algorithm
 */
function getAlgorithmDisplayName(pattern) {
  const operationText = pattern.operation === 'encrypt' ? 'Encryption' : 'Decryption';
  const cipher = pattern.cipher || 'Unknown';
  const mode = pattern.mode || '';

  return `${cipher} ${mode ? mode + ' ' : ''}${operationText} (${pattern.library})`;
}

/**
 * Validate if we have enough information to generate a script
 */
function canGenerateScript(pattern) {
  return pattern.supportLevel !== 'unknown' && pattern.sampleCount > 0;
}

/**
 * Get configuration hints for the user
 */
function getConfigHints(pattern) {
  const hints = [];

  if (!pattern.hasKey) {
    hints.push('Key was not captured. You may need to extract it manually from the application.');
  }

  if (pattern.algorithm.includes('CBC') && !pattern.hasIV) {
    hints.push('CBC mode requires an IV. Check if it\'s static or needs to be extracted from requests.');
  }

  if (pattern.sampleCount < 3) {
    hints.push('Limited samples captured. More samples will improve accuracy.');
  }

  return hints;
}

// Export functions for use in panel.js
window.GalaxyGenerator = {
  aggregateAlgorithms,
  extractAlgorithmSignature,
  getAlgorithmDisplayName,
  canGenerateScript,
  getConfigHints
};
