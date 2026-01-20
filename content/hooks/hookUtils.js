// /content/hooks/hookUtils.js

/**
 * Captures a simplified stack trace showing where the crypto operation was called from.
 * @param {number} skipFrames - Number of frames to skip from the top (default: 2).
 * @returns {string[]} Array of stack frame strings.
 */
export function captureStackTrace(skipFrames = 2) {
  const stack = new Error().stack;
  if (!stack) return [];

  const lines = stack.split('\n').slice(skipFrames + 1); // Skip Error constructor and this function
  const frames = [];

  for (const line of lines) {
    // Parse stack frame to extract useful info
    // Format: "functionName at url:line:column" or "url:line:column"
    const trimmed = line.trim();

    // Stop at extension boundaries
    if (trimmed.includes('chrome-extension://')) {
      break;
    }

    // Extract relevant info
    let frame = trimmed;

    // Clean up the frame string
    frame = frame
      .replace(/^at /, '') // Remove 'at' prefix
      .replace(/\(anonymous\)/, 'anonymous') // Clean anonymous functions
      .replace(/<anonymous>/, 'anonymous');

    // Skip internal frames
    if (frame.includes('injected.js') ||
        frame.includes('content.js') ||
        frame.includes('hooks/')) {
      continue;
    }

    // Limit frame length
    if (frame.length > 150) {
      frame = frame.substring(0, 150) + '...';
    }

    frames.push(frame);

    // Limit to 5 frames
    if (frames.length >= 5) {
      break;
    }
  }

  return frames;
}

/**
 * Adds a stack trace to the captured data.
 * @param {object} data - The data object to enhance.
 * @param {number} skipFrames - Number of frames to skip.
 * @returns {object} Enhanced data object with stack_trace.
 */
export function addStackTrace(data, skipFrames = 3) {
  return {
    ...data,
    stack_trace: captureStackTrace(skipFrames)
  };
}

/**
 * Weak cryptography detection rules.
 * Returns a warning if the algorithm/parameters are considered weak.
 */
export const WEAK_CRYPTO_WARNINGS = {
  algorithms: {
    'DES': 'DES is considered weak and deprecated. Use AES-256 instead.',
    'TripleDES': 'TripleDES is deprecated. Consider migrating to AES-256.',
    'RC4': 'RC4 is broken and should never be used.',
    'MD5': 'MD5 is cryptographically broken. Use SHA-256 or SHA-3.',
    'SHA1': 'SHA-1 is deprecated. Use SHA-256 or stronger.',
    'RSA': {
      check: (data) => {
        const keySize = data.key_bits || data.key_size || data.modulusBits;
        if (keySize && keySize < 2048) {
          return `RSA key size ${keySize} bits is too small. Use at least 2048 bits.`;
        }
        return null;
      }
    }
  },
  key_derivation: {
    'PBKDF2': {
      check: (data) => {
        const iterations = data.iterations;
        if (iterations && iterations < 100000) {
          return `PBKDF2 iteration count ${iterations} is below recommended 100,000.`;
        }
        return null;
      }
    },
    'EvpKDF': {
      check: (data) => {
        const iterations = data.iterations;
        if (iterations && iterations < 1000) {
          return `EvpKDF iteration count ${iterations} is low. Consider increasing it.`;
        }
        return null;
      }
    }
  }
};

/**
 * Checks if crypto operation uses weak cryptography.
 * @param {string} library - Library name.
 * @param {string} method - Method name.
 * @param {object} data - Captured data.
 * @returns {string|null} Warning message or null if secure.
 */
export function checkWeakCrypto(library, method, data) {
  const methodUpper = method.toUpperCase();

  // Check for weak algorithms
  for (const [algo, warning] of Object.entries(WEAK_CRYPTO_WARNINGS.algorithms)) {
    if (methodUpper.includes(algo)) {
      if (typeof warning === 'string') {
        return `⚠️ WEAK CRYPTO: ${warning}`;
      } else if (typeof warning.check === 'function') {
        const specificWarning = warning.check(data);
        if (specificWarning) {
          return `⚠️ WEAK CRYPTO: ${specificWarning}`;
        }
      }
    }
  }

  // Check key derivation
  for (const [kdf, rule] of Object.entries(WEAK_CRYPTO_WARNINGS.key_derivation)) {
    if (methodUpper.includes(kdf) && typeof rule.check === 'function') {
      const warning = rule.check(data);
      if (warning) {
        return `⚠️ WEAK CRYPTO: ${warning}`;
      }
    }
  }

  // Check for small AES keys (128 bits is acceptable, but warn about it)
  if (methodUpper.includes('AES') && data.key_size) {
    // This would need more context about key size format
    // Skip for now as AES-128 is still considered secure
  }

  return null;
}

/**
 * Performance monitoring class.
 */
export class PerformanceMonitor {
  constructor() {
    this.metrics = new Map();
  }

  /**
   * Start timing an operation.
   * @param {string} operationId - Unique identifier for the operation.
   * @returns {number} Start time.
   */
  start(operationId) {
    const startTime = performance.now();
    this.metrics.set(operationId, { startTime });
    return startTime;
  }

  /**
   * End timing an operation and return duration.
   * @param {string} operationId - Unique identifier for the operation.
   * @returns {number|null} Duration in milliseconds, or null if not found.
   */
  end(operationId) {
    const metric = this.metrics.get(operationId);
    if (!metric) return null;

    const endTime = performance.now();
    const duration = endTime - metric.startTime;
    this.metrics.delete(operationId);

    return duration;
  }

  /**
   * Measure an async operation.
   * @param {string} operationId - Operation identifier.
   * @param {Promise} promise - The promise to measure.
   * @returns {Promise} The original promise with duration tracking.
   */
  async measure(operationId, promise) {
    this.start(operationId);
    try {
      const result = await promise;
      const duration = this.end(operationId);
      return { result, duration };
    } catch (error) {
      const duration = this.end(operationId);
      throw { error, duration };
    }
  }
}

/**
 * Create a performance monitor instance.
 */
export const perfMonitor = new PerformanceMonitor();
