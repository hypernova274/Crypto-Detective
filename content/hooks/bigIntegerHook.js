// /content/hooks/bigIntegerHook.js

/**
 * Helper to convert a BigInteger object to a truncated hexadecimal string for concise logging.
 * @param {BigInteger} bigInt - The BigInteger object to convert.
 * @returns {string} A truncated hex string (e.g., "0x123...[64 digits]").
 */
function bigIntToTruncatedHex(bigInt) {
  if (!bigInt || typeof bigInt.toString !== 'function') return 'N/A';
  const hex = bigInt.toString(16);
  // Show the first 32 characters and the total length to give a sense of scale.
  if (hex.length > 32) {
    return `0x${hex.substring(0, 32)}...[${hex.length} hex digits]`;
  }
  return `0x${hex}`;
}

/**
 * Initializes hooks for the BigInteger library (jsbn), focusing on the core
 * modular exponentiation operation used in algorithms like RSA.
 * @param {function} callback - The function to call with captured crypto data.
 */
export function initBigIntegerHooks(callback) {
  if (typeof window.BigInteger === 'undefined' || !window.BigInteger.prototype) {
    return; // BigInteger library not found on the page.
  }

  const BigIntegerPrototype = window.BigInteger.prototype;

  // Hook the modular exponentiation function (`modPow`), which is the heart of RSA.
  // It computes: (this ^ exponent) mod modulus
  if (typeof BigIntegerPrototype.modPow === 'function') {
    const originalModPow = BigIntegerPrototype.modPow;

    BigIntegerPrototype.modPow = function(exponent, modulus) {
      const result = originalModPow.apply(this, arguments);

      callback({
        library: 'BigInteger.js (jsbn)',
        method: 'modPow',
        description: 'Core RSA mathematical operation.',
        data: {
          base: bigIntToTruncatedHex(this),
          exponent: bigIntToTruncatedHex(exponent),
          modulus: bigIntToTruncatedHex(modulus),
          result: bigIntToTruncatedHex(result)
        }
      });

      return result;
    };
  }
}
