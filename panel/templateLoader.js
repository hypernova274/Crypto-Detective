// /panel/templateLoader.js

/**
 * Galaxy Template Loader
 * Matches captured crypto operations with GalaxyDemo templates
 * Loads template file contents for AI generation
 */

/**
 * Cache for loaded template contents
 */
const TEMPLATE_CONTENT_CACHE = new Map();

/**
 * Load template file content
 * @param {string} templateFile - Template file path (e.g., 'GalaxyDemo-main/ciphers/aes_cbc.py')
 * @returns {Promise<string>} - Template file content
 */
async function loadTemplateContent(templateFile) {
  // Check cache first
  if (TEMPLATE_CONTENT_CACHE.has(templateFile)) {
    return TEMPLATE_CONTENT_CACHE.get(templateFile);
  }

  try {
    // Extract just the filename from the path
    const filename = templateFile.split('/').pop();

    // Try to load from templates directory
    const templateUrl = chrome.runtime.getURL(`panel/templates/${filename}`);

    const response = await fetch(templateUrl);
    if (!response.ok) {
      throw new Error(`Failed to load template: ${response.status}`);
    }

    const content = await response.text();

    // Cache the content
    TEMPLATE_CONTENT_CACHE.set(templateFile, content);

    console.log(`[TemplateLoader] Loaded template: ${templateFile} (${content.length} chars)`);

    return content;
  } catch (error) {
    console.warn(`[TemplateLoader] Failed to load template ${templateFile}:`, error);
    return null;
  }
}

/**
 * Clear template content cache (useful for debugging or refreshing)
 */
function clearTemplateCache() {
  TEMPLATE_CONTENT_CACHE.clear();
  console.log('[TemplateLoader] Template cache cleared');
}

/**
 * Template mapping based on algorithm signatures
 */
const TEMPLATE_MAP = {
  // AES templates
  'AES/CBC/PKCS5Padding': {
    templateFile: 'GalaxyDemo-main/ciphers/aes_cbc.py',
    algorithm: 'AES-CBC',
    description: 'AES encryption in CBC mode with PKCS5 padding'
  },
  'AES/ECB/PKCS5Padding': {
    templateFile: 'GalaxyDemo-main/ciphers/aes_ecb.py',
    algorithm: 'AES-ECB',
    description: 'AES encryption in ECB mode with PKCS5 padding'
  },
  'AES/GCM/NoPadding': {
    templateFile: 'GalaxyDemo-main/ciphers/aes_gcm.py',
    algorithm: 'AES-GCM',
    description: 'AES encryption in GCM mode (authenticated encryption)'
  },

  // RSA templates
  'RSA/ECB/PKCS1Padding': {
    templateFile: 'GalaxyDemo-main/ciphers/rsa.py',
    algorithm: 'RSA',
    description: 'RSA encryption with PKCS1 padding'
  },

  // DES templates
  'DES/CBC/PKCS5Padding': {
    templateFile: 'GalaxyDemo-main/ciphers/des.py',
    algorithm: 'DES-CBC',
    description: 'DES encryption in CBC mode'
  },
  'DESede/CBC/PKCS5Padding': {
    templateFile: 'GalaxyDemo-main/ciphers/des3.py',
    algorithm: 'TripleDES',
    description: 'Triple DES (3DES) encryption'
  },

  // Hybrid encryption
  'HYBRID': {
    templateFile: 'GalaxyDemo-main/ciphers/aes_rsa.py',
    algorithm: 'RSA+AES',
    description: 'Hybrid encryption: RSA for key, AES for data'
  },
  'DYNAMIC_KEY': {
    templateFile: 'GalaxyDemo-main/ciphers/dynamic_key.py',
    algorithm: 'Dynamic Key',
    description: 'Dynamic key encryption scenario'
  },

  // SM (Chinese national cryptography) templates
  'SM2': {
    templateFile: 'GalaxyDemo-main/ciphers/sm2.py',
    algorithm: 'SM2',
    description: 'SM2 elliptic curve cryptography (Chinese standard)'
  },
  'SM4/CBC/PKCS5Padding': {
    templateFile: 'GalaxyDemo-main/ciphers/sm4_cbc.py',
    algorithm: 'SM4-CBC',
    description: 'SM4 block cipher in CBC mode (Chinese standard)'
  },
  'SM2+SM4': {
    templateFile: 'GalaxyDemo-main/ciphers/sm2_sm4.py',
    algorithm: 'SM2+SM4',
    description: 'Combined SM2 and SM4 encryption'
  }
};

/**
 * Match a crypto log to a template
 * @param {Object} log - Captured crypto operation log
 * @returns {Object|null} - Matched template info or null
 */
function matchTemplate(log) {
  const { library, method, data } = log;

  try {
    // Extract algorithm signature
    let algorithm = null;

    if (library === 'CryptoJS') {
      const [cipher, operation] = method.split('.');
      if (operation !== 'encrypt' && operation !== 'decrypt') {
        return null;
      }

      const mode = (data.mode || 'CBC').toString().toUpperCase();
      algorithm = `${cipher}/${mode}/PKCS5Padding`;

    } else if (library === 'JSEncrypt') {
      if (method !== 'encrypt' && method !== 'decrypt') {
        return null;
      }
      algorithm = 'RSA/ECB/PKCS1Padding';

    } else if (library === 'Web Crypto API') {
      if (method !== 'encrypt' && method !== 'decrypt') {
        return null;
      }

      const algorithmName = data.algorithm || '';
      if (algorithmName.includes('AES-CBC')) {
        algorithm = 'AES/CBC/PKCS5Padding';
      } else if (algorithmName.includes('AES-ECB')) {
        algorithm = 'AES/ECB/PKCS5Padding';
      } else if (algorithmName.includes('AES-GCM')) {
        algorithm = 'AES/GCM/NoPadding';
      } else if (algorithmName.includes('RSA')) {
        algorithm = 'RSA/ECB/PKCS1Padding';
      }
    }

    // Look up template
    if (algorithm && TEMPLATE_MAP[algorithm]) {
      return {
        ...TEMPLATE_MAP[algorithm],
        matchedAlgorithm: algorithm,
        confidence: 'high'
      };
    }

    // Try fuzzy matching
    if (library === 'CryptoJS' && method.includes('AES')) {
      return {
        templateFile: 'GalaxyDemo-main/ciphers/aes_cbc.py',
        algorithm: 'AES (generic)',
        description: 'AES encryption - using CBC template as base',
        matchedAlgorithm: 'AES/CBC/PKCS5Padding',
        confidence: 'low'
      };
    }

    return null;

  } catch (e) {
    console.warn('[TemplateLoader] Error matching template:', e);
    return null;
  }
}

/**
 * Get template info for display
 * @param {Object} log - Captured crypto operation log
 * @returns {Object} - Template display info
 */
function getTemplateDisplayInfo(log) {
  const match = matchTemplate(log);

  if (!match) {
    return {
      hasTemplate: false,
      message: 'No matching template found',
      suggestion: 'Try using AI generation to create a custom script'
    };
  }

  return {
    hasTemplate: true,
    templateName: match.algorithm,
    templatePath: match.templateFile,
    description: match.description,
    confidence: match.confidence
  };
}

/**
 * Check for hybrid encryption (multiple algorithms detected)
 * @param {Array} logs - Array of captured logs
 * @returns {Object|null} - Hybrid encryption info or null
 */
function detectHybridEncryption(logs) {
  const algorithms = new Set();

  logs.forEach(log => {
    const match = matchTemplate(log);
    if (match) {
      algorithms.add(match.matchedAlgorithm);
    }
  });

  // Check if we have both RSA and AES
  const hasRSA = Array.from(algorithms).some(alg => alg.includes('RSA'));
  const hasAES = Array.from(algorithms).some(alg => alg.includes('AES'));

  if (hasRSA && hasAES) {
    return {
      type: 'HYBRID',
      templateFile: 'GalaxyDemo-main/ciphers/aes_rsa.py',
      algorithms: Array.from(algorithms),
      description: 'Hybrid encryption detected (RSA + AES)'
    };
  }

  return null;
}

/**
 * Format template info for display in UI
 * @param {Object} templateInfo - Template info from getTemplateDisplayInfo
 * @returns {string} - HTML string for display
 */
function formatTemplateDisplay(templateInfo) {
  if (!templateInfo.hasTemplate) {
    return `
      <div class="template-no-match">
        <div>❌ ${templateInfo.message}</div>
        <div style="font-size: 12px; margin-top: 4px;">💡 ${templateInfo.suggestion}</div>
      </div>
    `;
  }

  const confidenceIcon = templateInfo.confidence === 'high' ? '✅' : '⚠️';
  return `
    <div class="template-name">${confidenceIcon} ${templateInfo.templateName}</div>
    <div class="template-path">${templateInfo.templatePath}</div>
    <div style="margin-top: 8px; font-size: 12px;">${templateInfo.description}</div>
  `;
}

// Export functions
window.TemplateLoader = {
  matchTemplate,
  getTemplateDisplayInfo,
  detectHybridEncryption,
  formatTemplateDisplay,
  loadTemplateContent,
  clearTemplateCache,
  TEMPLATE_MAP
};
