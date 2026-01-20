// /panel/aiScriptGenerator.js

/**
 * AI-Powered Script Generator
 * Uses Claude/GPT to generate complex Galaxy scripts with intelligent analysis
 */

/**
 * AI Provider Configuration
 */
const AI_PROVIDERS = {
  CLAUDE: {
    name: 'Claude',
    baseUrl: 'https://api.anthropic.com/v1/messages',
    model: 'claude-3-5-sonnet-20241022'
  },
  OPENAI: {
    name: 'OpenAI',
    baseUrl: 'https://api.openai.com/v1/chat/completions',
    model: 'gpt-4'
  },
  GLM: {
    name: 'GLM-4',
    baseUrl: 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
    model: 'glm-4'
  }
};

/**
 * Generate a comprehensive prompt for Galaxy script generation
 */
function buildGalaxyPrompt(patterns, config, context) {
  const { jsonKey, encoding, language } = config;
  const selectedPattern = patterns.find(p => p.id === context.selectedPatternId);
  const allPatterns = patterns;

  // Analyze patterns to detect complexity
  const complexity = analyzeComplexity(allPatterns, selectedPattern);

  let prompt = `You are an expert Burp Suite Galaxy script generator. Generate a ${language.toUpperCase()} script based on the following cryptographic analysis.

## Task
Generate a complete, production-ready Galaxy ${language === 'python' ? 'Python (GraalPy)' : 'JavaScript (GraalJS)'} script.

## Cryptographic Analysis

### Primary Algorithm
${formatPatternForPrompt(selectedPattern)}

### All Detected Algorithms
${allPatterns.map(p => formatPatternForPrompt(p)).join('\n')}

### Complexity Analysis
${formatComplexityAnalysis(complexity)}

## Script Requirements

1. **Structure**: Must include all 4 hook functions (hook_request_to_burp, hook_request_to_server, hook_response_to_burp, hook_response_to_client)
2. **Algorithm**: Use Galaxy's CryptoUtil for crypto operations
3. **Data Extraction**: jsonKey = "${jsonKey}", encoding = ${encoding}
4. **Language**: ${language === 'python' ? 'Python' : 'JavaScript'} with proper type conversions
5. **Comments**: Add clear Chinese comments explaining each section
6. **Error Handling**: Include basic error handling

## Special Considerations

${generateSpecialInstructions(selectedPattern, complexity, allPatterns)}

## Output Format

Provide ONLY the complete script code without markdown formatting or explanations. The script should be ready to use in Galaxy plugin.

`;

  return prompt;
}

/**
 * Format a single pattern for the prompt
 */
function formatPatternForPrompt(pattern) {
  let text = `
- **Algorithm**: ${pattern.algorithm}
- **Operation**: ${pattern.operation}
- **Library**: ${pattern.library}
- **Samples**: ${pattern.sampleCount}
`;

  if (pattern.key) {
    text += `- **Key**: ${typeof pattern.key === 'string' ? pattern.key.substring(0, 20) + '...' : 'captured'}\n`;
  }

  if (pattern.iv) {
    text += `- **IV**: ${typeof pattern.iv === 'string' ? pattern.iv.substring(0, 20) + '...' : 'captured'}\n`;
  }

  if (pattern.samples && pattern.samples.length > 0) {
    const sample = pattern.samples[0];
    text += `- **Sample Plaintext**: ${typeof sample.plaintext === 'string' ? sample.plaintext.substring(0, 30) : 'N/A'}\n`;
    text += `- **Sample Ciphertext**: ${typeof sample.ciphertext === 'string' ? sample.ciphertext.substring(0, 30) + '...' : 'N/A'}\n`;
  }

  return text;
}

/**
 * Analyze complexity of detected patterns
 */
function analyzeComplexity(allPatterns, selectedPattern) {
  const analysis = {
    isHybrid: false,
    hasDynamicKey: false,
    hasMultipleAlgorithms: false,
    keyDerivation: null,
    recommendedApproach: 'standard'
  };

  // Check for hybrid encryption (RSA + AES)
  const hasRSA = allPatterns.some(p => p.cipher === 'RSA');
  const hasAES = allPatterns.some(p => p.cipher === 'AES');
  analysis.isHybrid = hasRSA && hasAES;

  // Check for multiple algorithms
  analysis.hasMultipleAlgorithms = allPatterns.length > 1;

  // Detect potential dynamic key patterns
  allPatterns.forEach(p => {
    if (p.samples && p.samples.length >= 2) {
      // Check if keys differ between samples
      const keys = p.samples
        .map(s => extractKeyFromSample(s))
        .filter(k => k);

      if (keys.length >= 2 && new Set(keys).size > 1) {
        analysis.hasDynamicKey = true;
        analysis.keyDerivation = detectKeyDerivationPattern(p);
      }
    }
  });

  // Determine recommended approach
  if (analysis.isHybrid) {
    analysis.recommendedApproach = 'hybrid';
  } else if (analysis.hasDynamicKey) {
    analysis.recommendedApproach = 'dynamic_key';
  } else if (analysis.hasMultipleAlgorithms) {
    analysis.recommendedApproach = 'multi_algorithm';
  }

  return analysis;
}

/**
 * Extract key from sample data
 */
function extractKeyFromSample(sample) {
  // Try to find key in various fields
  if (sample.data) {
    return sample.data.key || sample.data.password;
  }
  return null;
}

/**
 * Detect key derivation pattern
 */
function detectKeyDerivationPattern(pattern) {
  // Analyze key samples to detect pattern
  const samples = pattern.samples || [];
  if (samples.length < 2) return null;

  // Check for time-based keys
  const hasTimestampPattern = samples.some(s => {
    const key = extractKeyFromSample(s);
    return key && (key.includes('timestamp') || key.includes('time'));
  });

  // Check for hash-based keys
  const hasHashPattern = samples.some(s => {
    const plaintext = s.plaintext || '';
    return plaintext.match(/[a-f0-9]{32,}/);
  });

  if (hasTimestampPattern) return 'timestamp_based';
  if (hasHashPattern) return 'hash_based';

  return 'unknown';
}

/**
 * Format complexity analysis for prompt
 */
function formatComplexityAnalysis(complexity) {
  let text = '';

  if (complexity.isHybrid) {
    text += '- **Hybrid Encryption Detected**: Combines RSA (key exchange) + AES (data encryption)\n';
  }

  if (complexity.hasDynamicKey) {
    text += '- **Dynamic Key Detected**: Key changes per request\n';
    text += `- **Key Derivation**: ${complexity.keyDerivation || 'unknown pattern'}\n`;
  }

  if (complexity.hasMultipleAlgorithms) {
    text += '- **Multiple Algorithms**: More than one crypto operation detected\n';
  }

  if (!text) {
    text = '- **Standard**: Static key encryption detected';
  }

  return text;
}

/**
 * Generate special instructions based on complexity
 */
function generateSpecialInstructions(pattern, complexity, allPatterns) {
  let instructions = '';

  if (complexity.isHybrid) {
    instructions = `
### Hybrid Encryption Instructions
This appears to be a hybrid encryption scheme. Generate a script that:
1. Decrypts the symmetric key using RSA private key
2. Uses the decrypted symmetric key to decrypt the actual data
3. Look for both 'data' and 'key' fields in the JSON response

Reference the dynamic_key.py example from Galaxy templates for structure.
`;
  } else if (complexity.hasDynamicKey) {
    instructions = `
### Dynamic Key Instructions
This scheme uses dynamic keys. Generate a script that:
1. Extracts the key from each request/response
2. May need to derive the key from request parameters
3. Include comments explaining where to obtain the key

If key derivation pattern is detected (${complexity.keyDerivation}), include helper functions.
`;
  } else {
    instructions = `
### Standard Encryption Instructions
Generate a standard encryption/decryption script with:
- Static key: ${pattern.key || 'MANUALLY_CONFIGURE'}
${pattern.iv ? `- Static IV: ${pattern.iv}` : '- IV: ' + (pattern.algorithm.includes('CBC') ? 'Extract from request or set static' : 'Not required')}
- Standard Galaxy CryptoUtil usage
`;
  }

  // Add custom key warning if needed
  if (!pattern.key) {
    instructions += `
⚠️ **IMPORTANT**: Key was not captured. Add a clear comment indicating where the user should configure the key.
`;
  }

  return instructions;
}

/**
 * Call AI API to generate script
 */
async function callAIAPI(prompt, provider = 'CLAUDE', apiKey) {
  const config = AI_PROVIDERS[provider];

  if (!apiKey) {
    throw new Error('API Key is required. Please configure in settings.');
  }

  let requestBody;
  let headers = {
    'Content-Type': 'application/json'
  };

  if (provider === 'CLAUDE') {
    headers['anthropic-version'] = '2023-06-01';
    headers['x-api-key'] = apiKey;

    requestBody = {
      model: config.model,
      max_tokens: 4096,
      messages: [{
        role: 'user',
        content: prompt
      }]
    };
  } else if (provider === 'OPENAI') {
    headers['Authorization'] = `Bearer ${apiKey}`;

    requestBody = {
      model: config.model,
      messages: [{
        role: 'user',
        content: prompt
      }],
      max_tokens: 4096,
      temperature: 0.7
    };
  }

  try {
    const response = await fetch(config.baseUrl, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API Error (${response.status}): ${errorText}`);
    }

    const data = await response.json();

    // Extract content based on provider
    let scriptContent;
    if (provider === 'CLAUDE') {
      scriptContent = data.content[0].text;
    } else if (provider === 'OPENAI') {
      scriptContent = data.choices[0].message.content;
    }

    // Clean up markdown code blocks if present
    scriptContent = scriptContent.replace(/```python\n?/gi, '');
    scriptContent = scriptContent.replace(/```javascript\n?/gi, '');
    scriptContent = scriptContent.replace(/```\n?/g, '');

    return scriptContent;
  } catch (error) {
    console.error('AI API call failed:', error);
    throw error;
  }
}

/**
 * Main function to generate script using AI
 */
async function generateAIScript(patterns, config, context, aiProvider, apiKey) {
  // Build prompt
  const prompt = buildGalaxyPrompt(patterns, config, context);

  // Call AI API
  const script = await callAIAPI(prompt, aiProvider, apiKey);

  return script;
}

/**
 * Validate AI-generated script
 */
function validateAIScript(script) {
  const errors = [];

  // Check for required functions
  const requiredFunctions = [
    'hook_request_to_burp',
    'hook_request_to_server',
    'hook_response_to_burp',
    'hook_response_to_client'
  ];

  requiredFunctions.forEach(func => {
    if (!script.includes(`def ${func}`) && !script.includes(`function ${func}`)) {
      errors.push(`Missing required function: ${func}`);
    }
  });

  // Check for imports
  if (!script.includes('import') && !script.includes('require')) {
    errors.push('Missing import statements');
  }

  // Check for ALGORITHM definition
  if (!script.includes('ALGORITHM')) {
    errors.push('Missing ALGORITHM configuration');
  }

  return {
    isValid: errors.length === 0,
    errors: errors
  };
}

/**
 * Get AI provider info
 */
function getAIProviders() {
  return Object.keys(AI_PROVIDERS).map(key => ({
    id: key,
    name: AI_PROVIDERS[key].name,
    model: AI_PROVIDERS[key].model
  }));
}

/**
 * Get API key URL instructions
 */
function getAPIKeyInstructions(provider) {
  const instructions = {
    CLAUDE: {
      url: 'https://console.anthropic.com/settings/keys',
      name: 'Anthropic API Key',
      format: 'sk-ant-xxxxxx'
    },
    OPENAI: {
      url: 'https://platform.openai.com/api-keys',
      name: 'OpenAI API Key',
      format: 'sk-xxxxxx'
    },
    GLM: {
      url: 'https://open.bigmodel.cn/usercenter/apikeys',
      name: '智谱AI API Key',
      format: 'id.secret (例如: 1234.abc123...)'
    }
  };

  return instructions[provider] || instructions.CLAUDE;
}

// Export for use in panel.js
window.AIScriptGenerator = {
  generateAIScript,
  validateAIScript,
  getAIProviders,
  getAPIKeyInstructions,
  analyzeComplexity
};
