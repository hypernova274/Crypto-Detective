// /panel/panel.js

document.addEventListener('DOMContentLoaded', () => {
  const clearLogsBtn = document.getElementById('clear-logs-btn');
  const searchInput = document.getElementById('search-input');
  const filterCheckboxes = document.querySelectorAll('.filter-lib');
  const logsTableBody = document.getElementById('logs-tbody');
  const noLogsMessage = document.getElementById('no-logs-message');
  const noResultsMessage = document.getElementById('no-results-message');

  let allLogs = []; // A local cache of all logs to enable fast filtering

  // Expose allLogs globally for debugging and Galaxy integration
  window.cryptoDetectiveState = {
    get allLogs() {
      return allLogs;
    },
    get logCount() {
      return allLogs.length;
    }
  };

  /**
   * Sanitizes a string for safe insertion into HTML.
   */
  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  // 简单 JSON 语法高亮 + 行号/标点着色
  function highlightJson(obj) {
    try {
      let json = JSON.stringify(obj, null, 2);
      if (!json) return '';
      json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      json = json.replace(/(\"(?:\\u[\da-fA-F]{4}|\\.|[^\\\"])*\")(\s*:\s*)/g, '<span class="hl-key">$1</span>$2');
      json = json.replace(/(:\s*)(\"(?:\\u[\da-fA-F]{4}|\\.|[^\\\"])*\")/g, '$1<span class="hl-string">$2</span>');
      json = json.replace(/(:\s*)(-?\d+(?:\.\d+)?|true|false|null)/g, (m, p1, p2) => {
        if (p2 === 'true' || p2 === 'false') return p1 + '<span class="hl-boolean">' + p2 + '</span>';
        if (p2 === 'null') return p1 + '<span class="hl-null">null</span>';
        return p1 + '<span class="hl-number">' + p2 + '</span>';
      });
      json = json.replace(/([{}\[\],])/g, '<span class="hl-punc">$1</span>');

      const lines = json.split('\n');
      return lines.map((line, i) => `\n<span class=\"code-line\"><span class=\"line-no\">${i + 1}</span><span class=\"line-text\">${line || ' '}</span></span>`).join('');
    } catch (e) {
      return escapeHtml(String(obj));
    }
  }

  function truncate(str, maxLen = 256) {
    if (typeof str !== 'string') return '';
    return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
  }

  function extractPlainCipher(log) {
    const data = (log && log.data) || {};
    const method = String(log && log.method || '').toLowerCase();
    const lib = String(log && log.library || '');

    let plaintext = null;
    let ciphertext = null;

    if (lib === 'JSEncrypt') {
      if (method.includes('encrypt')) {
        plaintext = data.plaintext;
        ciphertext = data.result_ciphertext_b64;
      } else if (method.includes('decrypt')) {
        ciphertext = data.ciphertext_b64;
        plaintext = data.result_plaintext;
      }
    } else if (lib === 'CryptoJS') {
      if (method.includes('encrypt')) {
        plaintext = data.message;
        ciphertext = data.result_ciphertext;
      } else if (method.includes('decrypt')) {
        ciphertext = data.ciphertext;
        plaintext = data.result_plaintext;
      }
    } else if (lib === 'Web Crypto API') {
      if (method.includes('encrypt')) {
        plaintext = data.input_data_hex;
        ciphertext = data.result_ciphertext_hex;
      } else if (method.includes('decrypt')) {
        ciphertext = data.input_ciphertext_hex;
        plaintext = data.result_plaintext_hex;
      }
    } else if (lib === 'Forge.js') {
      if (method.includes('encrypt')) {
        plaintext = data.input_data;
        ciphertext = data.output_data;
      } else if (method.includes('decrypt')) {
        ciphertext = data.input_data;
        plaintext = data.output_data;
      }
    }

    if (!plaintext && typeof data.plaintext === 'string') plaintext = data.plaintext;
    if (!ciphertext && (typeof data.ciphertext === 'string' || typeof data.ciphertext_b64 === 'string')) {
      ciphertext = data.ciphertext || data.ciphertext_b64;
    }
    if (!ciphertext && (typeof data.result_ciphertext === 'string' || typeof data.result_ciphertext_b64 === 'string')) {
      ciphertext = data.result_ciphertext || data.result_ciphertext_b64;
    }
    if (!plaintext && (typeof data.result_plaintext === 'string' || typeof data.result_plaintext_hex === 'string')) {
      plaintext = data.result_plaintext || data.result_plaintext_hex;
    }

    return {
      plaintext: typeof plaintext === 'string' ? plaintext : null,
      ciphertext: typeof ciphertext === 'string' ? ciphertext : null,
    };
  }

  /**
   * Renders the entire list of logs to the table, applying current filters.
   */
  function renderTable() {
    const searchTerm = searchInput.value.toLowerCase();
    const activeFilters = Array.from(filterCheckboxes)
      .filter(cb => cb.checked)
      .map(cb => cb.value);

    logsTableBody.innerHTML = ''; // Clear the table

    const filteredLogs = allLogs.filter(log => {
      const searchHaystack = [
        log.library,
        log.method,
        log.origin,
        JSON.stringify(log.data)
      ].join(' ').toLowerCase();

      const matchesSearch = !searchTerm || searchHaystack.includes(searchTerm);
      const matchesFilter = activeFilters.includes(log.library);

      return matchesSearch && matchesFilter;
    });

    filteredLogs.forEach(addLogRow);
    updateEmptyStates();
  }

  /**
   * Updates visibility of the "no logs" or "no results" messages.
   */
  function updateEmptyStates() {
    const hasAnyLogs = allLogs.length > 0;
    const hasVisibleLogs = logsTableBody.children.length > 0;

    noLogsMessage.style.display = !hasAnyLogs ? 'block' : 'none';
    noResultsMessage.style.display = hasAnyLogs && !hasVisibleLogs ? 'block' : 'none';
  }

  /**
   * Creates and appends a new row to the table for a single log entry.
   */
  function buildSummaryHtml(plaintext, ciphertext) {
    const MAX_LEN = 256;
    const hasPlainMore = typeof plaintext === 'string' && plaintext.length > MAX_LEN;
    const hasCipherMore = typeof ciphertext === 'string' && ciphertext.length > MAX_LEN;

    const plainTrunc = hasPlainMore ? truncate(plaintext, MAX_LEN) : plaintext || '';
    const cipherTrunc = hasCipherMore ? truncate(ciphertext, MAX_LEN) : ciphertext || '';

    const plainBlock = plaintext ? `
<div class="summary-item plaintext">
  <strong>明文:</strong>
  <span class="summary-text truncated">${escapeHtml(plainTrunc)}</span>
  ${hasPlainMore ? `<span class="summary-text full" style="display:none">${escapeHtml(plaintext)}</span>` : ''}
  ${hasPlainMore ? `<a href="#" class="toggle-more" data-target="plain" data-expanded="false">显示更多</a>` : ''}
</div>` : '';

    const cipherBlock = ciphertext ? `
<div class="summary-item ciphertext">
  <strong>密文:</strong>
  <span class="summary-text truncated">${escapeHtml(cipherTrunc)}</span>
  ${hasCipherMore ? `<span class="summary-text full" style="display:none">${escapeHtml(ciphertext)}</span>` : ''}
  ${hasCipherMore ? `<a href="#" class="toggle-more" data-target="cipher" data-expanded="false">显示更多</a>` : ''}
</div>` : '';

    const hasAny = !!(plaintext || ciphertext);
    return hasAny ? `<div class="log-summary">${plainBlock}${cipherBlock}</div>` : '';
  }

  function addLogRow(log) {
    const row = document.createElement('tr');
    row.className = 'log-row';
    // Store data on the element for filtering
    row.dataset.library = log.library;
    row.dataset.searchText = [log.library, log.method, log.origin, JSON.stringify(log.data)].join(' ');

    const safeTimestamp = escapeHtml(new Date(log.timestamp).toLocaleTimeString());
    const safeLibrary = escapeHtml(log.library);
    const safeMethod = escapeHtml(log.method);
    const safeOrigin = escapeHtml(log.origin);
    const highlightedData = highlightJson(log.data);

    const { plaintext, ciphertext } = extractPlainCipher(log);
    const summaryHtml = buildSummaryHtml(plaintext, ciphertext);

    row.innerHTML = `
      <td class="col-time">${safeTimestamp}</td>
      <td class="col-lib">${safeLibrary}</td>
      <td class="col-method">${safeMethod}</td>
      <td class="col-data">${summaryHtml}<pre class="log-data-pre"><code>${highlightedData}</code></pre></td>
      <td class="col-origin"><a href="${safeOrigin}" target="_blank" title="${safeOrigin}">${safeOrigin}</a></td>
      <td class="col-galaxy"><button class="generate-galaxy-btn" data-log-index="${allLogs.indexOf(log)}">Generate</button></td>
    `;
    logsTableBody.appendChild(row);
  }

  // 展开/收起交互（事件委托）
  document.addEventListener('click', (e) => {
    const target = e.target;
    if (!target || !(target instanceof Element)) return;
    if (!target.classList.contains('toggle-more')) return;
    e.preventDefault();
    const container = target.closest('.summary-item');
    if (!container) return;
    const truncated = container.querySelector('.summary-text.truncated');
    const full = container.querySelector('.summary-text.full');
    const expanded = target.getAttribute('data-expanded') === 'true';
    if (full) {
      if (expanded) {
        full.style.display = 'none';
        if (truncated) truncated.style.display = '';
        target.textContent = '显示更多';
        target.setAttribute('data-expanded', 'false');
      } else {
        if (truncated) truncated.style.display = 'none';
        full.style.display = '';
        target.textContent = '显示更少';
        target.setAttribute('data-expanded', 'true');
      }
    }
  });

  // --- Initialize Panel ---

  // 1. Establish connection with the background script.
  const port = chrome.runtime.connect({ name: 'crypto-detective-ui' });

  // 2. Listen for real-time updates.
  port.onMessage.addListener((message) => {
    if (!message || !message.type) return;

    switch (message.type) {
      case 'NEW_LOG':
        allLogs.unshift(message.payload); // Add to local cache
        renderTable(); // Re-render the table with the new log
        break;
      case 'LOGS_CLEARED':
        allLogs = []; // Clear local cache
        renderTable(); // Re-render to show empty state
        break;
    }
  });

  // 3. Get initial data when the panel opens.
  chrome.runtime.sendMessage({ type: 'GET_INITIAL_DATA' }, (response) => {
    if (chrome.runtime.lastError) {
      console.error("Crypto Detective: " + chrome.runtime.lastError.message);
      noLogsMessage.textContent = "Error loading data. Try closing and reopening the DevTools panel.";
      return;
    }
    allLogs = response.logs || [];
    renderTable();
  });

  // 4. Set up event listeners for controls.
  clearLogsBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'CLEAR_LOGS' });
  });

  searchInput.addEventListener('input', renderTable);
  filterCheckboxes.forEach(cb => cb.addEventListener('change', renderTable));

  // --- Galaxy Script Generator Integration ---

  // Validate Galaxy modules are loaded
  console.log('[Galaxy] Checking if Galaxy modules are loaded...');
  console.log('[Galaxy] window.GalaxyGenerator:', typeof window.GalaxyGenerator);
  console.log('[Galaxy] window.GalaxyTemplates:', typeof window.GalaxyTemplates);
  console.log('[Galaxy] window.AIScriptGenerator:', typeof window.AIScriptGenerator);

  if (!window.GalaxyGenerator) {
    console.error('[Galaxy] ERROR: window.GalaxyGenerator not found! Check if galaxyGenerator.js is loaded.');
  }
  if (!window.GalaxyTemplates) {
    console.error('[Galaxy] ERROR: window.GalaxyTemplates not found! Check if galaxyTemplates.js is loaded.');
  }

  const galaxyPanel = document.getElementById('galaxy-panel');
  const galaxyGeneratorBtn = document.getElementById('galaxy-generator-btn');
  const closeGalaxyPanelBtn = document.getElementById('close-galaxy-panel');
  const detectedAlgorithmsContainer = document.getElementById('detected-algorithms');
  const generateScriptBtn = document.getElementById('generate-script-btn');
  const copyScriptBtn = document.getElementById('copy-script-btn');
  const downloadScriptBtn = document.getElementById('download-script-btn');
  const outputSection = document.getElementById('output-section');
  const generatedScriptTextarea = document.getElementById('generated-script');
  const selectedCryptoRecordContainer = document.getElementById('selected-crypto-record');
  const matchedTemplateContainer = document.getElementById('matched-template');
  const aiLogSection = document.getElementById('ai-log-section');
  const aiLogOutput = document.getElementById('ai-log-output');
  const copyLogBtn = document.getElementById('copy-log-btn');
  const clearLogBtn = document.getElementById('clear-log-btn');

  let selectedLog = null; // Store the selected crypto log for single-record generation

  // Open Galaxy panel (global button - legacy, still works)
  galaxyGeneratorBtn.addEventListener('click', () => {
    galaxyPanel.classList.add('open');
    detectAndDisplayAlgorithms();
  });

  // Close Galaxy panel
  closeGalaxyPanelBtn.addEventListener('click', () => {
    galaxyPanel.classList.remove('open');
  });

  // Generate button clicks on each row (event delegation)
  logsTableBody.addEventListener('click', (e) => {
    if (!e.target.classList.contains('generate-galaxy-btn')) return;

    const logIndex = parseInt(e.target.dataset.logIndex);
    if (isNaN(logIndex) || logIndex < 0 || logIndex >= allLogs.length) {
      console.error('[Galaxy] Invalid log index:', logIndex);
      return;
    }

    selectedLog = allLogs[logIndex];
    console.log('[Galaxy] Selected log for Galaxy generation:', selectedLog);

    // Open panel and display selected log info
    galaxyPanel.classList.add('open');
    displaySelectedCryptoRecord(selectedLog);
    matchAndDisplayTemplate(selectedLog);
  });

  // Refresh algorithm detection (removed - not needed for single-record mode)

  // Generate script button
  generateScriptBtn.addEventListener('click', () => {
    generateGalaxyScript();
  });

  // Copy script button
  copyScriptBtn.addEventListener('click', () => {
    copyScriptToClipboard();
  });

  // Download script button
  downloadScriptBtn.addEventListener('click', () => {
    downloadScriptFile();
  });

  // Copy log button
  if (copyLogBtn) {
    copyLogBtn.addEventListener('click', () => {
      const logText = aiLogOutput.textContent;
      if (!logText) {
        alert('No log to copy.');
        return;
      }
      navigator.clipboard.writeText(logText).then(() => {
        const originalText = copyLogBtn.textContent;
        copyLogBtn.textContent = 'Copied!';
        setTimeout(() => {
          copyLogBtn.textContent = originalText;
        }, 2000);
      }).catch(err => {
        alert('Failed to copy: ' + err);
      });
    });
  }

  // Clear log button
  if (clearLogBtn) {
    clearLogBtn.addEventListener('click', () => {
      aiLogOutput.innerHTML = '';
      aiLogSection.style.display = 'none';
    });
  }

  // AI checkbox toggle
  const useAICheckbox = document.getElementById('use-ai');
  const aiProviderConfig = document.getElementById('ai-provider-config');
  const apiKeyConfig = document.getElementById('api-key-config');
  const getAPIKeyLink = document.getElementById('get-api-key-link');
  const aiProviderSelect = document.getElementById('ai-provider');

  // Only add AI listeners if elements exist
  if (useAICheckbox && aiProviderConfig && apiKeyConfig && getAPIKeyLink && aiProviderSelect) {
    useAICheckbox.addEventListener('change', () => {
      if (useAICheckbox.checked) {
        aiProviderConfig.style.display = 'block';
        apiKeyConfig.style.display = 'block';
        updateAPIKeyLink();
      } else {
        aiProviderConfig.style.display = 'none';
        apiKeyConfig.style.display = 'none';
      }
    });

    aiProviderSelect.addEventListener('change', () => {
      updateAPIKeyLink();
    });

    getAPIKeyLink.addEventListener('click', (e) => {
      e.preventDefault();
      const provider = aiProviderSelect.value;
      const instructions = window.AIScriptGenerator.getAPIKeyInstructions(provider);
      chrome.tabs.create({ url: instructions.url });
    });

    function updateAPIKeyLink() {
      const provider = aiProviderSelect.value;
      const instructions = window.AIScriptGenerator.getAPIKeyInstructions(provider);
      getAPIKeyLink.textContent = `Get ${instructions.name}`;

      // 更新 placeholder 提示 API Key 格式
      const apiKeyInput = document.getElementById('api-key');
      if (apiKeyInput && instructions.format) {
        apiKeyInput.placeholder = `Enter your ${instructions.name}\nFormat: ${instructions.format}`;
      }
    }

    // 初始化时也更新一次
    updateAPIKeyLink();

    // 从 localStorage 恢复 AI Provider 和 API Key
    const savedProvider = localStorage.getItem('galaxy-ai-provider');
    const savedAPIKey = localStorage.getItem('galaxy-api-key');
    if (savedProvider) {
      aiProviderSelect.value = savedProvider;
      updateAPIKeyLink();
    }
    if (savedAPIKey) {
      document.getElementById('api-key').value = savedAPIKey;
    }

    // 保存 AI Provider 选择
    aiProviderSelect.addEventListener('change', () => {
      localStorage.setItem('galaxy-ai-provider', aiProviderSelect.value);
    });

    // 保存 API Key（输入时自动保存）
    const apiKeyInput = document.getElementById('api-key');
    apiKeyInput.addEventListener('input', () => {
      localStorage.setItem('galaxy-api-key', apiKeyInput.value.trim());
    });
  }

  // === AI Prompt 模板和本地存储 ===
  const aiPromptTextarea = document.getElementById('ai-prompt');
  const usePromptTemplateBtn = document.getElementById('use-prompt-template-btn');
  const clearPromptBtn = document.getElementById('clear-prompt-btn');

  // 专业提示词模板
  const PROFESSIONAL_PROMPT_TEMPLATE = `请特别关注以下要求：

## 代码质量
- 添加完整的异常捕获和错误处理
- 在关键步骤添加详细的中文注释
- 处理边界情况（空数据、格式错误等）

## 功能实现
- 实现双向处理：请求加密 + 响应解密
- 正确映射 JavaScript 参数到 Python 加密库
- 使用 Galaxy API：hook_request_to_burp, hook_request_to_server
- 数据验证：确保解密后的数据格式正确

## 测试和调试
- 添加调试日志输出（但不输出完整密钥）
- 提供测试示例代码注释
- 说明常见问题的排查方法`;

  // 从 localStorage 恢复提示词
  const savedPrompt = localStorage.getItem('galaxy-ai-prompt');
  if (savedPrompt && aiPromptTextarea) {
    aiPromptTextarea.value = savedPrompt;
  }

  // 使用专业模板按钮
  if (usePromptTemplateBtn && aiPromptTextarea) {
    usePromptTemplateBtn.addEventListener('click', () => {
      if (confirm('这将覆盖当前的自定义提示词，是否继续？')) {
        aiPromptTextarea.value = PROFESSIONAL_PROMPT_TEMPLATE;
        localStorage.setItem('galaxy-ai-prompt', PROFESSIONAL_PROMPT_TEMPLATE);
        addAILog('已加载专业提示词模板', 'success');
      }
    });
  }

  // 清空提示词按钮
  if (clearPromptBtn && aiPromptTextarea) {
    clearPromptBtn.addEventListener('click', () => {
      if (confirm('确定要清空提示词吗？')) {
        aiPromptTextarea.value = '';
        localStorage.setItem('galaxy-ai-prompt', '');
        addAILog('提示词已清空', 'info');
      }
    });
  }

  // 自动保存提示词
  if (aiPromptTextarea) {
    aiPromptTextarea.addEventListener('input', () => {
      localStorage.setItem('galaxy-ai-prompt', aiPromptTextarea.value);
    });
  }

  // === 配置项的本地存储 ===
  const scriptLanguageSelect = document.getElementById('script-language');
  const jsonKeyInput = document.getElementById('json-key');
  const encodingTypeSelect = document.getElementById('encoding-type');

  // 恢复保存的配置
  const savedLanguage = localStorage.getItem('galaxy-script-language');
  const savedJsonKey = localStorage.getItem('galaxy-json-key');
  const savedEncoding = localStorage.getItem('galaxy-encoding');

  if (savedLanguage && scriptLanguageSelect) scriptLanguageSelect.value = savedLanguage;
  if (savedJsonKey && jsonKeyInput) jsonKeyInput.value = savedJsonKey;
  if (savedEncoding && encodingTypeSelect) encodingTypeSelect.value = savedEncoding;

  // 保存配置变化
  if (scriptLanguageSelect) {
    scriptLanguageSelect.addEventListener('change', () => {
      localStorage.setItem('galaxy-script-language', scriptLanguageSelect.value);
    });
  }
  if (jsonKeyInput) {
    jsonKeyInput.addEventListener('input', () => {
      localStorage.setItem('galaxy-json-key', jsonKeyInput.value);
    });
  }
  if (encodingTypeSelect) {
    encodingTypeSelect.addEventListener('change', () => {
      localStorage.setItem('galaxy-encoding', encodingTypeSelect.value);
    });
  }

  /**
   * Add a log entry to the AI log output
   */
  function addAILog(message, type = 'info') {
    if (!aiLogOutput) return;

    // Show log section if hidden
    if (aiLogSection && aiLogSection.style.display === 'none') {
      aiLogSection.style.display = 'block';
    }

    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-${type}`;

    if (type === 'info') {
      logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span><span class="log-info">${escapeHtml(message)}</span>`;
    } else if (type === 'success') {
      logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span><span class="log-success">✓ ${escapeHtml(message)}</span>`;
    } else if (type === 'warning') {
      logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span><span class="log-warning">⚠ ${escapeHtml(message)}</span>`;
    } else if (type === 'error') {
      logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span><span class="log-error">✗ ${escapeHtml(message)}</span>`;
    } else {
      logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span>${escapeHtml(message)}`;
    }

    aiLogOutput.appendChild(logEntry);
    aiLogOutput.scrollTop = aiLogOutput.scrollHeight; // Auto-scroll to bottom
  }

  /**
   * Display the selected crypto record details in the Galaxy panel
   */
  function displaySelectedCryptoRecord(log) {
    const container = document.getElementById('selected-crypto-record');
    if (!container) return;

    const { library, method, data, origin } = log;

    // Extract key info
    let keyInfo = 'Not captured';
    let ivInfo = 'Not captured';

    if (library === 'CryptoJS') {
      keyInfo = data.key ? `"${data.key}"` : 'Not captured';
      ivInfo = data.iv ? `"${data.iv}"` : 'Not captured';
    } else if (library === 'JSEncrypt') {
      keyInfo = data.key_summary || data.public_key || 'Not captured';
    } else if (library === 'Web Crypto API') {
      keyInfo = data.key_type || 'Not captured';
    }

    container.innerHTML = `
      <div class="detail-row">
        <span class="detail-label">Library:</span>
        <span class="detail-value">${escapeHtml(library)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Method:</span>
        <span class="detail-value">${escapeHtml(method)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Key:</span>
        <span class="detail-value">${escapeHtml(keyInfo)}</span>
      </div>
      ${ivInfo !== 'Not captured' ? `
      <div class="detail-row">
        <span class="detail-label">IV:</span>
        <span class="detail-value">${escapeHtml(ivInfo)}</span>
      </div>
      ` : ''}
      <div class="detail-row">
        <span class="detail-label">Origin:</span>
        <span class="detail-value"><a href="${escapeHtml(origin)}" target="_blank">${escapeHtml(origin)}</a></span>
      </div>
    `;
  }

  /**
   * Match template and display in the Galaxy panel
   */
  function matchAndDisplayTemplate(log) {
    const container = document.getElementById('matched-template');
    if (!container) return;

    const templateInfo = window.TemplateLoader.getTemplateDisplayInfo(log);
    container.innerHTML = window.TemplateLoader.formatTemplateDisplay(templateInfo);
  }

  /**
   * Detect algorithms from captured logs and display them
   */
  function detectAndDisplayAlgorithms() {
    console.log('[Galaxy] detectAndDisplayAlgorithms called');
    console.log('[Galaxy] allLogs length:', allLogs.length);
    console.log('[Galaxy] allLogs:', allLogs);

    detectedPatterns = window.GalaxyGenerator.aggregateAlgorithms(allLogs);

    console.log('[Galaxy] detectedPatterns length:', detectedPatterns.length);
    console.log('[Galaxy] detectedPatterns:', detectedPatterns);

    if (detectedPatterns.length === 0) {
      detectedAlgorithmsContainer.innerHTML = `
        <div class="empty-state">No algorithms detected. Capture some crypto operations first.</div>
      `;
      return;
    }

    detectedAlgorithmsContainer.innerHTML = '';

    detectedPatterns.forEach((pattern, index) => {
      const item = document.createElement('div');
      item.className = 'algorithm-item';
      if (index === 0) {
        item.classList.add('selected');
        selectedPattern = pattern;
      }

      const canGenerate = window.GalaxyGenerator.canGenerateScript(pattern);
      const badgeClass = pattern.supportLevel === 'high' ? 'badge-success' : 'badge-warning';

      item.innerHTML = `
        <input type="radio" name="algorithm" value="${pattern.id}" ${index === 0 ? 'checked' : ''} ${!canGenerate ? 'disabled' : ''}>
        <div class="algorithm-info">
          <div class="algorithm-name">
            ${window.GalaxyGenerator.getAlgorithmDisplayName(pattern)}
            <span class="badge ${badgeClass}">${pattern.sampleCount} samples</span>
          </div>
          <div class="algorithm-details">
            ${pattern.algorithm}
            ${pattern.hasKey ? ' • Key captured' : ' • Key not captured'}
            ${pattern.hasIV ? ' • IV captured' : ''}
          </div>
        </div>
      `;

      item.addEventListener('click', () => {
        if (!canGenerate) return;

        // Remove selection from all items
        document.querySelectorAll('.algorithm-item').forEach(el => {
          el.classList.remove('selected');
        });

        // Select this item
        item.classList.add('selected');
        selectedPattern = pattern;
      });

      detectedAlgorithmsContainer.appendChild(item);
    });
  }

  /**
   * Generate Galaxy script based on selected pattern and configuration
   */
  async function generateGalaxyScript() {
    console.log('[Galaxy] Generate script button clicked');
    addAILog('=== Script Generation Started ===', 'info');

    // Check if we have a selected log
    if (!selectedLog) {
      alert('Please click "Generate" button on a log row first.');
      console.warn('[Galaxy] No log selected');
      addAILog('Error: No log selected. Please click "Generate" button on a log row first.', 'error');
      return;
    }

    console.log('[Galaxy] Selected log:', selectedLog);
    addAILog(`Selected algorithm: ${selectedLog.library} - ${selectedLog.method}`, 'info');

    const languageEl = document.getElementById('script-language');
    const jsonKeyEl = document.getElementById('json-key');
    const encodingEl = document.getElementById('encoding-type');
    const aiPromptEl = document.getElementById('ai-prompt');

    if (!languageEl || !jsonKeyEl || !encodingEl) {
      alert('Error: Required configuration elements not found');
      console.error('[Galaxy] Missing configuration elements');
      addAILog('Error: Required configuration elements not found', 'error');
      return;
    }

    const language = languageEl.value;
    const jsonKey = jsonKeyEl.value || 'data';
    const encoding = encodingEl.value;
    const userPrompt = aiPromptEl ? aiPromptEl.value.trim() : '';
    const useAI = useAICheckbox ? useAICheckbox.checked : false;

    console.log('[Galaxy] Config:', { language, jsonKey, encoding, useAI, userPrompt });
    addAILog(`Configuration: ${language}, jsonKey="${jsonKey}", encoding=${encoding}, useAI=${useAI}`, 'info');

    // Get template match for the selected log
    const templateMatch = window.TemplateLoader.matchTemplate(selectedLog);
    console.log('[Galaxy] Template match:', templateMatch);

    if (templateMatch) {
      addAILog(`Matched template: ${templateMatch.templateFile}`, 'success');
    } else {
      addAILog('No exact template match found. Will use generic approach.', 'warning');
    }

    // Extract algorithm signature from the log
    addAILog('Extracting algorithm signature from log...', 'info');

    // Log the complete selected log for debugging
    console.log('[Galaxy] Full selected log:', JSON.stringify(selectedLog, null, 2));
    addAILog(`Library: ${selectedLog.library}, Method: ${selectedLog.method}`, 'info');

    // Check what data we have
    if (!selectedLog.data) {
      console.error('[Galaxy] No data field in selected log!');
      addAILog('Error: Log entry missing data field', 'error');
      alert('The selected log entry is missing required data. Please try a different log or capture new crypto operations.');
      return;
    }

    console.log('[Galaxy] Log data keys:', Object.keys(selectedLog.data));
    console.log('[Galaxy] Log data:', selectedLog.data);
    addAILog(`Data keys: ${Object.keys(selectedLog.data).join(', ')}`, 'info');

    let signature = window.GalaxyGenerator.extractAlgorithmSignature(selectedLog);

    // Even if signature extraction fails, we can still try AI generation with the raw data
    if (!signature) {
      console.warn('[Galaxy] Failed to extract algorithm signature, but will try AI generation with raw data');
      addAILog('Warning: Could not auto-detect algorithm details', 'warning');
      addAILog('Will use AI to analyze the captured data', 'info');

      // Continue with AI generation using a minimal signature
      signature = {
        library: selectedLog.library,
        algorithm: 'Unknown', // Let AI figure it out
        cipher: selectedLog.method.split('.')[0] || 'Unknown',
        mode: selectedLog.data?.mode || 'Unknown',
        operation: selectedLog.method.split('.')[1] || 'unknown',
        key: selectedLog.data?.key || null,
        iv: selectedLog.data?.iv || null,
        hasSample: !!(selectedLog.data?.message || selectedLog.data?.ciphertext),
        data: selectedLog.data
      };
    }

    console.log('[Galaxy] Algorithm signature:', signature);
    addAILog(`Extracted algorithm: ${signature.algorithm}`, 'info');

    // Build config for generation
    const config = {
      algorithm: signature.algorithm,
      key: signature.key || '',
      iv: signature.iv || '',
      jsonKey,
      encoding,
      language
    };

    try {
      let script;

      if (useAI) {
        // AI-based generation with template + crypto info + user prompt
        const aiProvider = aiProviderSelect.value;
        const apiKey = document.getElementById('api-key').value;

        if (!apiKey) {
          alert('Please enter your API key to use AI generation.');
          addAILog('Error: API Key is missing', 'error');
          return;
        }

        console.log('[Galaxy] Using AI generation with provider:', aiProvider);
        addAILog(`AI Provider: ${aiProvider}`, 'info');

        // Show loading state
        generateScriptBtn.textContent = 'Generating with AI...';
        generateScriptBtn.disabled = true;

        // Build the AI prompt with template, crypto info, and user instructions
        addAILog('Loading template file...', 'info');
        const aiPrompt = await buildAIPromptWithTemplate(selectedLog, templateMatch, userPrompt, config);

        console.log('[Galaxy] AI Prompt length:', aiPrompt.length);
        addAILog(`Built AI prompt (${aiPrompt.length} characters)`, 'info');
        addAILog(`User prompt: ${userPrompt || '(none)'}`, 'info');

        // Call AI API
        addAILog('Sending request to AI API...', 'info');
        script = await callAIForScriptGeneration(aiPrompt, aiProvider, apiKey);
        addAILog('AI API request completed successfully', 'success');
        addAILog(`Generated script length: ${script.length} characters`, 'info');

        // Reset button
        generateScriptBtn.textContent = 'Generate Galaxy Script';
        generateScriptBtn.disabled = false;
      } else {
        // Template-based generation
        console.log('[Galaxy] Using template-based generation');
        addAILog('Using template-based generation (fast mode)', 'info');
        script = window.GalaxyTemplates.generateGalaxyScript(signature, config, [signature]);
        addAILog(`Generated script length: ${script.length} characters`, 'info');
      }

      // Display generated script
      generatedScriptTextarea.value = script;
      outputSection.style.display = 'block';

      console.log('[Galaxy] Script generated successfully');
      addAILog('=== Script Generation Completed Successfully ===', 'success');
      addAILog('Script is ready to copy or download', 'info');
    } catch (error) {
      console.error('[Galaxy] Script generation error:', error);
      addAILog(`Error: ${error.message}`, 'error');
      alert('Error generating script: ' + error.message);

      // Reset button if it was disabled
      if (generateScriptBtn.disabled) {
        generateScriptBtn.textContent = 'Generate Galaxy Script';
        generateScriptBtn.disabled = false;
      }
    }
  }

  /**
   * Build AI prompt with template, crypto info, and user instructions
   */
  async function buildAIPromptWithTemplate(log, templateMatch, userPrompt, config) {
    const { library, method, data } = log;

    // 构建 JS 加密算法片段说明
    const jsCryptoSnippet = `
// JavaScript 加密算法片段（捕获自网页）
// 库: ${library}
// 方法: ${method}
// 加密参数:
${Object.entries(data).map(([key, value]) => {
  if (key === 'mode' && typeof value === 'object') {
    return `//   - ${key}: [CryptoJS Mode Object]`;
  }
  return `//   - ${key}: ${JSON.stringify(value)}`;
}).join('\n')}
`;

    let prompt = `你是一个专业的 Burp Suite Galaxy 脚本生成专家。

# 任务概述
根据捕获的 JavaScript 加密算法片段和 GalaxyDemo Python 模板，生成一个完整的 Galaxy 脚本。

## 捕获的 JavaScript 加密算法片段
\`\`\`javascript
${jsCryptoSnippet}
// 示例调用（实际参数值见下方完整数据）：
// CryptoJS.AES.${method.split('.')[1]}(ciphertext, key, { mode: CryptoJS.mode.${data.mode || 'CBC'}, iv: iv })
\`\`\`

## 完整的加密参数数据
\`\`\`json
${JSON.stringify(data, null, 2)}
\`\`\`

## 参考 Python 模板
`;

    if (templateMatch) {
      prompt += `**模板文件**: ${templateMatch.templateFile}
**算法类型**: ${templateMatch.algorithm}
**模板说明**: ${templateMatch.description}

`;

      // 尝试加载模板文件内容
      const templateContent = await window.TemplateLoader.loadTemplateContent(templateMatch.templateFile);

      if (templateContent) {
        prompt += `### 模板完整代码
\`\`\`python
${templateContent}
\`\`\`

以上是 GalaxyDemo 的参考模板。请基于此模板结构，将上述 JavaScript 的加密参数（key、iv、mode 等）正确映射到 Python 加密库的对应参数。
`;
      } else {
        prompt += `⚠️ 注意：模板文件内容未能加载，但请参考 GalaxyDemo-main/ciphers/ 目录下的 ${templateMatch.templateFile} 文件。

该模板通常展示：
1. 标准 Galaxy 脚本的结构
2. Python 加密库的正确使用方式（如 Crypto.Cipher.AES）
3. Galaxy API 的调用方法（hook_request_to_burp, hook_request_to_server 等）
4. 数据编码和解码的处理方式

你需要做的是：将上述 JavaScript 的加密参数（key、iv、mode 等）映射到 Python 模板的对应参数。
`;
      }
    } else {
      prompt += `未找到精确匹配的模板。
请参考 GalaxyDemo-main/ciphers/aes_cbc.py 作为基础模板，根据实际的 JavaScript 加密算法进行适配。

关键映射关系：
- JavaScript CryptoJS.AES -> Python Crypto.Cipher.AES
- JavaScript mode (CBC/ECB/GCM) -> Python mode (MODE_CBC/MODE_ECB/MODE_GCM)
- JavaScript key/iv -> Python bytes 类型
- JavaScript Base64 编码 -> Python base64.b64decode
`;
    }

    // 配置信息
    prompt += `## 脚本配置
- 目标语言: ${config.language}
- JSON 字段名: ${config.jsonKey}
- 数据编码: ${config.encoding}
- 密钥: ${config.key || '需要从捕获数据中提取'}
- IV: ${config.iv || '需要从捕获数据中提取'}

`;

    if (userPrompt) {
      prompt += `## 用户自定义要求
${userPrompt}

`;
    }

    prompt += `## 生成要求
请生成一个完整的、可直接运行的 Galaxy 脚本，要求：

1. **参考模板结构**：基于 GalaxyDemo 的 Python 模板结构
2. **参数映射**：将 JavaScript 的加密参数正确映射到 Python
3. **Galaxy API**：实现 hook_request_to_burp 和 hook_request_to_server 函数
4. **数据处理**：
   - 从请求中提取 ${config.jsonKey} 字段
   - 使用 ${config.encoding} 解码
   - 执行解密/加密操作
   - 将结果替换回请求
5. **错误处理**：添加完善的异常捕获和日志输出
6. **代码注释**：添加中文注释说明关键步骤

## 输出格式
请只输出完整的 ${config.language} 脚本代码，不要包含任何解释或额外文字。

`;
    return prompt;
  }

  /**
   * Call AI API for script generation
   */
  async function callAIForScriptGeneration(prompt, provider, apiKey) {
    let apiUrl, headers, body;

    addAILog(`Initializing ${provider} API call...`, 'info');

    if (provider === 'CLAUDE') {
      // Claude API
      apiUrl = 'https://api.anthropic.com/v1/messages';
      headers = {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      };
      body = {
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 4096,
        messages: [{
          role: 'user',
          content: prompt
        }]
      };
      addAILog(`Model: claude-3-5-sonnet-20241022, Max tokens: 4096`, 'info');
    } else if (provider === 'OPENAI') {
      // OpenAI API
      apiUrl = 'https://api.openai.com/v1/chat/completions';
      headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      };
      body = {
        model: 'gpt-4',
        messages: [{
          role: 'user',
          content: prompt
        }],
        max_tokens: 4096
      };
      addAILog(`Model: gpt-4, Max tokens: 4096`, 'info');
    } else if (provider === 'GLM') {
      // 智谱AI GLM-4 API - 使用代码生成专用端点
      apiUrl = 'https://open.bigmodel.cn/api/coding/paas/v4';
      headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      };
      body = {
        model: 'glm-4',
        messages: [{
          role: 'user',
          content: prompt
        }],
        max_tokens: 4096,
        temperature: 0.3  // 降低随机性以获得更一致的代码
      };
      addAILog(`Model: glm-4, Max tokens: 4096`, 'info');
      addAILog(`Using code generation endpoint`, 'info');
    } else {
      throw new Error(`Unknown AI provider: ${provider}`);
    }

    console.log(`[Galaxy] Calling ${provider} API:`, apiUrl);
    addAILog(`API Endpoint: ${apiUrl}`, 'info');
    addAILog('Sending POST request to AI API...', 'info');

    const startTime = Date.now();
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    });

    const elapsedTime = Date.now() - startTime;
    addAILog(`API response received (${elapsedTime}ms)`, 'info');

    if (!response.ok) {
      const errorText = await response.text();
      addAILog(`API Error (${response.status}): ${response.statusText}`, 'error');
      addAILog(`Error details: ${errorText.substring(0, 200)}`, 'error');

      // 提供特定错误类型的帮助信息
      if (response.status === 401) {
        if (provider === 'GLM') {
          addAILog('智谱 AI 认证失败。请检查:', 'error');
          addAILog('1. API Key 格式应为: id.secret (例如: 1234.abc123...)', 'error');
          addAILog('2. 请在智谱开放平台 (https://open.bigmodel.cn/) 获取 API Key', 'error');
          addAILog('3. 确保没有复制多余的空格或字符', 'error');
        } else if (provider === 'CLAUDE') {
          addAILog('Claude API 认证失败。请检查:', 'error');
          addAILog('1. API Key 应以 sk-ant- 开头', 'error');
          addAILog('2. 请在 https://console.anthropic.com/ 获取 API Key', 'error');
        } else if (provider === 'OPENAI') {
          addAILog('OpenAI API 认证失败。请检查:', 'error');
          addAILog('1. API Key 应以 sk- 开头', 'error');
          addAILog('2. 请在 https://platform.openai.com/api-keys 获取 API Key', 'error');
        }
      }

      throw new Error(`API request failed: ${response.status} ${response.statusText}\n${errorText}`);
    }

    const result = await response.json();
    addAILog('Parsing API response...', 'info');

    // Extract the generated content from different API response formats
    let generatedContent;
    if (provider === 'CLAUDE') {
      generatedContent = result.content[0].text;
      addAILog('Extracted content from Claude response format', 'success');
    } else if (provider === 'OPENAI' || provider === 'GLM') {
      generatedContent = result.choices[0].message.content;
      addAILog(`Extracted content from ${provider} response format`, 'success');
    }

    if (!generatedContent) {
      addAILog('Failed to extract content from API response', 'error');
      throw new Error(`Failed to extract response from ${provider}`);
    }

    return generatedContent;
  }

  /**
   * Copy generated script to clipboard
   */
  function copyScriptToClipboard() {
    const script = generatedScriptTextarea.value;
    if (!script) {
      alert('No script to copy. Generate a script first.');
      return;
    }

    navigator.clipboard.writeText(script).then(() => {
      const originalText = copyScriptBtn.textContent;
      copyScriptBtn.textContent = 'Copied!';
      setTimeout(() => {
        copyScriptBtn.textContent = originalText;
      }, 2000);
    }).catch(err => {
      alert('Failed to copy: ' + err);
    });
  }

  /**
   * Download generated script as a file
   */
  function downloadScriptFile() {
    const script = generatedScriptTextarea.value;
    if (!script) {
      alert('No script to download. Generate a script first.');
      return;
    }

    const language = document.getElementById('script-language').value;
    let filename;

    if (selectedLog) {
      const signature = window.GalaxyGenerator.extractAlgorithmSignature(selectedLog);
      filename = window.GalaxyTemplates.getDefaultFileName(signature, language);
    } else {
      // Fallback filename
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      const ext = language === 'python' ? 'py' : 'js';
      filename = `galaxy-script-${timestamp}.${ext}`;
    }

    // Create blob and download
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
});
