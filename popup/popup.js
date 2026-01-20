// /popup/popup.js

document.addEventListener('DOMContentLoaded', () => {
    const monitoringToggle = document.getElementById('monitoring-toggle');
    const clearLogsBtn = document.getElementById('clear-logs-btn');
    const logsContainer = document.getElementById('logs-container');
    const noLogsMessage = document.getElementById('no-logs-message');

    /**
     * Sanitizes a string for safe insertion into HTML.
     * @param {string} str The string to escape.
     * @returns {string} The escaped string.
     */
    function escapeHtml(str) {
        if (typeof str !== 'string') return '';
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // 简单 JSON 语法高亮 + 行号/标点着色
    function highlightJson(obj) {
        try {
            let json = JSON.stringify(obj, null, 2);
            if (!json) return '';
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

            // 高亮键（冒号前的字符串）
            json = json.replace(/("(?:\\u[\da-fA-F]{4}|\\.|[^\\"])*")(\s*:\s*)/g, '<span class="hl-key">$1</span>$2');

            // 高亮字符串值（冒号后的字符串）
            json = json.replace(/(:\s*)("(?:\\u[\da-fA-F]{4}|\\.|[^\\"])*")/g, '$1<span class="hl-string">$2</span>');

            // 高亮数字/布尔/null（仅匹配冒号后紧接的标量）
            json = json.replace(/(:\s*)(-?\d+(?:\.\d+)?|true|false|null)/g, (m, p1, p2) => {
                if (p2 === 'true' || p2 === 'false') return p1 + '<span class="hl-boolean">' + p2 + '</span>';
                if (p2 === 'null') return p1 + '<span class="hl-null">null</span>';
                return p1 + '<span class="hl-number">' + p2 + '</span>';
            });

            // 标点/结构符号
            json = json.replace(/([{}\[\],])/g, '<span class="hl-punc">$1</span>');

            // 行号包装
            const lines = json.split('\n');
            return lines.map((line, i) => `\n<span class="code-line"><span class="line-no">${i + 1}</span><span class="line-text">${line || ' '}</span></span>`).join('');
        } catch (e) {
            return escapeHtml(String(obj));
        }
    }

    /**
     * Truncate a long string for UI display.
     */
    function truncate(str, maxLen = 256) {
        if (typeof str !== 'string') return '';
        return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
    }

    /**
     * Extract plaintext/ciphertext summary from a log entry across libraries.
     * Returns { plaintext, ciphertext } when available.
     */
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

        // Heuristic fallback
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
            ciphertext: typeof ciphertext === 'string' ? ciphertext : null
        };
    }

    /**
     * Checks if the logs container is empty and shows or hides the "no logs" message.
     */
    function checkIfEmpty() {
        // The container always has the no-logs-message div, so check for other elements.
        const logEntries = logsContainer.getElementsByClassName('log-entry');
        noLogsMessage.style.display = logEntries.length === 0 ? 'block' : 'none';
    }

    /**
     * Creates and prepends a new log entry element to the container.
     * @param {object} log - The log object from the background script.
     */
    function buildSummaryHtml(plaintext, ciphertext) {
        const MAX_LEN = 256;
        const hasPlainMore = typeof plaintext === 'string' && plaintext.length > MAX_LEN;
        const hasCipherMore = typeof ciphertext === 'string' && ciphertext.length > MAX_LEN;

        const plainTrunc = hasPlainMore ? truncate(plaintext, MAX_LEN) : plaintext || '';
        const cipherTrunc = hasCipherMore ? truncate(ciphertext, MAX_LEN) : ciphertext || '';

        const plainBlock = plaintext ? `
            <div class="summary-item">
                <strong>明文:</strong>
                <span class="summary-text truncated">${escapeHtml(plainTrunc)}</span>
                ${hasPlainMore ? `<span class="summary-text full" style="display:none">${escapeHtml(plaintext)}</span>` : ''}
                ${hasPlainMore ? `<a href="#" class="toggle-more" data-target="plain" data-expanded="false">显示更多</a>` : ''}
            </div>
        ` : '';

        const cipherBlock = ciphertext ? `
            <div class="summary-item">
                <strong>密文:</strong>
                <span class="summary-text truncated">${escapeHtml(cipherTrunc)}</span>
                ${hasCipherMore ? `<span class="summary-text full" style="display:none">${escapeHtml(ciphertext)}</span>` : ''}
                ${hasCipherMore ? `<a href="#" class="toggle-more" data-target="cipher" data-expanded="false">显示更多</a>` : ''}
            </div>
        ` : '';

        const hasAny = !!(plaintext || ciphertext);
        return hasAny ? `<div class="log-summary">${plainBlock}${cipherBlock}</div>` : '';
    }

    function addLogEntry(log) {
        const logEntryDiv = document.createElement('div');
        logEntryDiv.className = 'log-entry';

        const safeLibrary = escapeHtml(log.library || 'Unknown');
        const safeMethod = escapeHtml(log.method || 'Unknown');
        const safeTimestamp = escapeHtml(new Date(log.timestamp).toLocaleTimeString());
        const highlightedData = highlightJson(log.data);

        const { plaintext, ciphertext } = extractPlainCipher(log);
        const summaryHtml = buildSummaryHtml(plaintext, ciphertext);

        logEntryDiv.innerHTML = `
            <div class="log-header">
                <div>
                    <span class="library">${safeLibrary}</span>
                    <span class="method">${safeMethod}</span>
                </div>
                <span class="timestamp">${safeTimestamp}</span>
            </div>
            ${summaryHtml}
            <pre class="log-data"><code>${highlightedData}</code></pre>
        `;
        logsContainer.prepend(logEntryDiv);
        checkIfEmpty();
    }

    // 交互：展开/收起 明文/密文
    logsContainer.addEventListener('click', (e) => {
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
                // 收起
                full.style.display = 'none';
                if (truncated) truncated.style.display = '';
                target.textContent = '显示更多';
                target.setAttribute('data-expanded', 'false');
            } else {
                // 展开
                if (truncated) truncated.style.display = 'none';
                full.style.display = '';
                target.textContent = '显示更少';
                target.setAttribute('data-expanded', 'true');
            }
        }
    });

    // --- Initialize Popup ---

    // 1. Establish a long-lived connection with the background script.
    // This is more efficient than using one-off messages for frequent UI updates.
    const port = chrome.runtime.connect({ name: 'crypto-detective-ui' });

    // 2. Listen for real-time updates from the background script.
    port.onMessage.addListener((message) => {
        if (!message || !message.type) return;

        switch (message.type) {
            case 'NEW_LOG':
                addLogEntry(message.payload);
                break;
            case 'LOGS_CLEARED':
                // Remove only log entries, not the placeholder message.
                logsContainer.querySelectorAll('.log-entry').forEach(el => el.remove());
                checkIfEmpty();
                break;
            case 'MONITORING_STATUS_CHANGED':
                monitoringToggle.checked = message.payload.isEnabled;
                break;
        }
    });

    // 3. Send a one-time message to get the initial state when the popup opens.
    chrome.runtime.sendMessage({ type: 'GET_INITIAL_DATA' }, (response) => {
        if (chrome.runtime.lastError) {
            console.error("Crypto Detective: " + chrome.runtime.lastError.message);
            noLogsMessage.textContent = "Error loading data. Try reopening the popup or reloading the extension.";
            return;
        }
        // Set the initial state of the toggle switch
        monitoringToggle.checked = response.status;

        // Clear any existing logs and populate with the initial list
        logsContainer.querySelectorAll('.log-entry').forEach(el => el.remove());
        if (response.logs && response.logs.length > 0) {
            response.logs.forEach(addLogEntry);
        }
        checkIfEmpty();
    });

    // 4. Set up event listeners for user controls.
    monitoringToggle.addEventListener('change', () => {
        chrome.runtime.sendMessage({
            type: 'TOGGLE_MONITORING',
            isEnabled: monitoringToggle.checked
        });
    });

    clearLogsBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'CLEAR_LOGS' });
    });
});
