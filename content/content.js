// /content/content.js

// 注入页面上下文的模块脚本，并建立与后台的桥接
(function initContent() {
  // 1) 将 injected.js 以 <script type="module"> 注入到页面上下文
  function injectModuleScript() {
    if (document.getElementById('crypto-detective-injected')) return;
    const script = document.createElement('script');
    script.id = 'crypto-detective-injected';
    script.type = 'module';
    script.src = chrome.runtime.getURL('content/injected.js');
    (document.documentElement || document.head || document).prepend(script);
  }

  // 2) 将页面上下文传来的消息转发给后台
  function forwardOperation(operationData) {
    try {
      chrome.runtime.sendMessage({
        type: 'CRYPTO_OPERATION',
        payload: {
          ...operationData,
          timestamp: new Date().toISOString(),
          origin: window.location.href
        }
      });
    } catch (e) {
      // 忽略
    }
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const message = event.data;
    if (!message || message.source !== 'crypto-detective') return;
    if (message.type === 'CRYPTO_OPERATION' && message.payload) {
      forwardOperation(message.payload);
    }
  });

  // 3) 额外：在内容脚本侧拦截表单提交（无需 MAIN world）
  function detectBase64(str) {
    const base64Regex = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$/;
    return base64Regex.test(str) && str.length % 4 === 0;
  }

  document.addEventListener('submit', function(event) {
    try {
      const form = event.target;
      if (!form || typeof form.querySelectorAll !== 'function') return;
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      passwordInputs.forEach(input => {
        const value = input && typeof input.value === 'string' ? input.value : '';
        if (value && detectBase64(value)) {
          forwardOperation({
            library: 'Custom Encryption',
            method: 'Base64 Encoding',
            data: {
              input: value,
              message: 'Possible Base64 encoded password'
            }
          });
        }
      });
    } catch (e) {
      // 忽略
    }
  }, true);

  injectModuleScript();
})();
