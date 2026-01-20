// /content/injected.js (runs in page context as an ES module)

import { initWebCryptoHooks } from './hooks/webCryptoHook.js';
import { initCryptoJsHooks } from './hooks/cryptoJsHook.js';
import { initJsEncryptHooks } from './hooks/jsEncryptHook.js';
import { initForgeHooks } from './hooks/forgeHook.js';
import { initBigIntegerHooks } from './hooks/bigIntegerHook.js';
import { initLibsodiumHooks } from './hooks/libsodiumHook.js';

function postOperation(operationData) {
  try {
    window.postMessage({
      source: 'crypto-detective',
      type: 'CRYPTO_OPERATION',
      payload: operationData
    }, '*');
  } catch {
    // ignore
  }
}

function main() {
  // 1) WebCrypto 通常始终存在，尽早挂钩一次即可
  try { initWebCryptoHooks(postOperation); } catch {}

  // 2) 对异步出现的全局库增加监听与轮询
  const hookState = {
    cryptojs: false,
    jsencrypt: false,
    forge: false,
    biginteger: false,
    libsodium: false,
  };

  function tryHookCryptoJS() {
    if (!hookState.cryptojs && typeof window.CryptoJS !== 'undefined') {
      try { initCryptoJsHooks(postOperation); hookState.cryptojs = true; } catch {}
    }
  }
  function tryHookJSEncrypt() {
    if (!hookState.jsencrypt && typeof window.JSEncrypt !== 'undefined' && window.JSEncrypt?.prototype) {
      try { initJsEncryptHooks(postOperation); hookState.jsencrypt = true; } catch {}
    }
  }
  function tryHookForge() {
    if (!hookState.forge && typeof window.forge !== 'undefined') {
      try { initForgeHooks(postOperation); hookState.forge = true; } catch {}
    }
  }
  function tryHookBigInteger() {
    if (!hookState.biginteger && typeof window.BigInteger !== 'undefined' && window.BigInteger?.prototype) {
      try { initBigIntegerHooks(postOperation); hookState.biginteger = true; } catch {}
    }
  }
  function tryHookLibsodium() {
    if (!hookState.libsodium && (typeof window.sodium !== 'undefined' || typeof window._sodium !== 'undefined')) {
      try { initLibsodiumHooks(postOperation); hookState.libsodium = true; } catch {}
    }
  }

  function watchGlobalProperty(name, onAvailable) {
    try {
      if (window[name] !== undefined) {
        onAvailable(window[name]);
        return;
      }
      let current;
      Object.defineProperty(window, name, {
        configurable: true,
        enumerable: true,
        get() { return current; },
        set(v) {
          current = v;
          // 恢复为普通数据属性，避免持续 getter/setter 开销
          try {
            Object.defineProperty(window, name, { value: v, writable: true, enumerable: true, configurable: true });
          } catch {}
          try { onAvailable(v); } catch {}
        }
      });
    } catch {
      // Fallback to polling if defineProperty fails
    }
  }

  // 先尝试一次
  tryHookCryptoJS();
  tryHookJSEncrypt();
  tryHookForge();
  tryHookBigInteger();
  tryHookLibsodium();

  // 使用 defineProperty 监听赋值
  watchGlobalProperty('CryptoJS', tryHookCryptoJS);
  watchGlobalProperty('JSEncrypt', tryHookJSEncrypt);
  watchGlobalProperty('forge', tryHookForge);
  watchGlobalProperty('BigInteger', tryHookBigInteger);
  watchGlobalProperty('sodium', tryHookLibsodium);
  watchGlobalProperty('_sodium', tryHookLibsodium);

  // 轮询兜底（捕获库后续子模块加载等场景）
  const intervalId = setInterval(() => {
    tryHookCryptoJS();
    tryHookJSEncrypt();
    tryHookForge();
    tryHookBigInteger();
    tryHookLibsodium();

    if (hookState.cryptojs && hookState.jsencrypt && hookState.forge && hookState.biginteger && hookState.libsodium) {
      clearInterval(intervalId);
    }
  }, 500);

  // 最长观察时间，避免常驻
  setTimeout(() => { try { clearInterval(intervalId); } catch {} }, 30000);
}

// Run as early as possible
main();

