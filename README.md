English | [中文](README_zh.md)

# Crypto Detective

## Project Overview

Crypto Detective is a professional Chrome extension designed for developers, security researchers, and quality assurance engineers. It intercepts and logs front-end cryptographic operations in real-time, providing clear insight into how and when encryption and hashing are being used on a web page. By revealing the inner workings of client-side crypto, it helps in debugging, security analysis, understanding complex web applications, and **automated testing with Galaxy script generation**.

## Key Features

### Real-time Crypto Interception
- **Instant Detection**: Automatically detects and logs cryptographic operations as they happen
- **Performance Monitoring**: Records execution time for each operation
- **Stack Tracing**: Displays call location (up to 5 levels) for debugging
- **Weak Crypto Detection**: Automatically detects and warns about weak encryption algorithms

### Extensive Library Support
Captures operations from a comprehensive range of popular crypto libraries:

#### Standard Web Crypto API (`window.crypto.subtle`)
- **Encrypt/Decrypt**: `subtle.encrypt()`, `subtle.decrypt()`
- **Sign/Verify**: `subtle.sign()`, `subtle.verify()`
- **Digest**: `subtle.digest()`
- **Key Management**: `generateKey()`, `importKey()`, `exportKey()`, `deriveKey()`, `deriveBits()`

#### CryptoJS
- **Symmetric Encryption**:
  - AES (CBC, ECB, GCM modes)
  - DES, TripleDES, Rabbit, RC4
- **Hash Algorithms**: MD5, SHA1, SHA256, SHA3, SHA512, RIPEMD160
- **HMAC**: All supported hash algorithms
- **Key Derivation**: PBKDF2, EvpKDF

#### Forge.js
- **Ciphers**: AES, 3DES, DES
- **Hashes**: MD5, SHA1, SHA256, SHA384, SHA512
- **PBKDF2**: Key derivation
- **HMAC**: Keyed hashing
- **RSA Operations**: Public key encrypt/decrypt, Private key sign/verify
- **Random**: `random.getBytes()`
- **TLS**: Basic tracking of `createConnection()`

#### JSEncrypt
- **RSA Encryption/Decryption**: Intercepts `encrypt()` and `decrypt()` methods
- **Key Information**: Automatically captures public/private key PEM summaries

#### Libsodium
- **AEAD Encryption**: `crypto_aead_xchacha20poly1305_ietf_*`
- **Public Key Encryption**: `crypto_box_easy` / `crypto_box_open_easy`
- **Ed25519 Signatures**: `crypto_sign` / `crypto_sign_open`
- **Key Exchange**: `crypto_scalarmult` (ECDH)
- **Hash**: `crypto_generichash` (BLAKE2)
- **Key Derivation**: `crypto_pwhash` (Argon2)
- **Symmetric Encryption**: `crypto_secretbox_easy` / `crypto_secretbox_open_easy`

#### BigInteger.js (jsbn)
- **Modular Exponentiation**: `modPow()` - Core RSA mathematical operations

### Dual UI Design

#### Quick-Access Popup
- **Monitoring Toggle**: Enable/disable crypto interception globally
- **Real-time Activity**: Quick summary of recent operations
- **Clear Logs**: Delete all captured logs
- **State Persistence**: Settings saved across browser sessions

#### Detailed DevTools Panel
- **Structured Table View**: Advanced, persistent display of all operations
- **Real-time Search**: Filter logs by any text
- **Library Filtering**: Show/hide logs from specific crypto libraries
- **Source Tracking**: See which webpage origin performed the operation
- **Performance Metrics**: View execution time for each operation
- **Galaxy Integration**: Generate Galaxy scripts directly from log entries

### Weak Cryptography Detection

Automatically detects and warns about weak cryptographic practices:

#### Algorithm Detection
- **Deprecated Algorithms**: DES, TripleDES, RC4
- **Broken Algorithms**: RC4 (compromised)
- **Weak Hashes**: MD5, SHA1
- **Weak RSA Keys**: RSA key size < 2048 bits

#### Key Derivation Detection
- **PBKDF2**: Iteration count < 100,000
- **EvpKDF**: Iteration count < 1,000
- **Argon2**: Low opslimit warnings

### Smart Data Handling

- **Base64 Detection**: Automatically identifies and marks Base64-encoded data
- **Hexadecimal Display**: Binary data shown in hex format
- **Data Truncation**: Long data automatically truncated with expand view
- **Type Conversion**: Intelligently handles different data types (WordArray, ByteBuffer, etc.)

### Galaxy Script Generator

**NEW**: Advanced automated testing integration!

#### Features
- **Built-in Templates**: 13 common encryption mode templates including:
  - AES-CBC, AES-ECB, AES-GCM
  - DES, 3DES
  - RSA
  - SM2, SM2+SM4, SM4-CBC
  - Dynamic key scenarios
  - And more...

- **AI-Enhanced Generation**:
  - Combine templates with captured crypto information
  - Custom AI prompts for specialized scenarios
  - Support for multiple AI providers:
    - Claude (Anthropic)
    - GPT-4 (OpenAI)
    - GLM-4 (Zhipu AI)
  - API key management with local storage

- **Multi-Language Support**:
  - Python (GraalPy)
  - JavaScript (GraalJS)

- **Flexible Encoding**:
  - Base64
  - Hex
  - Raw data

#### Usage
1. Open DevTools Panel and find the "Crypto Detective" tab
2. Click the "Generate Galaxy Script" button on any log entry
3. Review the matched template and customize settings
4. Optionally use AI to enhance the script
5. Copy or download the generated script

### State Management

- **Memory Limit**: Maximum 500 log entries stored
- **Persistent State**: Monitoring state saved across sessions
- **State Broadcasting**: Changes notified to all connected UI components
- **Badge Counter**: Browser toolbar shows captured log count

## Installation Instructions (for Chrome/Edge)

To load and test the extension:

1. Navigate to `chrome://extensions` in your browser
2. Enable **"Developer mode"** using the toggle switch in the top-right corner
3. Click the **"Load unpacked"** button
4. Select the `crypto-detective` directory (root folder containing `manifest.json`)
5. The "Crypto Detective" extension should now appear in your extensions list

## Usage Guide

### Popup UI

- **Access**: Click the Crypto Detective icon in your browser toolbar
- **Monitoring Toggle**: Use the switch to enable/disable crypto interception globally
- **Clear Logs**: Click "Clear Logs" to delete all captured logs from memory
- **Recent Activity**: View a list of the most recently captured operations
- **Expandable Details**: Click on any log entry to see full details

### DevTools Panel

1. Open Chrome DevTools (press `F12` or `Ctrl+Shift+I`)
2. Find and click the **"Crypto Detective"** tab in the panel toolbar
3. **Main Features**:
   - **Real-time Updates**: New logs appear automatically
   - **Search Bar**: Filter logs by any text (library names, methods, origins, etc.)
   - **Library Filters**: Check/uncheck libraries to show/hide their logs
   - **Clear Logs**: Remove all captured logs
   - **Galaxy Generation**: Click the "Generate" button on any row to create a Galaxy script

### Galaxy Script Generator

1. From the DevTools panel, click "Generate Galaxy Script" on any log entry
2. **Script Configuration**:
   - **Language**: Choose Python (GraalPy) or JavaScript (GraalJS)
   - **Field Names**: Customize variable names for data fields
   - **Encoding**: Select Base64, Hex, or Raw data format
3. **AI Generation** (Optional):
   - Select AI provider (Claude, GPT-4, GLM-4)
   - Enter custom prompt if needed
   - Click "Generate with AI"
4. **Output**:
   - Copy script to clipboard
   - Download as .py or .js file
   - Review warnings and AI generation logs

## Architecture

### File Structure
```
crypto-detective/
├── manifest.json              # Chrome extension configuration
├── background/                # Background service
│   ├── background.js         # Service entry point
│   ├── messageRouter.js      # Message routing
│   └── stateManager.js       # State management
├── content/                   # Content scripts
│   ├── content.js            # Content script entry
│   ├── injected.js           # Page-injected script (module)
│   └── hooks/                # Crypto library hooks
│       ├── webCryptoHook.js  # Web Crypto API
│       ├── cryptoJsHook.js   # CryptoJS
│       ├── forgeHook.js      # Forge.js
│       ├── jsEncryptHook.js  # JSEncrypt
│       ├── libsodiumHook.js  # Libsodium
│       ├── bigIntegerHook.js # BigInteger.js
│       └── hookUtils.js      # Utility functions
├── popup/                     # Popup window
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── devtools/                  # DevTools initialization
│   ├── devtools.html
│   └── devtools.js
├── panel/                     # DevTools panel
│   ├── panel.html
│   ├── panel.js
│   ├── panel.css
│   ├── galaxyGenerator.js     # Galaxy script generator
│   ├── galaxyTemplates.js     # Galaxy templates
│   ├── aiScriptGenerator.js   # AI script generator
│   └── templates/             # Encryption templates
│       ├── aes_cbc.py
│       ├── aes_ecb.py
│       ├── aes_gcm.py
│       ├── aes_rsa.py
│       ├── des.py
│       ├── des3.py
│       ├── dynamic_key.py
│       ├── rsa.py
│       ├── sm2.py
│       ├── sm2_sm4.py
│       └── sm4_cbc.py
├── icons/                     # Extension icons
├── test/                      # Test pages
│   ├── test-galaxy.html
│   └── test-hooks.html
└── README*.md                # Documentation
```

## Testing Checklist

### Installation & Basic UI
- [ ] Extension loads successfully via "Load unpacked"
- [ ] No errors in `chrome://extensions`
- [ ] Popup UI opens correctly
- [ ] DevTools panel opens correctly

### State Management
- [ ] **Popup Toggle**:
  - [ ] Toggle correctly enables/disables interception
  - [ ] State persists after closing/reopening popup
  - [ ] State persists after browser restart
- [ ] **Log Clearing**:
  - [ ] "Clear Logs" in popup removes all logs
  - [ ] "Clear" in DevTools removes all logs
  - [ ] Both UIs sync correctly

### DevTools Panel Functionality
- [ ] **Real-time Updates**: New logs appear immediately
- [ ] **Search**: Search bar filters logs correctly
- [ ] **Filtering**: Library checkboxes work properly
- [ ] **Empty States**: "No operations captured" / "No logs match" messages appear

### Hooking Accuracy
- [ ] **Web Crypto API**: encrypt/decrypt operations captured
- [ ] **CryptoJS**: AES and SHA256 operations captured
- [ ] **JSEncrypt**: encrypt/decrypt operations captured
- [ ] **Forge.js**: Cipher and hash operations captured
- [ ] **Libsodium**: AEAD and box operations captured
- [ ] **BigInteger.js**: modPow operations captured
- [ ] **Data Accuracy**: Algorithm, method name, and parameters displayed correctly

### Galaxy Script Generation
- [ ] **Template Matching**: Correct template selected for each operation
- [ ] **Basic Generation**: Scripts generated without AI
- [ ] **AI Integration**:
  - [ ] Claude API integration works
  - [ ] GPT-4 API integration works
  - [ ] GLM-4 API integration works
- [ ] **Multi-language**: Both Python and JavaScript scripts generated
- [ ] **Encoding Options**: Base64, Hex, and Raw encoding work correctly
- [ ] **Download/Download**: Scripts can be copied and downloaded

### Weak Crypto Detection
- [ ] **Algorithm Warnings**: DES, RC4, MD5 detected and warned
- [ ] **RSA Key Size**: Small keys (< 2048 bits) flagged
- [ ] **Iteration Count**: Low PBKDF2/EvpKDF iterations detected
- [ ] **Visual Indicators**: Warnings displayed prominently in UI

## Security Considerations

- **Sensitive Data Protection**: Key information is automatically masked in display
- **Sandbox Execution**: Hooks run in isolated environment
- **Minimal Permissions**: Only requests necessary extension permissions
- **Memory Safety**: Log limit prevents memory leaks
- **Local Storage**: API keys stored locally in browser storage

## Troubleshooting

### Extension Not Loading
- Verify Developer Mode is enabled
- Check for errors in `chrome://extensions`
- Ensure you selected the correct directory

### No Logs Appearing
- Verify monitoring is enabled in popup
- Refresh the target webpage
- Check browser console for errors

### Galaxy Generation Not Working
- Verify API keys are correctly configured
- Check network connection
- Review AI generation logs for errors

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

Please refer to the LICENSE file for details.

## Acknowledgments

This project was created to assist developers and security researchers in understanding and debugging cryptographic operations in web applications. Special thanks to the open-source community for all the cryptographic libraries that this extension supports.
