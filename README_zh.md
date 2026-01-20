# Crypto Detective - 加密侦探

## 项目概述

Crypto Detective 是一款专业的 Chrome 浏览器扩展，专为开发者、安全研究员设计。它能够实时拦截和记录前端加密操作，清晰地展示网页上如何以及何时使用加密和哈希算法。通过揭示客户端加密的内部工作机制，它有助于调试、安全分析、理解复杂的 Web 应用程序，以及**使用 Galaxy 脚本生成进行自动化测试**。

## 核心功能

### 实时加密拦截
- **即时检测**: 自动检测并记录正在发生的加密操作
- **性能监控**: 记录每个操作的执行时间
- **堆栈跟踪**: 显示调用位置（最多 5 层）便于调试
- **弱加密检测**: 自动检测并警告弱加密算法

### 广泛的库支持
捕获来自多种流行加密库的操作：

#### 标准 Web Crypto API (`window.crypto.subtle`)
- **加密/解密**: `subtle.encrypt()`, `subtle.decrypt()`
- **签名/验证**: `subtle.sign()`, `subtle.verify()`
- **摘要**: `subtle.digest()`
- **密钥管理**: `generateKey()`, `importKey()`, `exportKey()`, `deriveKey()`, `deriveBits()`

#### CryptoJS
- **对称加密**:
  - AES (CBC, ECB, GCM 模式)
  - DES, TripleDES, Rabbit, RC4
- **哈希算法**: MD5, SHA1, SHA256, SHA3, SHA512, RIPEMD160
- **HMAC**: 所有支持的哈希算法
- **密钥派生**: PBKDF2, EvpKDF

#### Forge.js
- **密码算法**: AES, 3DES, DES
- **哈希算法**: MD5, SHA1, SHA256, SHA384, SHA512
- **PBKDF2**: 密钥派生
- **HMAC**: 带密钥的哈希
- **RSA 操作**: 公钥加密/解密, 私钥签名/验证
- **随机数**: `random.getBytes()`
- **TLS**: 基本跟踪 `createConnection()`

#### JSEncrypt
- **RSA 加密/解密**: 拦截 `encrypt()` 和 `decrypt()` 方法
- **密钥信息**: 自动捕获公钥/私钥 PEM 摘要

#### Libsodium
- **AEAD 加密**: `crypto_aead_xchacha20poly1305_ietf_*`
- **公开密钥加密**: `crypto_box_easy` / `crypto_box_open_easy`
- **Ed25519 签名**: `crypto_sign` / `crypto_sign_open`
- **密钥交换**: `crypto_scalarmult` (ECDH)
- **哈希**: `crypto_generichash` (BLAKE2)
- **密钥派生**: `crypto_pwhash` (Argon2)
- **对称加密**: `crypto_secretbox_easy` / `crypto_secretbox_open_easy`

#### BigInteger.js (jsbn)
- **模幂运算**: `modPow()` - RSA 核心数学运算

### 双界面设计

#### 快速访问弹窗
- **监控切换**: 全局启用/禁用加密拦截
- **实时活动**: 最近操作的快速摘要
- **清除日志**: 删除所有已捕获的日志
- **状态持久化**: 设置在浏览器会话间保存

#### 详细开发者工具面板
- **结构化表格视图**: 所有操作的高级持久化显示
- **实时搜索**: 按任意文本过滤日志
- **库过滤**: 显示/隐藏特定加密库的日志
- **源跟踪**: 查看执行操作的网页来源
- **性能指标**: 查看每个操作的执行时间
- **Galaxy 集成**: 直接从日志条目生成 Galaxy 脚本

### 弱加密检测

自动检测并警告弱加密实践：

#### 算法检测
- **已弃用算法**: DES, TripleDES, RC4
- **已破解算法**: RC4
- **弱哈希**: MD5, SHA1
- **弱 RSA 密钥**: RSA 密钥大小 < 2048 位

#### 密钥派生检测
- **PBKDF2**: 迭代次数 < 100,000
- **EvpKDF**: 迭代次数 < 1,000
- **Argon2**: 低 opslimit 警告

### 智能数据处理

- **Base64 检测**: 自动识别并标记 Base64 编码的数据
- **十六进制显示**: 二进制数据以十六进制格式展示
- **数据截断**: 长数据自动截断并支持展开查看
- **类型转换**: 智能处理不同数据类型（WordArray, ByteBuffer 等）

### Galaxy 脚本生成器

**新增功能**: 高级自动化测试集成！

#### 功能特性
- **内置模板**: 13 种常见加密模式模板，包括：
  - AES-CBC, AES-ECB, AES-GCM
  - DES, 3DES
  - RSA
  - SM2, SM2+SM4, SM4-CBC
  - 动态密钥场景
  - 等等...

- **AI 增强生成**:
  - 结合模板与捕获的加密信息
  - 自定义 AI 提示词用于特殊场景
  - 支持多个 AI 提供商：
    - Claude (Anthropic)
    - GPT-4 (OpenAI)
    - GLM-4 (智谱 AI)
  - API 密钥管理，本地存储

- **多语言支持**:
  - Python (GraalPy)
  - JavaScript (GraalJS)

- **灵活编码**:
  - Base64
  - Hex
  - 原始数据

#### 使用方法
1. 打开开发者工具面板并找到 "Crypto Detective" 标签页
2. 点击任何日志条目上的 "Generate Galaxy Script" 按钮
3. 查看匹配的模板并自定义设置
4. 可选择使用 AI 增强脚本
5. 复制或下载生成的脚本

### 状态管理

- **内存限制**: 最多存储 500 条日志
- **持久化状态**: 监控状态跨会话保存
- **状态广播**: 更改通知所有连接的 UI 组件
- **徽章计数**: 浏览器工具栏显示捕获的日志数量

## 安装说明 (适用于 Chrome/Edge)

要加载和测试此扩展：

1. 在浏览器中导航至 `chrome://extensions`
2. 使用右上角的切换开关启用 **"开发者模式"**
3. 点击 **"加载已解压的扩展程序"** 按钮
4. 选择 `crypto-detective` 目录（包含 `manifest.json` 的根文件夹）
5. "Crypto Detective" 扩展程序现在应该出现在您的扩展列表中

## 使用指南

### 弹窗界面

- **访问**: 点击浏览器工具栏中的 Crypto Detective 图标
- **监控切换**: 使用开关全局启用/禁用加密拦截
- **清除日志**: 点击 "Clear Logs" 删除内存中所有已捕获的日志
- **最近活动**: 查看最近捕获的操作列表
- **可展开详情**: 点击任何日志条目查看完整详情

### 开发者工具面板

1. 打开 Chrome 开发者工具（按 `F12` 或 `Ctrl+Shift+I`）
2. 找到并点击面板工具栏中的 **"Crypto Detective"** 标签页
3. **主要功能**:
   - **实时更新**: 新日志自动出现
   - **搜索栏**: 按任意文本过滤日志（库名、方法、来源等）
   - **库过滤**: 勾选/取消勾选库以显示/隐藏其日志
   - **清除日志**: 删除所有已捕获的日志
   - **Galaxy 生成**: 点击任何行上的 "Generate" 按钮创建 Galaxy 脚本

### Galaxy 脚本生成器

1. 从开发者工具面板中，点击任何日志条目上的 "Generate Galaxy Script"
2. **脚本配置**:
   - **语言**: 选择 Python (GraalPy) 或 JavaScript (GraalJS)
   - **字段名**: 自定义数据字段的变量名
   - **编码**: 选择 Base64、Hex 或原始数据格式
3. **AI 生成**（可选）:
   - 选择 AI 提供商（Claude、GPT-4、GLM-4）
   - 如有需要输入自定义提示词
   - 点击 "Generate with AI"
4. **输出**:
   - 复制脚本到剪贴板
   - 下载为 .py 或 .js 文件
   - 查看警告和 AI 生成日志

## 项目架构

### 文件结构
```
crypto-detective/
├── manifest.json              # Chrome 扩展配置
├── background/                # 后台服务
│   ├── background.js         # 服务入口
│   ├── messageRouter.js      # 消息路由
│   └── stateManager.js       # 状态管理
├── content/                   # 内容脚本
│   ├── content.js            # 内容脚本入口
│   ├── injected.js           # 页面注入脚本（模块）
│   └── hooks/                # 加密库钩子
│       ├── webCryptoHook.js  # Web Crypto API
│       ├── cryptoJsHook.js   # CryptoJS
│       ├── forgeHook.js      # Forge.js
│       ├── jsEncryptHook.js  # JSEncrypt
│       ├── libsodiumHook.js  # Libsodium
│       ├── bigIntegerHook.js # BigInteger.js
│       └── hookUtils.js      # 工具函数
├── popup/                     # 弹出窗口
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── devtools/                  # 开发者工具初始化
│   ├── devtools.html
│   └── devtools.js
├── panel/                     # 开发者工具面板
│   ├── panel.html
│   ├── panel.js
│   ├── panel.css
│   ├── galaxyGenerator.js     # Galaxy 脚本生成器
│   ├── galaxyTemplates.js     # Galaxy 模板
│   ├── aiScriptGenerator.js   # AI 脚本生成器
│   └── templates/             # 加密模板
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
├── icons/                     # 扩展图标
├── test/                      # 测试页面
│   ├── test-galaxy.html
│   └── test-hooks.html
└── README*.md                # 文档
```

## 测试清单

### 安装和基本界面
- [ ] 扩展程序通过 "加载已解压的扩展程序" 成功加载
- [ ] `chrome://extensions` 中没有错误
- [ ] 弹窗界面正确打开
- [ ] 开发者工具面板正确打开

### 状态管理
- [ ] **弹窗切换**:
  - [ ] 切换开关正确启用/禁用拦截
  - [ ] 关闭/重新打开弹窗后状态持久化
  - [ ] 浏览器重启后状态持久化
- [ ] **日志清除**:
  - [ ] 弹窗中的 "Clear Logs" 删除所有日志
  - [ ] 开发者工具中的 "Clear" 删除所有日志
  - [ ] 两个 UI 正确同步

### 开发者工具面板功能
- [ ] **实时更新**: 新日志立即出现
- [ ] **搜索**: 搜索栏正确过滤日志
- [ ] **过滤**: 库复选框正常工作
- [ ] **空状态**: "No operations captured" / "No logs match" 消息正确显示

### 钩子准确性
- [ ] **Web Crypto API**: encrypt/decrypt 操作被捕获
- [ ] **CryptoJS**: AES 和 SHA256 操作被捕获
- [ ] **JSEncrypt**: encrypt/decrypt 操作被捕获
- [ ] **Forge.js**: Cipher 和哈希操作被捕获
- [ ] **Libsodium**: AEAD 和 box 操作被捕获
- [ ] **BigInteger.js**: modPow 操作被捕获
- [ ] **数据准确性**: 算法、方法名称和参数正确显示

### Galaxy 脚本生成
- [ ] **模板匹配**: 为每个操作选择正确的模板
- [ ] **基本生成**: 不使用 AI 生成脚本
- [ ] **AI 集成**:
  - [ ] Claude API 集成正常工作
  - [ ] GPT-4 API 集成正常工作
  - [ ] GLM-4 API 集成正常工作
- [ ] **多语言**: 生成 Python 和 JavaScript 脚本
- [ ] **编码选项**: Base64、Hex 和原始编码正常工作
- [ ] **复制/下载**: 脚本可以复制和下载

### 弱加密检测
- [ ] **算法警告**: DES、RC4、MD5 被检测并警告
- [ ] **RSA 密钥大小**: 小密钥（< 2048 位）被标记
- [ ] **迭代次数**: 低 PBKDF2/EvpKDF 迭代被检测
- [ ] **视觉指示**: 警告在 UI 中突出显示

## 安全考虑

- **敏感数据保护**: 密钥信息在显示时自动脱敏
- **沙箱执行**: 钩子在隔离环境中运行
- **最小权限**: 仅请求必要的扩展权限
- **内存安全**: 日志限制防止内存泄漏
- **本地存储**: API 密钥存储在浏览器本地存储中

## 故障排除

### 扩展程序无法加载
- 验证已启用开发者模式
- 检查 `chrome://extensions` 中的错误
- 确保选择了正确的目录

### 没有日志出现
- 验证弹窗中已启用监控
- 刷新目标网页
- 检查浏览器控制台是否有错误

### Galaxy 生成不工作
- 验证 API 密钥配置正确
- 检查网络连接
- 查看生成日志中的错误

## 贡献

欢迎贡献！请随时提交问题或拉取请求。

## 许可证

请参阅 LICENSE 文件了解详细信息。

## 致谢

本项目旨在帮助开发者和安全研究员理解和调试 Web 应用程序中的加密操作。特别感谢开源社区以及此扩展支持的所有加密库。
