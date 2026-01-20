// /panel/galaxyTemplates.js

/**
 * Galaxy Script Templates
 * Provides template generators for various encryption algorithms
 */

/**
 * Python (GraalPy) template for AES algorithms
 */
function generatePythonAES(config) {
  const { algorithm, key, iv, jsonKey, encoding } = config;

  const paramMap = iv ? `paramMap = {"iv": "${iv}"}` : 'paramMap = None';

  let encodingFunc = 'CodeUtil.b64decode';
  let decodingFunc = 'CodeUtil.b64encodeToString';

  if (encoding === 'hex') {
    encodingFunc = 'CodeUtil.hexToBytes';
    decodingFunc = 'CodeUtil.bytesToHex';
  }

  return `import json
from java.org.m2sec.core.utils import (
    CodeUtil,
    CryptoUtil,
)
from java.org.m2sec.core.models import Request, Response
from java.lang import Byte

"""
Auto-generated Galaxy script for Crypto-Detective
Algorithm: ${algorithm}
Generated: ${new Date().toISOString()}
"""

ALGORITHM = "${algorithm}"
secret = b"${key || 'YOUR_KEY_HERE'}"
${iv ? `iv = "${iv}"` : ''}
${paramMap}
jsonKey = "${jsonKey}"
log = None


def hook_request_to_burp(request: Request) -> Request:
    """HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(request.content)
    # 调用函数解密
    data: bytes = decrypt(encryptedData)
    # 更新body为已解密的数据
    request.content = data
    return request


def hook_request_to_server(request: Request) -> Request:
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = request.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    request.content = body
    return request


def hook_response_to_burp(response: Response) -> Response:
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用函数解密
    data: bytes = decrypt(encryptedData)
    # 更新body
    response.content = data
    return response


def hook_response_to_client(response: Response) -> Response:
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = response.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data)
    # 更新body
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    response.content = body
    return response


def decrypt(content: bytes) -> bytes:
    return CryptoUtil.aesDecrypt(ALGORITHM, content, secret, paramMap)


def encrypt(content: bytes) -> bytes:
    return CryptoUtil.aesEncrypt(ALGORITHM, content, secret, paramMap)


def get_data(content: bytes) -> bytes:
    return ${encodingFunc}(json.loads(convert_bytes(content)).get(jsonKey))


def to_data(content: bytes) -> bytes:
    jsonBody: dict = {}
    jsonBody[jsonKey] = ${decodingFunc}(content)
    return json.dumps(jsonBody).encode()


def set_log(log1):
    """程序在最开始会自动调用该函数，在上方函数可以放心使用log对象"""
    global log
    log = log1
    import sys
    log.info("python version: {}", sys.version)


def convert_bytes(java_byte_array):
    """将java的字节数组转为graalpy的字节数组, java的字节数组对应到graalpy中的类型是foreign对象, 如果想要用graalpy处理java的字节数组，最好先调用该函数"""
    return bytes([Byte.toUnsignedInt(b) for b in java_byte_array])
`;
}

/**
 * Python (GraalPy) template for RSA algorithms
 */
function generatePythonRSA(config) {
  const { algorithm, key, jsonKey, encoding } = config;

  let encodingFunc = 'CodeUtil.b64decode';
  let decodingFunc = 'CodeUtil.b64encodeToString';

  if (encoding === 'hex') {
    encodingFunc = 'CodeUtil.hexToBytes';
    decodingFunc = 'CodeUtil.bytesToHex';
  }

  return `import json
from java.org.m2sec.core.utils import (
    CodeUtil,
    CryptoUtil,
)
from java.org.m2sec.core.models import Request, Response
from java.lang import Byte

"""
Auto-generated Galaxy script for Crypto-Detective
Algorithm: ${algorithm}
Generated: ${new Date().toISOString()}
"""

ALGORITHM = "${algorithm}"
${key ? `publicKey = CodeUtil.b64decode("${key}")` : '# publicKey = CodeUtil.b64decode("YOUR_PUBLIC_KEY_HERE")'}
${key ? `privateKey = CodeUtil.b64decode("${key}")` : '# privateKey = CodeUtil.b64decode("YOUR_PRIVATE_KEY_HERE")'}
jsonKey = "${jsonKey}"
log = None


def hook_request_to_burp(request: Request) -> Request:
    """HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(request.content)
    # 调用内置函数解密
    data: bytes = decrypt(encryptedData, privateKey)
    # 更新body为已解密的数据
    request.content = data
    return request


def hook_request_to_server(request: Request) -> Request:
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = request.content
    # 调用内置函数加密回去
    encryptedData: bytes = encrypt(data, publicKey)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    request.content = body
    return request


def hook_response_to_burp(response: Response) -> Response:
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用内置函数解密
    data: bytes = decrypt(encryptedData, privateKey)
    # 更新body
    response.content = data
    return response


def hook_response_to_client(response: Response) -> Response:
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = response.content
    # 调用内置函数加密回去
    encryptedData: bytes = encrypt(data, publicKey)
    # 更新body
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    response.content = body
    return response


def decrypt(content: bytes, secret: bytes) -> bytes:
    return CryptoUtil.rsaDecrypt(ALGORITHM, content, secret)


def encrypt(content: bytes, secret: bytes) -> bytes:
    return CryptoUtil.rsaEncrypt(ALGORITHM, content, secret)


def get_data(content: bytes) -> bytes:
    return ${encodingFunc}(json.loads(convert_bytes(content))[jsonKey])


def to_data(content: bytes) -> bytes:
    jsonBody = {}
    jsonBody[jsonKey] = ${decodingFunc}(content)
    return json.dumps(jsonBody).encode()


def convert_bytes(java_byte_array: bytes) -> bytes:
    """将java的字节数组转为graalpy的字节数组, java的字节数组对应到graalpy中的类型是foreign对象, 如果想要用graalpy处理java的字节数组，最好先调用该函数"""
    return bytes([Byte.toUnsignedInt(b) for b in java_byte_array])


def set_log(log1):
    """程序在最开始会自动调用该函数，在上方函数可以放心使用log对象"""
    global log
    log = log1
    import sys
    log.info("python version: {}", sys.version)
`;
}

/**
 * Python (GraalPy) template for SM4 algorithm
 */
function generatePythonSM4(config) {
  const { algorithm, key, iv, jsonKey, encoding } = config;

  const paramMap = iv ? `paramMap = {"iv": "${iv}"}` : 'paramMap = None';

  let encodingFunc = 'CodeUtil.b64decode';
  let decodingFunc = 'CodeUtil.b64encodeToString';

  if (encoding === 'hex') {
    encodingFunc = 'CodeUtil.hexToBytes';
    decodingFunc = 'CodeUtil.bytesToHex';
  }

  return `import json
from java.org.m2sec.core.utils import (
    CodeUtil,
    CryptoUtil,
)
from java.org.m2sec.core.models import Request, Response
from java.lang import Byte

"""
Auto-generated Galaxy script for Crypto-Detective
Algorithm: ${algorithm} (SM4 国密算法)
Generated: ${new Date().toISOString()}
"""

ALGORITHM = "${algorithm}"
secret = b"${key || 'YOUR_SM4_KEY_HERE'}"
${iv ? `iv = "${iv}"` : ''}
${paramMap}
jsonKey = "${jsonKey}"
log = None


def hook_request_to_burp(request: Request) -> Request:
    """HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(request.content)
    # 调用函数解密
    data: bytes = decrypt(encryptedData)
    # 更新body为已解密的数据
    request.content = data
    return request


def hook_request_to_server(request: Request) -> Request:
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = request.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    request.content = body
    return request


def hook_response_to_burp(response: Response) -> Response:
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用函数解密
    data: bytes = decrypt(encryptedData)
    # 更新body
    response.content = data
    return response


def hook_response_to_client(response: Response) -> Response:
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = response.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data)
    # 更新body
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    response.content = body
    return response


def decrypt(content: bytes) -> bytes:
    return CryptoUtil.sm4Decrypt(ALGORITHM, content, secret, paramMap)


def encrypt(content: bytes) -> bytes:
    return CryptoUtil.sm4Encrypt(ALGORITHM, content, secret, paramMap)


def get_data(content: bytes) -> bytes:
    return ${encodingFunc}(json.loads(convert_bytes(content)).get(jsonKey))


def to_data(content: bytes) -> bytes:
    jsonBody: dict = {}
    jsonBody[jsonKey] = ${decodingFunc}(content)
    return json.dumps(jsonBody).encode()


def set_log(log1):
    """程序在最开始会自动调用该函数，在上方函数可以放心使用log对象"""
    global log
    log = log1
    import sys
    log.info("python version: {}", sys.version)


def convert_bytes(java_byte_array):
    """将java的字节数组转为graalpy的字节数组"""
    return bytes([Byte.toUnsignedInt(b) for b in java_byte_array])
`;
}

/**
 * Python (GraalPy) template for SM2 algorithm
 */
function generatePythonSM2(config) {
  const { algorithm, key, jsonKey, encoding } = config;

  const SM2_MODE = "c1c2c3";  // Default SM2 mode

  let encodingFunc = 'CodeUtil.b64decode';
  let decodingFunc = 'CodeUtil.b64encodeToString';

  if (encoding === 'hex') {
    encodingFunc = 'CodeUtil.hexToBytes';
    decodingFunc = 'CodeUtil.bytesToHex';
  }

  return `import json
from java.org.m2sec.core.utils import (
    CodeUtil,
    CryptoUtil,
)
from java.org.m2sec.core.models import Request, Response
from java.lang import Byte

"""
Auto-generated Galaxy script for Crypto-Detective
Algorithm: ${algorithm} (SM2 国密算法)
Generated: ${new Date().toISOString()}
"""

ALGORITHM = "SM2"
SM2_MODE = "${SM2_MODE}"
${key ? `publicKey = CodeUtil.b64decode("${key}")` : '# publicKey = CodeUtil.b64decode("YOUR_SM2_PUBLIC_KEY_HERE")'}
${key ? `privateKey = CodeUtil.b64decode("${key}")` : '# privateKey = CodeUtil.b64decode("YOUR_SM2_PRIVATE_KEY_HERE")'}
jsonKey = "${jsonKey}"
log = None


def hook_request_to_burp(request: Request) -> Request:
    """HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(request.content)
    # 调用内置函数解密
    data: bytes = decrypt(encryptedData, privateKey)
    # 更新body为已解密的数据
    request.content = data
    return request


def hook_request_to_server(request: Request) -> Request:
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = request.content
    # 调用内置函数加密回去
    encryptedData: bytes = encrypt(data, publicKey)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    request.content = body
    return request


def hook_response_to_burp(response: Response) -> Response:
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用内置函数解密
    data: bytes = decrypt(encryptedData, privateKey)
    # 更新body
    response.content = data
    return response


def hook_response_to_client(response: Response) -> Response:
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = response.content
    # 调用内置函数加密回去
    encryptedData: bytes = encrypt(data, publicKey)
    # 更新body
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    response.content = body
    return response


def decrypt(content: bytes, secret: bytes) -> bytes:
    return CryptoUtil.sm2Decrypt(SM2_MODE, content, secret)


def encrypt(content: bytes, secret: bytes) -> bytes:
    return CryptoUtil.sm2Encrypt(SM2_MODE, content, secret)


def get_data(content: bytes) -> bytes:
    return ${encodingFunc}(json.loads(convert_bytes(content))[jsonKey])


def to_data(content: bytes) -> bytes:
    jsonBody = {}
    jsonBody[jsonKey] = ${decodingFunc}(content)
    return json.dumps(jsonBody).encode()


def convert_bytes(java_byte_array: bytes) -> bytes:
    """将java的字节数组转为graalpy的字节数组"""
    return bytes([Byte.toUnsignedInt(b) for b in java_byte_array])


def set_log(log1):
    """程序在最开始会自动调用该函数，在上方函数可以放心使用log对象"""
    global log
    log = log1
    import sys
    log.info("python version: {}", sys.version)
`;
}

/**
 * Python (GraalPy) template for Hybrid Encryption (RSA + AES)
 */
function generatePythonHybrid(config, patterns) {
  const { jsonKey, encoding } = config;

  // Find RSA and AES patterns
  const rsaPattern = patterns.find(p => p.cipher === 'RSA');
  const aesPattern = patterns.find(p => p.cipher === 'AES');

  const rsaKey = rsaPattern?.key || 'YOUR_RSA_PRIVATE_KEY_HERE';
  const aesKey = aesPattern?.key || 'YOUR_AES_KEY_HERE';
  const aesMode = aesPattern?.mode || 'CBC';
  const aesIV = aesPattern?.iv;

  return `import json
from java.org.m2sec.core.utils import (
    CodeUtil,
    CryptoUtil,
)
from java.org.m2sec.core.models import Request, Response
from java.lang import Byte, ThreadLocal

"""
Auto-generated Galaxy script for Crypto-Detective
Algorithm: Hybrid (RSA + AES${aesMode})
Generated: ${new Date().toISOString()}
This script handles hybrid encryption where:
- RSA is used to encrypt the AES key
- AES is used to encrypt the actual data
"""

SYMMETRIC_ALGORITHM = "AES/${aesMode}/PKCS5Padding"
aesSecret = ThreadLocal()
aesSecret.set(b"${aesKey}")
ASYMMETRIC_ALGORITHM = "RSA/ECB/PKCS1Padding"
${rsaKey ? `publicKey = CodeUtil.b64decode("${rsaKey}")` : '# publicKey = CodeUtil.b64decode("YOUR_RSA_PUBLIC_KEY_HERE")'}
${rsaKey ? `privateKey = CodeUtil.b64decode("${rsaKey}")` : '# privateKey = CodeUtil.b64decode("YOUR_RSA_PRIVATE_KEY_HERE")'}
jsonKey1 = "data"
jsonKey2 = "key"
log = None


def hook_request_to_burp(request: Request) -> Request:
    """HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(request.content)
    # 获取用来解密的密钥，该密钥已使用publicKey进行rsa加密
    encryptedKey: bytes = get_key(request.content)
    # 调用内置函数解密，拿到aes密钥
    key: bytes = asymmetric_decrypt(encryptedKey, privateKey)
    aesSecret.set(key)
    # 调用内置函数解密报文
    data: bytes = symmetric_decrypt(encryptedData, key)
    # 更新body为已解密的数据
    request.content = data
    return request


def hook_request_to_server(request: Request) -> Request:
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。

    Args:
        request (Request): 请求对象

    Returns:
        Request: 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = request.content
    # 调用内置函数加密回去，这里使用设置的aesSecret进行加密
    encryptedData: bytes = symmetric_encrypt(data, aesSecret.get())
    # 调用内置函数加密aesSecret
    encryptedKey: bytes = asymmetric_encrypt(aesSecret.get(), publicKey)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData, encryptedKey)
    # 更新body
    request.content = body
    return request


def hook_response_to_burp(response: Response) -> Response:
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用内置函数解密
    data: bytes = symmetric_decrypt(encryptedData, aesSecret.get())
    # 更新body
    response.content = data
    return response


def hook_response_to_client(response: Response) -> Response:
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。

    Args:
        response (Response): 响应对象

    Returns:
        Response: 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
    """
    # 获取被解密的数据
    data: bytes = response.content
    # 调用内置函数加密回去
    encryptedData: bytes = symmetric_encrypt(data, aesSecret.get())
    # 更新body
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData, None)
    # 更新body
    response.content = body
    return response


def asymmetric_decrypt(content: bytes, secret: bytes) -> bytes:
    return CryptoUtil.rsaDecrypt(ASYMMETRIC_ALGORITHM, content, secret)


def asymmetric_encrypt(content: bytes, secret: bytes) -> bytes:
    return CryptoUtil.rsaEncrypt(ASYMMETRIC_ALGORITHM, content, secret)


def symmetric_decrypt(content: bytes, secret: bytes) -> bytes:
    ${aesIV ? `paramMap = {"iv": "${aesIV}"}` : 'paramMap = None'}
    return CryptoUtil.aesDecrypt(SYMMETRIC_ALGORITHM, content, secret, paramMap)


def symmetric_encrypt(content: bytes, secret: bytes) -> bytes:
    ${aesIV ? `paramMap = {"iv": "${aesIV}"}` : 'paramMap = None'}
    return CryptoUtil.aesEncrypt(SYMMETRIC_ALGORITHM, content, secret, paramMap)


def get_data(content: bytes) -> bytes:
    return CodeUtil.b64decode(json.loads(convert_bytes(content))[jsonKey1])


def get_key(content: bytes) -> bytes:
    return CodeUtil.b64decode(json.loads(convert_bytes(content))[jsonKey2])


def to_data(content: bytes, secret: bytes) -> bytes:
    jsonBody = {}
    jsonBody[jsonKey1] = CodeUtil.b64encodeToString(content)
    if secret is not None:
        jsonBody[jsonKey2] = CodeUtil.b64encodeToString(secret)
    return json.dumps(jsonBody).encode()


def convert_bytes(java_byte_array: bytes) -> bytes:
    """将java的字节数组转为graalpy的字节数组"""
    return bytes([Byte.toUnsignedInt(b) for b in java_byte_array])


def set_log(log1):
    """程序在最开始会自动调用该函数，在上方函数可以放心使用log对象"""
    global log
    log = log1
    import sys
    log.info("python version: {}", sys.version)
`;
}

/**
 * JavaScript (GraalJS) template for AES algorithms
 */
function generateJavaScriptAES(config) {
  const { algorithm, key, iv, jsonKey, encoding } = config;

  const paramMap = iv ? `var paramMap = {"iv": "${iv}"};` : 'var paramMap = null;';

  return `var CodeUtil = Java.type("org.m2sec.core.utils.CodeUtil")
var CryptoUtil = Java.type("org.m2sec.core.utils.CryptoUtil")
var JsonUtil = Java.type("org.m2sec.core.utils.JsonUtil")
var Request = Java.type("org.m2sec.core.models.Request")
var Response = Java.type("org.m2sec.core.models.Response")

/**
 * Auto-generated Galaxy script for Crypto-Detective
 * Algorithm: ${algorithm}
 * Generated: ${new Date().toISOString()}
 */

ALGORITHM = "${algorithm}"
secret = stringToByteArray("${key || 'YOUR_KEY_HERE'}")
${iv ? `iv = "${iv}"` : ''}
${paramMap}
jsonKey = "${jsonKey}"
log = void 0


/**
 * HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。
 * @param {Request} request 请求对象
 * @returns 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_request_to_burp(request) {
    // 获取需要解密的数据
    encryptedData = get_data(request.getContent())
    // 调用函数解密
    data = decrypt(encryptedData)
    // 更新body为已解密的数据
    request.setContent(data)
    return request
}


/**
 * HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。
 * @param {Request} request 请求对象
 * @returns 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_request_to_server(request) {
    // 获取被解密的数据
    data = request.getContent()
    // 调用函数加密回去
    encryptedData = encrypt(data)
    // 将已加密的数据转换为Server可识别的格式
    body = to_data(encryptedData)
    // 更新body
    request.setContent(body)
    return request
}


/**
 * HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。
 * @param {Response} response 响应对象
 * @returns 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_response_to_burp(response) {
    // 获取需要解密的数据
    encryptedData = get_data(response.getContent())
    // 调用函数解密
    data = decrypt(encryptedData)
    // 更新body
    response.setContent(data)
    return response
}


/**
 * HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。
 * @param {Response} response 响应对象
 * @returns 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_response_to_client(response) {
    data = response.getContent()
    // 调用函数加密回去
    encryptedData = encrypt(data)
    // 更新body
    // 将已加密的数据转换为Server可识别的格式
    body = to_data(encryptedData)
    // 更新body
    response.setContent(body)
    return response
}


function decrypt(content) {
    return CryptoUtil.aesDecrypt(ALGORITHM, content, secret, paramMap)
}


function encrypt(content) {
    return CryptoUtil.aesEncrypt(ALGORITHM, content, secret, paramMap)
}


function get_data(content) {
    return CodeUtil.b64decode(JsonUtil.jsonStrToMap(byteArrayToString(content)).get(jsonKey))
}


function to_data(content) {
    jsonBody = {}
    jsonBody[jsonKey] = CodeUtil.b64encodeToString(content)
    return stringToByteArray(JsonUtil.toJsonStr(jsonBody))
}


/**
 * 程序在最开始会自动调用该函数，在上方函数可以放心使用log对象
 */
function set_log(log1) {
    log = log1
}


/**
 * 字符串转字节数组
 */
function stringToByteArray(str) {
    let byteArray = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        byteArray[i] = str.charCodeAt(i);
    }
    return byteArray;
}


/**
 * 字节数组转字符串
 */
function byteArrayToString(byteArray) {
    return String.fromCharCode.apply(null, byteArray);
}
`;
}

/**
 * Main template generator function
 */
function generateGalaxyScript(pattern, config, allPatterns = []) {
  const { language, jsonKey, encoding } = config;
  const scriptConfig = {
    algorithm: pattern.algorithm,
    key: pattern.key,
    iv: pattern.iv,
    jsonKey: jsonKey,
    encoding: encoding
  };

  const cipher = pattern.cipher?.toUpperCase();

  // Check for hybrid encryption (RSA + AES)
  const hasRSA = allPatterns.some(p => p.cipher === 'RSA');
  const hasAES = allPatterns.some(p => p.cipher === 'AES');
  const isHybrid = hasRSA && hasAES && allPatterns.length > 1;

  if (language === 'javascript') {
    if (cipher === 'AES') {
      return generateJavaScriptAES(scriptConfig);
    }
    // Add more JavaScript templates as needed
    return generateJavaScriptAES(scriptConfig);
  } else {
    // Python (default)
    if (isHybrid) {
      return generatePythonHybrid(scriptConfig, allPatterns);
    } else if (cipher === 'AES') {
      return generatePythonAES(scriptConfig);
    } else if (cipher === 'RSA') {
      return generatePythonRSA(scriptConfig);
    } else if (cipher === 'SM2') {
      return generatePythonSM2(scriptConfig);
    } else if (cipher === 'SM4') {
      return generatePythonSM4(scriptConfig);
    } else if (cipher === 'DES') {
      return generatePythonAES(scriptConfig); // DES uses same template structure
    }
    // Default to AES template
    return generatePythonAES(scriptConfig);
  }
}

/**
 * Get file extension based on language
 */
function getFileExtension(language) {
  return language === 'javascript' ? '.js' : '.py';
}

/**
 * Get default filename for the script
 */
function getDefaultFileName(pattern, language) {
  const cipher = pattern.cipher || 'crypto';
  const mode = pattern.mode || '';
  const timestamp = new Date().toISOString().slice(0, 10);
  const ext = getFileExtension(language);

  return `${cipher.toLowerCase()}${mode ? '_' + mode.toLowerCase() : ''}_${timestamp}${ext}`;
}

// Export functions for use in panel.js
window.GalaxyTemplates = {
  generateGalaxyScript,
  getFileExtension,
  getDefaultFileName
};
