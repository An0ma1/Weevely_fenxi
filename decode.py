import base64
import hashlib
import zlib
import re

password = "dasd"
# 16（随机字符）+ 12（秘钥）+ len(X) + 12（秘钥）+ 16（随机字符）。
body = r"""1d8
aviv8UokN30B1zHEeba66e10fba7SaWzsPEs8nQhP9YZkYkBO6G/q7tcEIK8EbAxzUqulBS0M6gOXEXkk8NtJ8sdDIXccDt0Z+/HJjtLa+p6YNU4DKHy2vVPQXJUwEhAGMdoIBjCcAA5DUoR3pSEQGlWzXiijmfTdYfAJoYB1XLD6AqG+GCdjatOVHu7yx6Nq0C2vNeJUfZG+4Dm57MpFbNR2rIqMcOsEwDTJ1lclvUtiRmpDXacC7v0ulsoYqNNMh1PIOQEGsotDc8xWVqXEcQpPGesIR3ociwOnrrkDnjt4xwD4QEWhrUM1YMAqfaVWHXASFQ2MjTQXd9s1WovtWIGaOOpwFnuDXjxq+36ajzDBwzzipfTHoogrDMDPBcDEBtcAe8OJdn36Pwi1c3UB/lOmIdI9n43rfutJi8yIGqetqa4rSi9Tx43L/DIz9CQHtNtGVec8Q==4dbf9e99c22f
0"""

passwordhash = hashlib.md5(password.encode()).hexdigest().lower()

key = passwordhash[:8]
header = passwordhash[8:20]
footer = passwordhash[20:32]
print(header+"\t"+footer)

safe_kh = re.escape(header)
safe_kf = re.escape(footer)
pattern = f"{safe_kh}(.+?){safe_kf}"

# 执行匹配（支持多行内容）
encode_data = re.search(pattern, body, flags=re.DOTALL).group(1)


def gzuncompress(data: bytes) -> bytes:
    """
    解压由 PHP gzcompress() 或 Python gzcompress() 生成的数据
    :param data: 压缩后的字节流
    :return: 原始字节流
    """
    # 使用 zlib.MAX_WBITS | 32 自动检测头部 (兼容 zlib/gzip 格式)
    try:
        return zlib.decompress(data, wbits=zlib.MAX_WBITS | 32)
    except zlib.error as e:
        # 错误处理：数据可能损坏或格式不匹配
        raise ValueError("解压失败，数据可能损坏或格式错误") from e

def xor(t: bytes, k: bytes) -> bytes:
    """
    PHP x() 函数的 Python 实现
    :param t: 明文/密文字节流（bytes）
    :param k: 密钥字节流（bytes）
    :return: 异或加密/解密后的字节流
    """
    c = len(k)
    l = len(t)
    o = bytearray()
    i = 0
    while i < l:
        j = 0
        while j < c and i < l:
            # 按字节异或（PHP ^ 操作符的等效实现）
            o.append(t[i] ^ k[j])
            j += 1
            i += 1
    return bytes(o)

def fix_base64_padding(encoded_str):
    padding = 4 - (len(encoded_str) % 4)
    return encoded_str + ("=" * padding if padding != 4 else "")


try:
    # Base64解码
    base64_data = fix_base64_padding(encode_data)
    decoded_data = base64.b64decode(base64_data)

    # 异或解密
    xor_data = xor(decoded_data, key.encode())

    # 解压缩
    uncompressed_data = gzuncompress(xor_data)

    # 尝试多种编码方式
    encodings = ['utf-8', 'gbk', 'latin-1']
    for enc in encodings:
        try:
            final = uncompressed_data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        final = uncompressed_data.decode('utf-8', errors='replace')

except Exception as e:
    print(f"解密失败: {str(e)}")
    final = ""
