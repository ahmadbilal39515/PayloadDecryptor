# decrypt_try.py
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256

def try_base64(s):
    try:
        raw = base64.b64decode(s)
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            text = None
        return {
            "raw_bytes": raw,
            "hex": raw.hex(),
            "utf8_text": text
        }
    except Exception:
        return None

def aes_cbc_decrypt_b64(cipher_b64, key_bytes, iv_bytes):
    try:
        ct = base64.b64decode(cipher_b64)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8', errors='replace')
    except Exception:
        return None

def aes_cbc_decrypt_prefixed_iv_b64(cipher_b64, key_bytes, iv_length=16):
    try:
        data = base64.b64decode(cipher_b64)
        iv = data[:iv_length]
        ct = data[iv_length:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8', errors='replace')
    except Exception:
        return None

def derive_key_pbkdf2(passphrase, salt, length=32, iterations=1000, hash_name='sha1'):
    return PBKDF2(passphrase, salt, dkLen=length, count=iterations)

def key_from_utf8_string(key_str, length=32):
    b = key_str.encode('utf-8')
    if len(b) == length:
        return b
    if len(b) < length:
        return b.ljust(length, b'\0')
    return sha256(b).digest()[:length]

if __name__ == "__main__":
    b64_input = "Aj7Ut07zc6ggQpZPj4uGlR3Vmj5sepFM9mGmObCb9AQ="
    decoded = try_base64(b64_input)
    if decoded:
        print("[*] Base64 Decoded:")
        print("  Raw bytes:", decoded["raw_bytes"])
        print("  Hex:", decoded["hex"])
        print("  UTF-8 text:", decoded["utf8_text"])
    else:
        print("Invalid Base64 input.")

    # Example AES decryption (replace with your actual key/IV)
    # key = key_from_utf8_string("mysecretkey123456")
    # iv = b"\x00" * 16
    # decrypted = aes_cbc_decrypt_b64(b64_input, key, iv)
    # print("[*] AES Decrypted:", decrypted)
