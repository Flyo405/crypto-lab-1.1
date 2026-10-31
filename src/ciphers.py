import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# XOR на xorshift32

def xorshift32(seed, n):
    x = seed
    out = bytearray()
    while len(out) < n:
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        out += x.to_bytes(4, "little")
    return bytes(out[:n])


def xor_encrypt(data, key):
    seed = int.from_bytes(hashlib.sha256(key).digest()[:4], "little")
    if seed == 0:
        seed = 1
    stream = xorshift32(seed, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


xor_decrypt = xor_encrypt


# AES

def ecb_encrypt(data, key):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))


def ecb_decrypt(data, key):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data), 16)


def ctr_encrypt(data, key, nonce):
    return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(data)

ctr_decrypt = ctr_encrypt
