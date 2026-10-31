#   python src/cryptopic.py encrypt -m aes-ctr -k <ключ> -i imgs/my_pic.png -o imgs/enc.png
#   python src/cryptopic.py decrypt -k <ключ> -i imgs/enc.png -o imgs/dec.png

import argparse
import hashlib
import json
import os

import numpy as np
from PIL import Image

from ciphers import xor_encrypt, xor_decrypt, ecb_encrypt, ecb_decrypt, ctr_encrypt, ctr_decrypt

META = "results/meta.json"


def load_image(path):
    return np.array(Image.open(path).convert("RGB"))


def save_image(arr, path):
    Image.fromarray(arr).save(path)


def bytes_to_image(data, shape):
    return np.frombuffer(data, dtype=np.uint8).reshape(shape)


def read_meta():
    if not os.path.exists(META):
        return {}
    with open(META, encoding="utf-8") as f:
        return json.load(f)


def write_meta(meta):
    with open(META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def encrypt_image(method, key, in_path, out_path):
    img = load_image(in_path)
    data = img.tobytes()
    info = {"algorithm": method, "source": os.path.basename(in_path), "shape": list(img.shape)}

    if method == "xor":
        enc = xor_encrypt(data, key)
    elif method == "aes-ecb":
        enc = ecb_encrypt(data, key)
        info["tail"] = enc[len(data):].hex()
        enc = enc[:len(data)]
    elif method == "aes-ctr":
        nonce = os.urandom(8)
        enc = ctr_encrypt(data, key, nonce)
        info["nonce"] = nonce.hex()
    else:
        raise ValueError("неизвестный метод " + method)

    save_image(bytes_to_image(enc, img.shape), out_path)

    meta = read_meta()
    meta[os.path.basename(out_path)] = info
    write_meta(meta)


def decrypt_image(key, in_path, out_path):
    info = read_meta()[os.path.basename(in_path)]
    data = load_image(in_path).tobytes()
    method = info["algorithm"]

    if method == "xor":
        dec = xor_decrypt(data, key)
    elif method == "aes-ecb":
        dec = ecb_decrypt(data + bytes.fromhex(info["tail"]), key)
    elif method == "aes-ctr":
        dec = ctr_decrypt(data, key, bytes.fromhex(info["nonce"]))

    save_image(bytes_to_image(dec, info["shape"]), out_path)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def sha256_pixels(path):
    return hashlib.sha256(load_image(path).tobytes()).hexdigest()


def get_key(s):
    key = bytes.fromhex(s)
    if len(key) != 16:
        raise SystemExit("ключ должен быть 32 hex-символа (16 байт)")
    return key


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["genkey", "encrypt", "decrypt", "verify"])
    parser.add_argument("-m", "--method", choices=["xor", "aes-ecb", "aes-ctr"])
    parser.add_argument("-k", "--key")
    parser.add_argument("-i", "--input")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    if args.command == "genkey":
        print(os.urandom(16).hex())
    elif args.command == "encrypt":
        encrypt_image(args.method, get_key(args.key), args.input, args.output)
        print("готово:", args.output)
    elif args.command == "decrypt":
        decrypt_image(get_key(args.key), args.input, args.output)
        print("готово:", args.output)
    elif args.command == "verify":
        print("пиксели совпадают:", sha256_pixels(args.input) == sha256_pixels(args.output))
        print("файлы совпадают:  ", sha256_file(args.input) == sha256_file(args.output))
