#   python src/run_experiments.py <ключ в hex>

import csv
import os
import sys

import matplotlib.pyplot as plt
import numpy as np

from ciphers import ctr_encrypt
from cryptopic import encrypt_image, decrypt_image, load_image, bytes_to_image, sha256_file, sha256_pixels
from metrics import entropy, chi2, correlation, repeated_blocks, npcr_uaci

images = ["gradient", "checkerboard", "noise_texture", "my_pic"]
methods = ["xor", "aes-ecb", "aes-ctr"]
titles = {"original": "Исходное", "xor": "Потоковый XOR", "aes-ecb": "AES-ECB", "aes-ctr": "AES-CTR"}
main_image = "checkerboard"


def save_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def image_path(name, method):
    if method == "original":
        return f"imgs/{name}.png"
    return f"imgs/{name}_{method}.png"


def draw_histograms(name, out_path):
    fig, ax = plt.subplots(2, 4, figsize=(16, 7.5))
    for i, m in enumerate(["original"] + methods):
        img = load_image(image_path(name, m))
        ax[0, i].imshow(img)
        ax[0, i].set_title(titles[m])
        ax[0, i].axis("off")
        ax[1, i].hist(img.ravel(), bins=256, range=(0, 256))
        ax[1, i].set_title(f"H = {entropy(img):.4f} бит")
        ax[1, i].set_xlabel("значение байта")
    fig.suptitle(f"{name}.png: гистограммы (каналы R, G, B вместе)")
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def draw_three(pics, names, title, out_path):
    fig, ax = plt.subplots(1, 3, figsize=(12, 4.5))
    for i in range(3):
        ax[i].imshow(pics[i])
        ax[i].set_title(names[i])
        ax[i].axis("off")
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if len(sys.argv) > 1:
    key = bytes.fromhex(sys.argv[1])
else:
    key = os.urandom(16)
print("ключ K1:", key.hex())

os.makedirs("results", exist_ok=True)
if os.path.exists("results/meta.json"):
    os.remove("results/meta.json")

# 1) шифрую, расшифровываю и сравниваю sha256 исходника и восстановленного
print("\nПроверка обратимости:")
rows = []
for name in images:
    for m in methods:
        src = image_path(name, "original")
        enc = image_path(name, m)
        dec = f"imgs/{name}_{m}_restored.png"
        encrypt_image(m, key, src, enc)
        decrypt_image(key, enc, dec)
        same_pixels = sha256_pixels(src) == sha256_pixels(dec)
        same_file = sha256_file(src) == sha256_file(dec)
        print(f"{name:14} {m:8} пиксели: {same_pixels}  файл: {same_file}")
        rows.append([name, m, sha256_pixels(src), sha256_pixels(dec), same_pixels, same_file])
save_csv("results/reversibility.csv",
         ["image", "method", "sha256_original", "sha256_restored", "pixels_match", "file_match"], rows)

# 2) метрики для исходника и трёх шифротекстов
print("\nМетрики (энтропия, chi2, corr H, corr V, повторы блоков %):")
rows = []
for name in images:
    for m in ["original"] + methods:
        img = load_image(image_path(name, m))
        row = [name, m,
               round(entropy(img), 4),
               round(chi2(img), 1),
               round(correlation(img, "h"), 4),
               round(correlation(img, "v"), 4),
               round(repeated_blocks(img) * 100, 2)]
        print(*row)
        rows.append(row)
save_csv("results/metrics.csv", ["image", "method", "entropy", "chi2", "corr_h", "corr_v", "repeated_blocks_%"], rows)

# 3) гистограммы
draw_histograms(main_image, "results/histograms.png")
draw_histograms("my_pic", "results/histograms_my_pic.png")

# 4) меняю один бит ключа и сравниваю шифротексты AES-CTR
key2 = bytearray(key)
key2[0] ^= 1
key2 = bytes(key2)
print("\nключ K2:", key2.hex())

img = load_image(image_path(main_image, "original"))
nonce = os.urandom(8)
c1 = bytes_to_image(ctr_encrypt(img.tobytes(), key, nonce), img.shape)
c2 = bytes_to_image(ctr_encrypt(img.tobytes(), key2, nonce), img.shape)
npcr, uaci = npcr_uaci(c1, c2)
print(f"NPCR = {npcr:.4f} %, UACI = {uaci:.4f} %  (идеал 99.6094 % и 33.4635 %)")
save_csv("results/key_sensitivity.csv", ["image", "method", "npcr_%", "uaci_%"],
         [[main_image, "aes-ctr", round(npcr, 4), round(uaci, 4)]])
diff = np.abs(c1.astype(int) - c2.astype(int)).astype(np.uint8)
draw_three([c1, c2, diff], ["C1 (ключ K1)", "C2 (ключ K2)", "|C1 - C2|"],
           f"AES-CTR, {main_image}.png: NPCR = {npcr:.2f} %, UACI = {uaci:.2f} %",
           "results/key_sensitivity.png")

# 5) что будет, если в CTR два раза взять один nonce с тем же ключом
p1 = load_image("imgs/gradient.png")
p2 = load_image("imgs/checkerboard.png")
nonce = os.urandom(8)
c1 = bytes_to_image(ctr_encrypt(p1.tobytes(), key, nonce), p1.shape)
c2 = bytes_to_image(ctr_encrypt(p2.tobytes(), key, nonce), p2.shape)
draw_three([c1, c2, c1 ^ c2], ["CTR(gradient)", "CTR(checkerboard), тот же nonce", "C1 XOR C2 = P1 XOR P2"],
           "Повтор nonce в CTR", "results/nonce_reuse.png")

print("\nрезультаты в imgs/ и results/")
