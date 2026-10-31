import numpy as np


def entropy(img):
    counts = np.bincount(img.ravel(), minlength=256)
    p = counts / counts.sum()
    p = p[p > 0]
    return -np.sum(p * np.log2(p))


def chi2(img):
    counts = np.bincount(img.ravel(), minlength=256)
    expected = img.size / 256
    return np.sum((counts - expected) ** 2 / expected)


def correlation(img, direction, n=10000):
    h, w, _ = img.shape
    np.random.seed(0)
    y = np.random.randint(0, h - 1, n)
    x = np.random.randint(0, w - 1, n)
    a = img[y, x]
    if direction == "h":
        b = img[y, x + 1]
    else:
        b = img[y + 1, x]
    return np.corrcoef(a.ravel(), b.ravel())[0, 1]


def repeated_blocks(img):
    data = img.tobytes()
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    return 1 - len(set(blocks)) / len(blocks)


def npcr_uaci(c1, c2):
    c1 = c1.astype(int)
    c2 = c2.astype(int)
    npcr = np.mean(c1 != c2) * 100
    uaci = np.mean(np.abs(c1 - c2) / 255) * 100
    return npcr, uaci
