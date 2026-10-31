# CryptoPic - шифрование изображений

## Алгоритмы

- xor - свой потоковый шифр: cipher[i] = plain[i] XOR keystream[i], ключевой поток из генератора xorshift32 (seed = первые 4 байта SHA-256 от ключа).
- aes-ecb - AES-128-ECB с дополнением PKCS#7 (pycryptodome).
- aes-ctr - AES-128-CTR, для каждого шифрования новый случайный nonce (8 байт).

Шифруются байты пикселей (RGB), результат сохраняется как PNG того же размера.

## Зависимости

Python 3.10+:

    pip install pycryptodome numpy pillow matplotlib

## Файлы

- src/ciphers.py - xorshift32, XOR, AES-ECB, AES-CTR
- src/cryptopic.py - шифрование/расшифрование картинок из командной строки
- src/metrics.py - энтропия, chi2, корреляция, повторы блоков, NPCR/UACI
- src/run_experiments.py - весь эксперимент сразу
- imgs/ - исходные, зашифрованные (\*_xor, \*_aes-ecb, \*_aes-ctr) и восстановленные (\*_restored) картинки
- results/ - metrics.csv, histograms.png, meta.json и т.д.

## Параметры

- -k - ключ, 32 hex-символа (128 бит). Нигде не сохраняется.
- -m - метод: xor, aes-ecb или aes-ctr.
- -i, -o - входной и выходной файл.

Параметры шифрования пишутся в results/meta.json (ключ - имя файла шифротекста): алгоритм, исходный файл, размер, nonce для CTR, tail (последний блок после padding) для ECB.

Все команды запускаются из папки проекта.

## Сгенерировать ключ

    python src/cryptopic.py genkey

## Пример шифрования

    python src/cryptopic.py encrypt -m aes-ctr -k 00112233445566778899aabbccddeeff -i imgs/my_pic.png -o imgs/my_pic_enc.png

## Пример расшифрования

    python src/cryptopic.py decrypt -k 00112233445566778899aabbccddeeff -i imgs/my_pic_enc.png -o imgs/my_pic_dec.png

## Проверить, что картинки совпадают (SHA-256)

    python src/cryptopic.py verify -i imgs/my_pic.png -o imgs/my_pic_dec.png

## Весь эксперимент

    python src/run_experiments.py f2ee2f94d8785c7b720e9272f1c96ca0

Если ключ не указать, будет случайный. Nonce каждый раз новый, поэтому числа для AES-CTR при повторном запуске немного меняются.
