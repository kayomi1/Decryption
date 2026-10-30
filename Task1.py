"""
Запуск:
    python Task1.py novyi_obrii.bmp

"""

import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def aes_ecb(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()
 
 
def aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()

def flip_bit(data: bytes, i: int) -> bytes:
    b = bytearray(data)
    b[i // 8] ^= 1 << (i % 8)    # біт i mod 8 у байті i div 8
    return bytes(b)

def hamming(a: bytes, b: bytes) -> int:
    return bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")
 
def aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()

def aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()

def diff_bytes(a: bytes, b: bytes) -> int:
    return sum(x != y for x, y in zip(a, b))


#BMP
def step1_images(path: str) -> None:
    print("Крок 1: ECB та CTR (зображення)")
    data = open(path, "rb").read()
    offset = int.from_bytes(data[10:14], "little")   # байти 10-13, молодший байт першим
    header, pixels = data[:offset], data[offset:]
    print(f"Розмір файлу: {len(data)} байт, початок пікселів (з заголовка): {offset}")

    key = os.urandom(16)
    nonce = os.urandom(16)

    pad = (-len(pixels)) % 16       # доповнення нулями до кратності 16 (тільки для ECB)
    ecb = aes_ecb(key, pixels + b"\x00" * pad)[: len(pixels)]   # зайві байти відкидаємо
    ctr = aes_ctr(key, nonce, pixels)

    base = os.path.splitext(path)[0]
    open(base + "_ecb.bmp", "wb").write(header + ecb)
    open(base + "_ctr.bmp", "wb").write(header + ctr)
    print(f"Збережено: {base}_ecb.bmp та {base}_ctr.bmp\n")


def step2_avalanche() -> None:
    print("Крок 2: лавинний ефект")
    key = os.urandom(16)
    block = os.urandom(16)
    base_c = aes_ecb(key, block)

    bits = [0, 13, 27, 40, 55, 64, 77, 90, 105, 127]
    total = 0
    print(f"{'№':<3}{'Біт':<8}{'Відстань Геммінга':<20}{'Частка, %'}")
    for n, i in enumerate(bits, 1):
        c = aes_ecb(key, flip_bit(block, i))
        d = hamming(base_c, c)
        total += d
        print(f"{n:<3}{'біт ' + str(i):<8}{d:<20}{d / 128 * 100:.1f}")
    avg = total / len(bits)
    print(f"{'':<3}{'Середнє':<8}{avg:<20.1f}{avg / 128 * 100:.1f}")
    print("(очікувано близько 64 біт, тобто 50 %)\n")


def step3_propagation() -> None:
    print("Крок 3: поширення зміни, CBC і CTR")
    key = os.urandom(16)
    iv = os.urandom(16)
    text = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"

    pos = 5      # змінюємо байт №5 (перший блок), також можна поставити 20 (другий блок)
    results = {}
    for mode in ("CBC", "CTR"):
        if mode == "CBC":
            c = aes_cbc(key, iv, text)
        else:
            c = aes_ctr(key, iv, text)
        bad = bytearray(c)
        bad[pos] ^= 0xFF          # псує один байт шифру
        if mode == "CBC":
            p = aes_cbc_dec(key, iv, bytes(bad))
        else:
            p = aes_ctr(key, iv, bytes(bad))
        results[mode] = diff_bytes(text, p)
        print(f"{mode}: змінено байтів у шифрі = 1, зіпсовано байтів у тексті = {results[mode]}")
    print("(CBC: зіпсувався весь блок 16 байт + 1 байт наступного = 17; CTR: 1)\n")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        return
    path = sys.argv[1]
    step1_images(path)
    step2_avalanche()
    step3_propagation()


if __name__ == "__main__":
    main()


'''
   Запитання: 
   1. Чому на зображенні в режимі ECB видно вихідний малюнок, а в
режимі CTR – ні?

   2. Чому в режимі CTR зміна одного байта шифру псує лише один байт
тексту, а в режимі CBC – більше?

   3. Який режим і чому ви порадили б "Новому обрію" для
резервних копій?


   Відповіді:
   1. В ECB однакові блоки тексту дають однакові блоки шифру. А у CTR гама різна для кожного блоку, тому результат схожий на шум.

   2. У режимі CTR кожен блок шифрується незалежно, тому зміна одного байта шифру впливає лише на відповідний байт тексту. У режимі CBC
кожен блок шифру залежить від попереднього блоку, тому зміна одного байта шифру впливає на весь блок і частково на наступний.

   3. Для резервних копій я б порадив режим CTR, оскільки він забезпечує кращу безпеку та 
стійкість до атак, а також дозволяє паралельне шифрування та дешифрування, що може бути корисним для великих обсягів даних.
'''