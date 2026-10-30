"""
Запуск: python Task2.py
"""

import hashlib
import os


def gamma(key: bytes, nonce: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        block = key + nonce + counter.to_bytes(8, "big")
        out += hashlib.sha256(block).digest()   # 32 байти гами за крок
        counter += 1
    return out[:length]


def xor(data: bytes, g: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, g))


def encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return xor(plaintext, gamma(key, nonce, len(plaintext)))


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return xor(ciphertext, gamma(key, nonce, len(ciphertext)))


def main() -> None:
    key = os.urandom(32)
    nonce1 = os.urandom(16)
    nonce2 = os.urandom(16)

    text = "Привіт, це тестове повідомлення".encode("utf-8")

    # шифрування і розшифрування
    c1 = encrypt(key, nonce1, text)
    print("Шифр №1:", c1.hex())
    print("Розшифровано:", decrypt(key, nonce1, c1).decode("utf-8"))
    print("Розшифрування повертає вихідний текст:", decrypt(key, nonce1, c1) == text)
    print()

    # Той самий текст тричі (два рази з однаковим nonce, один раз з іншим)
    c2 = encrypt(key, nonce1, text)   # однакове nonce
    c3 = encrypt(key, nonce2, text)   # інше nonce
    print("Шифр №2 (те саме nonce):", c2.hex())
    print("Шифр №3 (інше nonce):   ", c3.hex())
    print("№1 == №2:", c1 == c2)
    print("№1 == №3:", c1 == c3)
    print()

    print("--- Перевірка за додатком Б ---")
    kb = bytes.fromhex("000102030405060708090A0B0C0D0E0F"
                       "101112131415161718191A1B1C1D1E1F")
    nb = bytes.fromhex("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF")
    msg = bytes.fromhex("D09FD180D0B8D0B2D196D182")  # "Привіт"
    print("Перші 12 байтів гами:", gamma(kb, nb, 12).hex(), "(очікувано 1cb37d298013f96066812720)")
    print("Шифр:", encrypt(kb, nb, msg).hex(), "(очікувано cc2cac a950ab29d2b717f6a2)")
    nb2 = bytes.fromhex("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF")
    print("Шифр з nonce B0..BF:", encrypt(kb, nb2, msg).hex(), "(очікувано 6be8cc214a81f758e9ef21db)")


if __name__ == "__main__":
    main()

'''
  Запитання:
  1. Чому одноразове число роблять різним для кожного повідомлення,
хоча воно не таємне?

  2. Яку роль у стандартних режимах AES виконують вектор ініціалізації
й початкове значення лічильника і чим вона схожа на роль одноразового числа?

  Відповіді:
  1. Одноразове число роблять різним для кожного повідомлення, щоб забезпечити унікальність гами для кожного шифрування. Якщо nonce
повторюється, то однакові блоки відкритого тексту будуть шифруватися однаково, що може призвести до витоку інформації та зменшення безпеки шифрування.

  2. Вектор ініціалізації та початкове значення лічильника у стандартних режимах AES виконують схожу роль, як і одноразове число, забезпечуючи унікальність
шифрування для кожного повідомлення.
'''