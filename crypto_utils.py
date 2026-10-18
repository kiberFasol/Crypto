"""
crypto_utils.py
Вспомогательные криптографические и математические функции:
- Генерация больших простых чисел (тест Миллера-Рабина).
- Поиск первообразных корней (генераторов).
- Расширенный алгоритм Евклида и модульное обращение.
- Хеширование SHA-256 и форматирование PKCS#1 v1.5 (RFC 8017).
- Стандартные криптографические группы (RFC 3526 / RFC 2409).
"""

import hashlib
import math
import secrets
from typing import List, Optional, Tuple

# Список первых простых чисел для быстрого отсева составных кандидатов
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313
]

# Префикс ASN.1 DER DigestInfo для SHA-256 (RFC 8017, EMSA-PKCS1-v1_5)
# 2.16.840.1.101.3.4.2.1 (id-sha256)
SHA256_ASN1_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Вероятностный тест простоты Миллера-Рабина.
    Вероятность ложного срабатывания для составного числа < 4^(-k) (при k=40 < 10^(-24)).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Быстрый предварительный отсев по малым простым делителям
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # Представление n - 1 = d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Раунды свидетелей
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # 2 <= a <= n - 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """
    Генерирует криптографически стойкое случайное простое число заданной битовой длины.
    """
    if bits < 2:
        raise ValueError("Разрядность простого числа должна быть не менее 2 бит")
    while True:
        # Устанавливаем старший и младший биты (число нечетное и заданной длины)
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate):
            return candidate


def generate_safe_prime(bits: int) -> Tuple[int, int]:
    """
    Генерирует безопасное простое число p = 2q + 1, где q — также простое (число Софи Жермен).
    Возвращает пару (p, q).
    """
    if bits < 4:
        raise ValueError("Разрядность должна быть >= 4")
    q_bits = bits - 1
    while True:
        q = secrets.randbits(q_bits) | (1 << (q_bits - 1)) | 1
        if is_prime_miller_rabin(q, k=25):
            p = 2 * q + 1
            if is_prime_miller_rabin(p, k=30):
                return p, q


def find_primitive_root_safe_prime(p: int, q: int) -> int:
    """
    Находит первообразный корень (генератор) g по модулю безопасного простого p = 2q + 1.
    Делители p - 1 = 2q: {1, 2, q, 2q}.
    Элемент g является генератором, если g^2 != 1 (mod p) и g^q != 1 (mod p).
    """
    for candidate in range(2, p - 1):
        if pow(candidate, 2, p) != 1 and pow(candidate, q, p) != 1:
            return candidate
    raise RuntimeError("Не удалось найти первообразный корень")


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Расширенный алгоритм Евклида.
    Возвращает (gcd, x, y), такие что: a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Вычисляет модульное обратное число a^(-1) mod m.
    Выбрасывает ValueError, если a и m взаимно просты.
    """
    try:
        return pow(a, -1, m)
    except TypeError:
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError(f"Числа {a} и {m} не взаимно просты, обратного элемента не существует")
        return (x % m + m) % m


def sha256_bytes(data: bytes | str) -> bytes:
    """Вычисляет SHA-256 хеш входных данных и возвращает байты."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes | str) -> str:
    """Вычисляет SHA-256 хеш входных данных и возвращает hex-строку."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_int(data: bytes | str) -> int:
    """Вычисляет SHA-256 хеш входных данных и возвращает целое число."""
    return int.from_bytes(sha256_bytes(data), byteorder="big")


def pkcs1_v1_5_encode(message: bytes | str, target_length_bytes: int) -> bytes:
    """
    Выполняет форматирование EMSA-PKCS1-v1_5 для SHA-256 (RFC 8017).
    EM = 0x00 || 0x01 || PS || 0x00 || T,
    где T — ASN.1 DER DigestInfo (SHA-256), PS — байты заполнения 0xFF.
    """
    h = sha256_bytes(message)
    t = SHA256_ASN1_PREFIX + h
    if target_length_bytes < len(t) + 11:
        raise ValueError(
            f"Длина модуля ({target_length_bytes} байт) слишком мала для PKCS#1 v1.5 с SHA-256 (минимум {len(t) + 11} байт)"
        )
    pad_len = target_length_bytes - len(t) - 3
    ps = b"\xff" * pad_len
    em = b"\x00\x01" + ps + b"\x00" + t
    return em


def pkcs1_v1_5_verify_encoded(em: bytes, message: bytes | str) -> bool:
    """
    Проверяет корректность структуры EMSA-PKCS1-v1_5 и совпадение хеша с исходным сообщением.
    """
    h_expected = sha256_bytes(message)
    t_expected = SHA256_ASN1_PREFIX + h_expected

    # em должен начинаться с 0x00 0x01 или если ведущий 0x00 был отброшен при преобразовании в int — с 0x01
    if em.startswith(b"\x00\x01"):
        body = em[2:]
    elif em.startswith(b"\x01"):
        body = em[1:]
    else:
        return False

    # Ищем разделитель 0x00 между PS (байтами 0xFF) и T
    try:
        sep_index = body.index(b"\x00")
    except ValueError:
        return False

    ps = body[:sep_index]
    # PS должен состоять только из 0xFF и быть не короче 8 байт (по RFC 8017)
    if len(ps) < 8 or any(b != 0xFF for b in ps):
        return False

    t = body[sep_index + 1 :]
    return t == t_expected


# Стандартная безопасная 1024-битная группа (RFC 2409, Oakley Group 2 / Diffie-Hellman & ElGamal)
# Позволяет моментально инициализировать криптостойкие параметры Эль-Гамаля без ожидания генерации
OAKLEY_GROUP_2_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)
OAKLEY_GROUP_2_P = int(OAKLEY_GROUP_2_P_HEX, 16)
OAKLEY_GROUP_2_G = 2  # Генератор для Oakley Group 2
