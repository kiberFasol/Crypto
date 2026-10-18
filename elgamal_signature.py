"""
elgamal_signature.py
Модуль реализации электронной цифровой подписи (ЭЦП) по схеме Эль-Гамаля (ElGamal Digital Signature).

Математические основы:
1. Параметры схемы:
   - Большое простое число p.
   - Первообразный корень (генератор) g группы Z_p*.
2. Ключи:
   - Секретный ключ: x в диапазоне [2, p - 2].
   - Открытый ключ: y = g^x mod p.
3. Формирование подписи для сообщения M:
   - Хеш h = H(M) mod (p - 1).
   - Случайное число k в [2, p - 2], такое что НОД(k, p - 1) = 1 (взаимно простое).
   - r = g^k mod p.
   - s = (h - x * r) * k^(-1) mod (p - 1).
   - Если s = 0, выбирается другое k.
   - Подпись: пара (r, s).
4. Проверка подписи:
   - 0 < r < p и 0 < s < p - 1.
   - v1 = g^h mod p.
   - v2 = (y^r * r^s) mod p.
   - Подпись верна тогда и только тогда, когда v1 == v2 (mod p).
"""

from dataclasses import dataclass
import math
import secrets
from typing import Any, Dict, Optional, Tuple, Union

from crypto_utils import (
    OAKLEY_GROUP_2_G,
    OAKLEY_GROUP_2_P,
    find_primitive_root_safe_prime,
    generate_safe_prime,
    mod_inverse,
    sha256_bytes,
    sha256_hex,
)


@dataclass
class ElGamalParameters:
    """Общие криптографические параметры схемы Эль-Гамаля (p, g)."""
    p: int  # Большое простое число
    g: int  # Первообразный корень по модулю p
    q: Optional[int] = None  # Фактор p - 1 = 2q (для безопасных простых чисел)

    @property
    def bit_length(self) -> int:
        return self.p.bit_length()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "p": self.p,
            "g": self.g,
            "bit_length": self.bit_length,
            "p_hex": hex(self.p),
            "g_hex": hex(self.g),
        }


@dataclass
class ElGamalPublicKey:
    """Открытый ключ схемы Эль-Гамаля (p, g, y)."""
    params: ElGamalParameters
    y: int  # y = g^x mod p

    @property
    def p(self) -> int:
        return self.params.p

    @property
    def g(self) -> int:
        return self.params.g

    @property
    def bit_length(self) -> int:
        return self.params.bit_length

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": "ElGamal",
            "bit_length": self.bit_length,
            "p": self.p,
            "g": self.g,
            "y": self.y,
            "y_hex": hex(self.y),
        }


@dataclass
class ElGamalPrivateKey:
    """Секретный (закрытый) ключ схемы Эль-Гамаля (p, g, x)."""
    params: ElGamalParameters
    x: int  # Случайное число x в [2, p - 2]

    @property
    def p(self) -> int:
        return self.params.p

    @property
    def g(self) -> int:
        return self.params.g

    def get_public_key(self) -> ElGamalPublicKey:
        y = pow(self.g, self.x, self.p)
        return ElGamalPublicKey(params=self.params, y=y)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": "ElGamal",
            "bit_length": self.params.bit_length,
            "p": self.p,
            "g": self.g,
            "x": self.x,
            "x_hex": hex(self.x),
        }


@dataclass
class ElGamalSignature:
    """Электронная подпись схемы Эль-Гамаля: пара (r, s)."""
    r: int
    s: int

    def to_tuple(self) -> Tuple[int, int]:
        return self.r, self.s

    def to_dict(self) -> Dict[str, Any]:
        return {
            "r": self.r,
            "s": self.s,
            "r_hex": hex(self.r),
            "s_hex": hex(self.s),
        }


class ElGamalSigner:
    """
    Класс реализации цифровой подписи по схеме Эль-Гамаля.
    Включает генерацию параметров, генерацию ключей, подписание и верификацию.
    """

    @staticmethod
    def generate_parameters(
        bits: int = 256,
        use_predefined_group: bool = False,
    ) -> ElGamalParameters:
        """
        Генерирует криптографические параметры (p, g) для схемы Эль-Гамаля.
        :param bits: Длина простого числа p в битах (по умолчанию 256 бит для динамической генерации).
        :param use_predefined_group: Использовать ли эталонную группу Oakley Group 2 (1024 бит, RFC 2409).
        :return: ElGamalParameters
        """
        if use_predefined_group:
            # Эталонная криптостойкая 1024-битная группа MODP из RFC 2409
            return ElGamalParameters(p=OAKLEY_GROUP_2_P, g=OAKLEY_GROUP_2_G)

        # Динамическая генерация безопасного простого числа p = 2q + 1 и генератора g
        p, q = generate_safe_prime(bits)
        g = find_primitive_root_safe_prime(p, q)
        return ElGamalParameters(p=p, g=g, q=q)

    @staticmethod
    def generate_keypair(
        params: ElGamalParameters,
    ) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
        """
        Генерирует пару ключей (открытый и закрытый) на основе параметров (p, g).
        :param params: Параметры p, g
        :return: (ElGamalPublicKey, ElGamalPrivateKey)
        """
        p, g = params.p, params.g
        # Закрытый ключ: случайное x, 2 <= x <= p - 2
        x = secrets.randbelow(p - 3) + 2
        # Открытый ключ: y = g^x mod p
        y = pow(g, x, p)

        pub_key = ElGamalPublicKey(params=params, y=y)
        priv_key = ElGamalPrivateKey(params=params, x=x)
        return pub_key, priv_key

    @staticmethod
    def _message_to_hash_int(message: Union[bytes, str], p: int) -> Tuple[int, str]:
        """
        Вычисляет SHA-256 хеш сообщения и проецирует его в диапазон [1, p - 2].
        """
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        else:
            msg_bytes = message

        h_bytes = sha256_bytes(msg_bytes)
        h_hex = h_bytes.hex()
        h_raw_int = int.from_bytes(h_bytes, byteorder="big")

        # Редукция хеша по модулю (p - 1)
        h = h_raw_int % (p - 1)
        if h == 0:
            h = 1  # Защита от нулевого значения хеша в формуле s
        return h, h_hex

    @staticmethod
    def sign(
        message: Union[bytes, str],
        private_key: ElGamalPrivateKey,
    ) -> Tuple[ElGamalSignature, Dict[str, Any]]:
        """
        Формирует цифровую подпись Эль-Гамаля (r, s) для сообщения.
        :param message: Подписываемое сообщение.
        :param private_key: Закрытый ключ автора (p, g, x).
        :return: (ElGamalSignature, диагностические_данные)
        """
        p = private_key.p
        g = private_key.g
        x = private_key.x
        p_minus_1 = p - 1

        # 1. Вычисление хеша сообщения
        h, h_hex = ElGamalSigner._message_to_hash_int(message, p)

        # 2. Выбор случайного сессионного ключа k, взаимно простого с (p - 1)
        k_attempts = 0
        while True:
            k_attempts += 1
            # k выбирается из диапазона [2, p - 2]
            k = secrets.randbelow(p - 3) + 2
            if math.gcd(k, p_minus_1) == 1:
                # 3. Вычисление r = g^k mod p
                r = pow(g, k, p)
                if r == 0:
                    continue

                # 4. Вычисление k^(-1) mod (p - 1)
                try:
                    k_inv = mod_inverse(k, p_minus_1)
                except ValueError:
                    continue

                # 5. Вычисление s = (h - x * r) * k^(-1) mod (p - 1)
                s = ((h - x * r) * k_inv) % p_minus_1
                if s != 0:
                    break

        signature = ElGamalSignature(r=r, s=s)

        diagnostics = {
            "scheme": "ElGamal Digital Signature",
            "sha256_hex": h_hex,
            "hash_h_mod_p_minus_1": h,
            "ephemeral_key_k": k,
            "k_attempts": k_attempts,
            "k_inv_mod_p_minus_1": k_inv,
            "r": r,
            "s": s,
            "r_hex": hex(r),
            "s_hex": hex(s),
            "p_bits": p.bit_length(),
            "private_key_x": x,
        }

        return signature, diagnostics

    @staticmethod
    def verify(
        message: Union[bytes, str],
        signature: ElGamalSignature,
        public_key: ElGamalPublicKey,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Проверяет подлинность цифровой подписи Эль-Гамаля.
        Условие проверки: g^h = (y^r * r^s) mod p.
        :param message: Проверяемое сообщение.
        :param signature: Подпись (r, s).
        :param public_key: Открытый ключ автора (p, g, y).
        :return: (результат_проверки: bool, диагностические_данные)
        """
        p = public_key.p
        g = public_key.g
        y = public_key.y
        r = signature.r
        s = signature.s
        p_minus_1 = p - 1

        # 1. Проверка диапазона компонент подписи: 0 < r < p и 0 < s < p - 1
        if not (0 < r < p):
            return False, {
                "is_valid": False,
                "reason": f"Компонента r ({r}) выходит за пределы диапазона (0, p)",
            }
        if not (0 < s < p_minus_1):
            return False, {
                "is_valid": False,
                "reason": f"Компонента s ({s}) выходит за пределы диапазона (0, p - 1)",
            }

        # 2. Вычисление хеша сообщения
        h, h_hex = ElGamalSigner._message_to_hash_int(message, p)

        # 3. Вычисление левой части равенства: v1 = g^h mod p
        v1 = pow(g, h, p)

        # 4. Вычисление правой части равенства: v2 = (y^r * r^s) mod p
        term1 = pow(y, r, p)
        term2 = pow(r, s, p)
        v2 = (term1 * term2) % p

        # 5. Проверка равенства v1 == v2
        is_valid = (v1 == v2)
        reason = (
            f"Подпись подлинна: v1 (g^h mod p = {v1}) == v2 ((y^r * r^s) mod p = {v2})"
            if is_valid
            else f"Подпись недействительна: v1 ({v1}) != v2 ({v2})"
        )

        diagnostics = {
            "is_valid": is_valid,
            "reason": reason,
            "recomputed_sha256_hex": h_hex,
            "hash_h": h,
            "v1_left_side": v1,
            "v2_right_side": v2,
            "term1_y_pow_r": term1,
            "term2_r_pow_s": term2,
            "r": r,
            "s": s,
            "y": y,
            "p": p,
            "g": g,
        }

        return is_valid, diagnostics
