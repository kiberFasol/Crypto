"""
rsa_signature.py
Модуль реализации электронной цифровой подписи (ЭЦП) на основе криптосистемы RSA.

Реализует:
- Генерацию ключей (модуль n, открытая экспонента e, секретная экспонента d).
- Хеширование сообщений алгоритмом SHA-256.
- Подписание закрытым ключом: s = m^d mod n (с поддержкой стандарта EMSA-PKCS1-v1_5).
- Верификацию подписи открытым ключом: m' = s^e mod n и сверку с хешем документа.
- Интеграцию со стандартной библиотекой `cryptography` для сравнения.
"""

from dataclasses import dataclass
import math
from typing import Any, Dict, Optional, Tuple, Union

from crypto_utils import (
    generate_prime,
    mod_inverse,
    pkcs1_v1_5_encode,
    pkcs1_v1_5_verify_encoded,
    sha256_bytes,
    sha256_hex,
    sha256_int,
)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    HAS_CRYPTOGRAPHY_LIB = True
except ImportError:
    HAS_CRYPTOGRAPHY_LIB = False


@dataclass
class RSAPublicKey:
    """Открытый ключ RSA (n, e)."""
    n: int  # Модуль n = p * q
    e: int  # Открытая экспонента (обычно 65537)

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    @property
    def byte_length(self) -> int:
        return (self.bit_length + 7) // 8

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": "RSA",
            "bit_length": self.bit_length,
            "n": self.n,
            "e": self.e,
            "n_hex": hex(self.n),
            "e_hex": hex(self.e),
        }


@dataclass
class RSAPrivateKey:
    """Закрытый (секретный) ключ RSA (n, d) с сохранением параметров p, q."""
    n: int  # Модуль n
    d: int  # Секретная экспонента d = e^(-1) mod phi(n)
    e: int  # Открытая экспонента e
    p: Optional[int] = None  # Первое простое число
    q: Optional[int] = None  # Второе простое число

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    @property
    def byte_length(self) -> int:
        return (self.bit_length + 7) // 8

    def get_public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": "RSA",
            "bit_length": self.bit_length,
            "n": self.n,
            "d": self.d,
            "e": self.e,
            "p": self.p,
            "q": self.q,
        }


class RSASigner:
    """
    Класс реализации цифровой подписи RSA.
    Поддерживает:
    - Чистый математический режим (учебный): s = H(M)^d mod n.
    - Стандартный режим PKCS#1 v1.5 (RFC 8017): s = (00 || 01 || PS || 00 || T)^d mod n.
    """

    @staticmethod
    def generate_keypair(bits: int = 1024, e: int = 65537) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        """
        Генерирует пару ключей RSA заданной битовой длины.
        :param bits: Общая битовая длина модуля n (по умолчанию 1024 бит).
        :param e: Открытая экспонента (по умолчанию 65537 - простое число Ферма F4).
        :return: (RSAPublicKey, RSAPrivateKey)
        """
        if bits < 512:
            raise ValueError("Для безопасной подписи длина модуля должна быть не менее 512 бит")

        prime_bits = bits // 2
        while True:
            p = generate_prime(prime_bits)
            q = generate_prime(bits - prime_bits)
            if p == q:
                continue

            n = p * q
            # Функция Эйлера phi(n) = (p - 1) * (q - 1)
            phi = (p - 1) * (q - 1)

            # Проверяем взаимную простоту e и phi(n)
            if math.gcd(e, phi) == 1:
                try:
                    d = mod_inverse(e, phi)
                    break
                except ValueError:
                    continue

        pub_key = RSAPublicKey(n=n, e=e)
        priv_key = RSAPrivateKey(n=n, d=d, e=e, p=p, q=q)
        return pub_key, priv_key

    @staticmethod
    def sign(
        message: Union[bytes, str],
        private_key: RSAPrivateKey,
        use_padding: bool = True,
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Создает цифровую подпись RSA для сообщения.
        :param message: Исходное сообщение (строка или байты).
        :param private_key: Закрытый ключ RSA.
        :param use_padding: Использовать ли дополнение PKCS#1 v1.5 (рекомендуется).
        :return: (подпись_число, диагностические_данные)
        """
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        else:
            msg_bytes = message

        msg_hash_bytes = sha256_bytes(msg_bytes)
        msg_hash_hex = msg_hash_bytes.hex()
        msg_hash_int = int.from_bytes(msg_hash_bytes, byteorder="big")

        mod_len_bytes = private_key.byte_length

        if use_padding:
            # Формирование блока по стандарту EMSA-PKCS1-v1_5
            encoded_block = pkcs1_v1_5_encode(msg_bytes, mod_len_bytes)
            m_int = int.from_bytes(encoded_block, byteorder="big")
        else:
            # Прямое использование хеша по модулю n (учебный режим)
            m_int = msg_hash_int % private_key.n
            encoded_block = m_int.to_bytes(mod_len_bytes, byteorder="big")

        # Вычисление подписи: s = m^d mod n
        signature_int = pow(m_int, private_key.d, private_key.n)

        diagnostics = {
            "scheme": "RSA-SHA256 (PKCS#1 v1.5)" if use_padding else "RSA-SHA256 (Raw Textbook)",
            "message_length_bytes": len(msg_bytes),
            "sha256_hex": msg_hash_hex,
            "sha256_int": msg_hash_int,
            "padded_block_hex": encoded_block.hex(),
            "padded_block_int": m_int,
            "private_exponent_d": private_key.d,
            "modulus_n": private_key.n,
            "signature_int": signature_int,
            "signature_hex": hex(signature_int),
            "signature_bytes_len": (signature_int.bit_length() + 7) // 8,
        }

        return signature_int, diagnostics

    @staticmethod
    def verify(
        message: Union[bytes, str],
        signature: int,
        public_key: RSAPublicKey,
        use_padding: bool = True,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Проверяет подлинность цифровой подписи RSA.
        :param message: Исходное сообщение.
        :param signature: Значение подписи (целое число).
        :param public_key: Открытый ключ автора.
        :param use_padding: Использовалось ли дополнение PKCS#1 v1.5.
        :return: (результат_проверки: bool, диагностические_данные)
        """
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        else:
            msg_bytes = message

        msg_hash_bytes = sha256_bytes(msg_bytes)
        msg_hash_hex = msg_hash_bytes.hex()
        msg_hash_int = int.from_bytes(msg_hash_bytes, byteorder="big")

        # Проверка диапазона подписи: 0 <= s < n
        if not (0 <= signature < public_key.n):
            return False, {
                "is_valid": False,
                "reason": "Значение подписи выходит за границы допустимого диапазона [0, n - 1]",
                "sha256_hex": msg_hash_hex,
            }

        # Восстановление значения: m' = s^e mod n
        recovered_m_int = pow(signature, public_key.e, public_key.n)
        mod_len_bytes = public_key.byte_length
        recovered_bytes = recovered_m_int.to_bytes(mod_len_bytes, byteorder="big")

        if use_padding:
            is_valid = pkcs1_v1_5_verify_encoded(recovered_bytes, msg_bytes)
            reason = (
                "Подпись корректна: блок PKCS#1 v1.5 валиден и хеш SHA-256 совпадает"
                if is_valid
                else "Подпись отклонена: неверная структура блока PKCS#1 v1.5 или хеш документа не совпадает"
            )
        else:
            expected_m_int = msg_hash_int % public_key.n
            is_valid = recovered_m_int == expected_m_int
            reason = (
                f"Подпись корректна: s^e mod n ({recovered_m_int}) совпадает с хешем документа ({expected_m_int})"
                if is_valid
                else f"Подпись отклонена: s^e mod n ({recovered_m_int}) != хеш документа ({expected_m_int})"
            )

        diagnostics = {
            "is_valid": is_valid,
            "reason": reason,
            "recomputed_sha256_hex": msg_hash_hex,
            "recovered_m_int": recovered_m_int,
            "recovered_bytes_hex": recovered_bytes.hex(),
            "public_exponent_e": public_key.e,
            "modulus_n": public_key.n,
        }

        return is_valid, diagnostics

    @staticmethod
    def sign_and_verify_with_cryptography_lib(
        message: Union[bytes, str],
        bits: int = 2048,
    ) -> Dict[str, Any]:
        """
        Демонстрационная реализация с использованием промышленной библиотеки `cryptography`.
        Позволяет сравнить результат нашего собственного модуля с эталонной библиотекой.
        """
        if not HAS_CRYPTOGRAPHY_LIB:
            return {"status": "Библиотека cryptography не установлена"}

        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        else:
            msg_bytes = message

        # Генерация ключей через cryptography
        priv_key = crypto_rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
        )
        pub_key = priv_key.public_key()

        # Создание подписи PKCS#1 v1.5 с SHA-256
        signature_bytes = priv_key.sign(
            msg_bytes,
            crypto_padding.PKCS1v15(),
            hashes.SHA256(),
        )

        # Проверка подписи
        try:
            pub_key.verify(
                signature_bytes,
                msg_bytes,
                crypto_padding.PKCS1v15(),
                hashes.SHA256(),
            )
            verification_status = True
        except Exception:
            verification_status = False

        return {
            "library": "cryptography (hazmat)",
            "key_size": bits,
            "signature_len_bytes": len(signature_bytes),
            "signature_hex": signature_bytes.hex()[:64] + "...",
            "verification_status": verification_status,
        }
