"""
main.py
Главный исполняемый модуль лабораторной работы по теме «Электронная цифровая подпись (ЭЦП)».

Предоставляет:
- Консольное интерактивное меню.
- Поддержку аргументов командной строки (--all, --rsa, --elgamal, --benchmark, --interactive).
- Интерактивный режим для ручного подписания и проверки любого пользовательского текста.
- Бенчмарк производительности (сравнение времени генерации ключей, подписания и верификации RSA vs ElGamal).
"""

import argparse
import sys
import time

# Настройка UTF-8 для корректного отображения кириллицы на Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False

from crypto_utils import sha256_hex
from elgamal_signature import ElGamalSigner, ElGamalSignature
from experiments import run_all_experiments, run_elgamal_experiments, run_rsa_experiments
from rsa_signature import RSASigner


def run_benchmark(iterations: int = 20):
    """
    Сравнительный бенчмарк скорости генерации ключей, подписания и проверки для RSA и ElGamal.
    """
    if HAS_RICH and console:
        console.print(Panel(
            f"[bold cyan]БЕНЧМАРК ПРОИЗВОДИТЕЛЬНОСТИ (число итераций: {iterations})[/bold cyan]",
            border_style="magenta"
        ))
    else:
        print(f"\n=== БЕНЧМАРК ПРОИЗВОДИТЕЛЬНОСТИ ({iterations} итераций) ===")

    test_doc = "Тестовый документ для замера времени выполнения криптографических операций цифровой подписи."

    # 1. Замер RSA 1024 бит
    t0 = time.time()
    for _ in range(iterations):
        pub_rsa, priv_rsa = RSASigner.generate_keypair(bits=1024)
    t_rsa_keygen = (time.time() - t0) / iterations

    t0 = time.time()
    for _ in range(iterations):
        sig_rsa, _ = RSASigner.sign(test_doc, priv_rsa, use_padding=True)
    t_rsa_sign = (time.time() - t0) / iterations

    t0 = time.time()
    for _ in range(iterations):
        RSASigner.verify(test_doc, sig_rsa, pub_rsa, use_padding=True)
    t_rsa_verify = (time.time() - t0) / iterations

    # 2. Замер ElGamal (RFC 2409 1024-бит)
    params_elgamal = ElGamalSigner.generate_parameters(use_predefined_group=True)
    t0 = time.time()
    for _ in range(iterations):
        pub_eg, priv_eg = ElGamalSigner.generate_keypair(params_elgamal)
    t_eg_keygen = (time.time() - t0) / iterations

    t0 = time.time()
    for _ in range(iterations):
        sig_eg, _ = ElGamalSigner.sign(test_doc, priv_eg)
    t_eg_sign = (time.time() - t0) / iterations

    t0 = time.time()
    for _ in range(iterations):
        ElGamalSigner.verify(test_doc, sig_eg, pub_eg)
    t_eg_verify = (time.time() - t0) / iterations

    if HAS_RICH and console:
        table = Table(title="Сравнение производительности: RSA vs ElGamal (1024 бит)", border_style="green")
        table.add_column("Операция", style="cyan", width=25)
        table.add_column("RSA 1024 бит (среднее)", style="yellow", justify="right")
        table.add_column("ElGamal 1024 бит (среднее)", style="magenta", justify="right")
        table.add_column("Анализ / Преимущество", style="white")

        table.add_row(
            "Генерация ключей",
            f"{t_rsa_keygen * 1000:.2f} мс",
            f"{t_eg_keygen * 1000:.2f} мс",
            f"ElGamal быстрее в {t_rsa_keygen / max(t_eg_keygen, 1e-9):.1f}x (параметры группы общие)"
        )
        table.add_row(
            "Формирование подписи",
            f"{t_rsa_sign * 1000:.2f} мс",
            f"{t_eg_sign * 1000:.2f} мс",
            "RSA выполняет возведение в степень с секретным d; ElGamal выбирает k и вычисляет g^k"
        )
        table.add_row(
            "Проверка подписи",
            f"{t_rsa_verify * 1000:.2f} мс",
            f"{t_eg_verify * 1000:.2f} мс",
            f"RSA быстрее в {t_eg_verify / max(t_rsa_verify, 1e-9):.1f}x (малая экспонента e=65537)"
        )
        console.print(table)
    else:
        print(f"RSA keygen:     {t_rsa_keygen * 1000:.2f} ms | ElGamal keygen: {t_eg_keygen * 1000:.2f} ms")
        print(f"RSA sign:       {t_rsa_sign * 1000:.2f} ms | ElGamal sign:   {t_eg_sign * 1000:.2f} ms")
        print(f"RSA verify:     {t_rsa_verify * 1000:.2f} ms | ElGamal verify: {t_eg_verify * 1000:.2f} ms")


def run_interactive_mode():
    """Интерактивный режим для ручного подписания и проверки произвольного текста."""
    if HAS_RICH and console:
        console.print(Panel(
            "[bold green]ИНТЕРАКТИВНЫЙ РЕЖИМ: СОЗДАНИЕ И ПРОВЕРКА ЭЦП[/bold green]\n"
            "Вы можете ввести любой текст, сгенерировать ключи, получить подпись и проверить ее.",
            border_style="green"
        ))
    else:
        print("\n=== ИНТЕРАКТИВНЫЙ РЕЖИМ ===")

    print("\nВыберите криптографический алгоритм:")
    print("1. RSA (1024 бит, PKCS#1 v1.5, SHA-256)")
    print("2. ElGamal (1024 бит, Oakley Group 2, SHA-256)")
    choice = input("Введите 1 или 2 [по умолчанию 1]: ").strip() or "1"

    default_text = "Служебная записка: Согласовать предоставление доступа к корпоративному хранилищу."
    print(f"\nВведите текст документа (или нажмите Enter для текста по умолчанию):\n[По умолчанию]: {default_text}")
    user_text = input("Ваш текст: ").strip() or default_text

    print(f"\n[1/3] Вычисление хеша SHA-256: {sha256_hex(user_text)}")

    if choice == "2":
        # ElGamal
        print("[2/3] Инициализация параметров схемы Эль-Гамаля и генерация ключей...")
        params = ElGamalSigner.generate_parameters(use_predefined_group=True)
        pub, priv = ElGamalSigner.generate_keypair(params)
        print(f"      Открытый ключ y: {hex(pub.y)[:30]}...")

        print("[3/3] Создание подписи ElGamal...")
        sig, diag = ElGamalSigner.sign(user_text, priv)
        print(f"      Подпись (r, s):")
        print(f"      r = {hex(sig.r)[:30]}...")
        print(f"      s = {hex(sig.s)[:30]}...")

        # Проверка
        print("\n--- Проверка подписи оригинального документа ---")
        valid, vdiag = ElGamalSigner.verify(user_text, sig, pub)
        print(f"Результат: {'[ПОДЛИННА]' if valid else '[ОТКЛОНЕНА]'}")

        # Проверка при искажении
        tampered = user_text + " (добавлено злоумышленником)"
        print(f"\n--- Проверка подписи модифицированного документа ---")
        invalid, _ = ElGamalSigner.verify(tampered, sig, pub)
        print(f"Результат: {'[ПОДЛИННА]' if invalid else '[ОТКЛОНЕНА]'}")

    else:
        # RSA
        print("[2/3] Генерация пары ключей RSA (1024 бит)...")
        pub, priv = RSASigner.generate_keypair(bits=1024)
        print(f"      Модуль n: {hex(pub.n)[:30]}...")
        print(f"      Открытая экспонента e: {pub.e}")

        print("[3/3] Создание подписи RSA-SHA256...")
        sig, diag = RSASigner.sign(user_text, priv, use_padding=True)
        print(f"      Подпись s: {hex(sig)[:30]}... ({diag['signature_bytes_len']} байт)")

        # Проверка
        print("\n--- Проверка подписи оригинального документа ---")
        valid, vdiag = RSASigner.verify(user_text, sig, pub, use_padding=True)
        print(f"Результат: {'[ПОДЛИННА]' if valid else '[ОТКЛОНЕНА]'}")

        # Проверка при искажении
        tampered = user_text + " (измененный текст)"
        print(f"\n--- Проверка подписи модифицированного документа ---")
        invalid, _ = RSASigner.verify(tampered, sig, pub, use_padding=True)
        print(f"Результат: {'[ПОДЛИННА]' if invalid else '[ОТКЛОНЕНА]'}")


def main_menu():
    """Интерактивное консольное меню выбора действий."""
    while True:
        print("\n" + "=" * 60)
        print(" ЛАБОРАТОРНАЯ РАБОТА: ЭЛЕКТРОННАЯ ЦИФРОВАЯ ПОДПИСЬ (ЭЦП)")
        print("=" * 60)
        print("1. Запустить все демонстрационные сценарии (RSA + ElGamal)")
        print("2. Запустить сценарии для RSA")
        print("3. Запустить сценарии для ElGamal")
        print("4. Интерактивное подписание произвольного текста")
        print("5. Бенчмарк производительности (RSA vs ElGamal)")
        print("0. Выход")
        print("-" * 60)
        choice = input("Выберите пункт меню [0-5]: ").strip()

        if choice == "1":
            run_all_experiments()
        elif choice == "2":
            run_rsa_experiments(bits=1024, use_padding=True)
        elif choice == "3":
            run_elgamal_experiments(use_predefined=True)
        elif choice == "4":
            run_interactive_mode()
        elif choice == "5":
            run_benchmark(iterations=10)
        elif choice == "0":
            print("Завершение работы.")
            break
        else:
            print("Неверный ввод. Пожалуйста, введите цифру от 0 до 5.")


def main():
    parser = argparse.ArgumentParser(
        description="Лабораторная работа: Электронная цифровая подпись (RSA и ElGamal)"
    )
    parser.add_argument("--all", action="store_true", help="Запустить все сценарии (RSA и ElGamal)")
    parser.add_argument("--rsa", action="store_true", help="Запустить сценарии только для RSA")
    parser.add_argument("--elgamal", action="store_true", help="Запустить сценарии только для ElGamal")
    parser.add_argument("--benchmark", action="store_true", help="Запустить замеры производительности")
    parser.add_argument("--interactive", action="store_true", help="Интерактивный режим работы")

    args = parser.parse_args()

    if args.all:
        run_all_experiments()
    elif args.rsa:
        run_rsa_experiments(bits=1024, use_padding=True)
    elif args.elgamal:
        run_elgamal_experiments(use_predefined=True)
    elif args.benchmark:
        run_benchmark(iterations=15)
    elif args.interactive:
        run_interactive_mode()
    else:
        # Если аргументы не указаны, запускаем интерактивное меню
        main_menu()


if __name__ == "__main__":
    main()
