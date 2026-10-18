"""
experiments.py
Блок демонстрационных экспериментов для исследования электронных цифровых подписей (RSA и ElGamal).

Моделирует три ключевых сценария информационной безопасности:
1. Сценарий 1 (Успешный):
   - Генерация ключей автора (Алиса).
   - Хеширование и подписание исходного документа.
   - Успешная проверка подписи получателем (Боб) с открытым ключом Алисы.
2. Сценарий 2 (Подделка документа / Нарушение целостности):
   - Злоумышленник (Ева) изменяет текст подписанного документа.
   - Боб проверяет исходную подпись против измененного документа.
   - Результат: отказ в валидации (обнаружение подделки).
3. Сценарий 3 (Подделка подписи / Неверный автор):
   - Сценарий 3А: Искажение байт самой подписи.
   - Сценарий 3Б: Проверка документа чужим открытым ключом (попытка выдать себя за автора).
   - Результат: отказ в валидации.
"""

import sys
import time
from typing import Optional

# Настройка UTF-8 вывода для терминалов Windows
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
    from rich.text import Text
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False

from elgamal_signature import ElGamalSigner, ElGamalSignature
from rsa_signature import RSASigner


def print_header(title: str, subtitle: Optional[str] = None):
    """Выводит стилизованный заголовок этапа."""
    if HAS_RICH and console:
        content = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            content += f"\n[dim]{subtitle}[/dim]"
        console.print(Panel(content, border_style="blue", expand=False))
    else:
        print("\n" + "=" * 70)
        print(f" {title.upper()} ")
        if subtitle:
            print(f" {subtitle}")
        print("=" * 70)


def print_scenario_result(scenario_num: str, title: str, is_valid: bool, expected_valid: bool, details: str):
    """Выводит результат проверки сценария."""
    test_passed = (is_valid == expected_valid)
    status_text = "ПОДЛИННА (VALID)" if is_valid else "ОТКЛОНЕНА (REJECTED)"

    if HAS_RICH and console:
        status_color = "green" if is_valid else "red"
        test_badge = "[bold green] ТЕСТ ПРОЙДЕН [/bold green]" if test_passed else "[bold red] ТЕСТ ПРОВАЛЕН [/bold red]"
        
        table = Table(title=f"Результат: {scenario_num} — {title}", border_style="cyan")
        table.add_column("Параметр", style="bold white", width=25)
        table.add_column("Значение", style="white")

        table.add_row("Статус проверки ЭЦП", f"[{status_color}]{status_text}[/{status_color}]")
        table.add_row("Ожидаемый статус", "VALID" if expected_valid else "REJECTED")
        table.add_row("Итог эксперимента", test_badge)
        table.add_row("Диагностика системы", details)
        console.print(table)
    else:
        print(f"\n--- Результат: {scenario_num} - {title} ---")
        print(f"Статус проверки ЭЦП: {status_text}")
        print(f"Ожидаемый статус:    {'VALID' if expected_valid else 'REJECTED'}")
        print(f"Итог эксперимента:   {'[ТЕСТ ПРОЙДЕН]' if test_passed else '[ТЕСТ ПРОВАЛЕН]'}")
        print(f"Диагностика:         {details}")


def run_rsa_experiments(bits: int = 1024, use_padding: bool = True):
    """
    Запускает полный цикл экспериментов для ЭЦП на основе RSA.
    """
    mode_name = "RSA-SHA256 (PKCS#1 v1.5)" if use_padding else "RSA-SHA256 (Raw Textbook)"
    print_header(
        f"ЭКСПЕРИМЕНТЫ: ЭЦП НА ОСНОВЕ АЛГОРИТМА RSA ({bits} бит)",
        f"Режим работы: {mode_name}",
    )

    # 1. Генерация ключей участников
    if HAS_RICH and console:
        console.print("[dim] Генерация ключей RSA для Алисы (автор) и Евы (злоумышленник)...[/dim]")
    t0 = time.time()
    alice_pub, alice_priv = RSASigner.generate_keypair(bits=bits)
    eva_pub, eva_priv = RSASigner.generate_keypair(bits=bits)
    t_gen = time.time() - t0

    if HAS_RICH and console:
        info_table = Table(title="Сгенерированные ключи RSA", border_style="blue")
        info_table.add_column("Участник", style="yellow")
        info_table.add_column("Параметр", style="cyan")
        info_table.add_column("Битовая длина", style="magenta")
        info_table.add_column("Значение (Hex префикс / суффикс)", style="green")

        n_hex = hex(alice_pub.n)
        d_hex = hex(alice_priv.d)
        info_table.add_row("Алиса (Автор)", "Модуль n", f"{alice_pub.bit_length} бит", f"{n_hex[:16]}...{n_hex[-16:]}")
        info_table.add_row("Алиса (Автор)", "Открытая эксп. e", f"{alice_pub.e.bit_length()} бит", str(alice_pub.e))
        info_table.add_row("Алиса (Автор)", "Секретная эксп. d", f"{alice_priv.bit_length} бит", f"{d_hex[:16]}...{d_hex[-16:]}")
        info_table.add_row("Ева (Злоумышленник)", "Модуль n_eva", f"{eva_pub.bit_length} бит", f"{hex(eva_pub.n)[:16]}...")
        console.print(info_table)
        console.print(f"[dim]Время генерации ключей: {t_gen:.3f} сек.[/dim]\n")

    # Исходный документ
    original_document = (
        "ДОГОВОР КУПЛИ-ПРОДАЖИ №104/2026.\n"
        "1. Продавец: ООО 'Вектор Безопасности'.\n"
        "2. Покупатель: ПАО 'КриптоСистемы'.\n"
        "3. Сумма сделки: 1 500 000 (Один миллион пятьсот тысяч) рублей.\n"
        "4. Срок поставки оборудования: до 01.12.2026."
    )

    # 2. Создание подписи
    sig_int, sign_diag = RSASigner.sign(original_document, alice_priv, use_padding=use_padding)

    if HAS_RICH and console:
        sig_hex = hex(sig_int)
        console.print(Panel(
            f"[bold yellow]Исходный документ:[/bold yellow]\n{original_document}\n\n"
            f"[bold cyan]Хеш SHA-256:[/bold cyan] {sign_diag['sha256_hex']}\n"
            f"[bold green]ЭЦП RSA (s):[/bold green] {sig_hex[:32]}...{sig_hex[-32:]} ({sign_diag['signature_bytes_len']} байт)",
            title="Формирование ЭЦП автором (Алиса)",
            border_style="green"
        ))

    # СЦЕНАРИЙ 1: Успешная проверка подлинного документа
    is_valid_1, diag_1 = RSASigner.verify(original_document, sig_int, alice_pub, use_padding=use_padding)
    print_scenario_result(
        scenario_num="Сценарий 1",
        title="Проверка подлинного документа и корректной подписи",
        is_valid=is_valid_1,
        expected_valid=True,
        details=diag_1["reason"],
    )

    # СЦЕНАРИЙ 2: Подделка документа злоумышленником
    tampered_document = original_document.replace("1 500 000", "9 500 000")
    is_valid_2, diag_2 = RSASigner.verify(tampered_document, sig_int, alice_pub, use_padding=use_padding)
    print_scenario_result(
        scenario_num="Сценарий 2",
        title="Попытка подделки документа (изменена сумма сделки)",
        is_valid=is_valid_2,
        expected_valid=False,
        details=diag_2["reason"],
    )

    # СЦЕНАРИЙ 3А: Искажение самой цифровой подписи
    corrupted_sig = sig_int ^ 0x1337  # Изменяем несколько бит в подписи
    is_valid_3a, diag_3a = RSASigner.verify(original_document, corrupted_sig, alice_pub, use_padding=use_padding)
    print_scenario_result(
        scenario_num="Сценарий 3А",
        title="Проверка с поврежденной/фальсифицированной подписью",
        is_valid=is_valid_3a,
        expected_valid=False,
        details=diag_3a["reason"],
    )

    # СЦЕНАРИЙ 3Б: Проверка с открытым ключом другого лица (Евы)
    is_valid_3b, diag_3b = RSASigner.verify(original_document, sig_int, eva_pub, use_padding=use_padding)
    print_scenario_result(
        scenario_num="Сценарий 3Б",
        title="Проверка подлинной подписи чужим открытым ключом (подмена автора)",
        is_valid=is_valid_3b,
        expected_valid=False,
        details=diag_3b["reason"],
    )


def run_elgamal_experiments(use_predefined: bool = True, bits: int = 256):
    """
    Запускает полный цикл экспериментов для ЭЦП по схеме Эль-Гамаля.
    """
    group_desc = "RFC 2409 Oakley Group 2 (1024 бит, g=2)" if use_predefined else f"Динамически сгенерированная безопасная группа ({bits} бит)"
    print_header(
        "ЭКСПЕРИМЕНТЫ: ЭЦП ПО СХЕМЕ ЭЛЬ-ГАМАЛЯ (ELGAMAL DIGITAL SIGNATURE)",
        f"Параметры группы: {group_desc}",
    )

    # 1. Инициализация параметров и ключей
    if HAS_RICH and console:
        console.print("[dim] Инициализация параметров схемы Эль-Гамаля и генерация ключей...[/dim]")
    t0 = time.time()
    params = ElGamalSigner.generate_parameters(bits=bits, use_predefined_group=use_predefined)
    alice_pub, alice_priv = ElGamalSigner.generate_keypair(params)
    eva_pub, eva_priv = ElGamalSigner.generate_keypair(params)
    t_gen = time.time() - t0

    if HAS_RICH and console:
        table = Table(title="Параметры и ключи ElGamal", border_style="blue")
        table.add_column("Объект", style="yellow")
        table.add_column("Параметр", style="cyan")
        table.add_column("Битовая длина", style="magenta")
        table.add_column("Значение (Hex / Dec)", style="green")

        p_hex = hex(params.p)
        y_hex = hex(alice_pub.y)
        table.add_row("Общие параметры", "Простое число p", f"{params.bit_length} бит", f"{p_hex[:16]}...{p_hex[-16:]}")
        table.add_row("Общие параметры", "Генератор g", f"{params.g.bit_length()} бит", str(params.g))
        table.add_row("Алиса (Автор)", "Секретный ключ x", f"{alice_priv.x.bit_length()} бит", f"{hex(alice_priv.x)[:16]}...")
        table.add_row("Алиса (Автор)", "Открытый ключ y = g^x mod p", f"{alice_pub.y.bit_length()} бит", f"{y_hex[:16]}...{y_hex[-16:]}")
        table.add_row("Ева (Злоумышленник)", "Открытый ключ y_eva", f"{eva_pub.y.bit_length()} бит", f"{hex(eva_pub.y)[:16]}...")
        console.print(table)
        console.print(f"[dim]Время инициализации: {t_gen:.3f} сек.[/dim]\n")

    # Исходный документ
    original_document = (
        "ПЛАТЕЖНОЕ ПОРУЧЕНИЕ №789.\n"
        "Плательщик: ООО 'Северный Альянс' (ИНН 7701234567).\n"
        "Получатель: АО 'ТехноИнвест' (ИНН 7809876543).\n"
        "Сумма платежа: 250 000 (Двести пятьдесят тысяч) рублей.\n"
        "Назначение: Оплата лицензии на криптографическое ПО."
    )

    # 2. Создание подписи ElGamal: (r, s)
    sig, sign_diag = ElGamalSigner.sign(original_document, alice_priv)

    if HAS_RICH and console:
        r_hex = hex(sig.r)
        s_hex = hex(sig.s)
        console.print(Panel(
            f"[bold yellow]Исходный документ:[/bold yellow]\n{original_document}\n\n"
            f"[bold cyan]Хеш SHA-256 (h):[/bold cyan] {sign_diag['sha256_hex']}\n"
            f"[bold magenta]Сессионный ключ k:[/bold magenta] {hex(sign_diag['ephemeral_key_k'])[:24]}... (НОД(k, p-1)=1)\n"
            f"[bold green]Компонента подписи r = g^k mod p:[/bold green] {r_hex[:24]}...{r_hex[-24:]}\n"
            f"[bold green]Компонента подписи s = (h - x*r)*k^(-1) mod (p-1):[/bold green] {s_hex[:24]}...{s_hex[-24:]}",
            title="Формирование ЭЦП Эль-Гамаля автором (Алиса)",
            border_style="green"
        ))

    # СЦЕНАРИЙ 1: Успешная проверка подлинного документа
    is_valid_1, diag_1 = ElGamalSigner.verify(original_document, sig, alice_pub)
    eq_details = f"v1 (g^h mod p) = {str(diag_1['v1_left_side'])[:20]}... | v2 (y^r * r^s mod p) = {str(diag_1['v2_right_side'])[:20]}..."
    print_scenario_result(
        scenario_num="Сценарий 1",
        title="Проверка подлинного документа и корректной подписи ElGamal",
        is_valid=is_valid_1,
        expected_valid=True,
        details=f"{diag_1['reason']} ({eq_details})",
    )

    # СЦЕНАРИЙ 2: Подделка документа злоумышленником
    tampered_document = original_document.replace("250 000", "7 250 000")
    is_valid_2, diag_2 = ElGamalSigner.verify(tampered_document, sig, alice_pub)
    print_scenario_result(
        scenario_num="Сценарий 2",
        title="Попытка подделки документа (изменена сумма платежа)",
        is_valid=is_valid_2,
        expected_valid=False,
        details=diag_2["reason"],
    )

    # СЦЕНАРИЙ 3А: Искажение самой цифровой подписи (компоненты s)
    corrupted_sig = ElGamalSignature(r=sig.r, s=(sig.s ^ 0x42) % (params.p - 1))
    is_valid_3a, diag_3a = ElGamalSigner.verify(original_document, corrupted_sig, alice_pub)
    print_scenario_result(
        scenario_num="Сценарий 3А",
        title="Проверка с поврежденной подписью (искажена компонента s)",
        is_valid=is_valid_3a,
        expected_valid=False,
        details=diag_3a["reason"],
    )

    # СЦЕНАРИЙ 3Б: Проверка подлинной подписи с чужим открытым ключом (Евы)
    is_valid_3b, diag_3b = ElGamalSigner.verify(original_document, sig, eva_pub)
    print_scenario_result(
        scenario_num="Сценарий 3Б",
        title="Проверка с чужим открытым ключом y_eva (подмена авторства)",
        is_valid=is_valid_3b,
        expected_valid=False,
        details=diag_3b["reason"],
    )


def run_all_experiments():
    """Запускает полный комплекс тестов по обоим алгоритмам."""
    print_header(
        "ЛАБОРАТОРНАЯ РАБОТА: ЭЛЕКТРОННАЯ ЦИФРОВАЯ ПОДПИСЬ (ЭЦП)",
        "Сравнительное исследование алгоритмов RSA и ElGamal",
    )
    run_rsa_experiments(bits=1024, use_padding=True)
    print("\n" + "#" * 70 + "\n")
    run_elgamal_experiments(use_predefined=True)


if __name__ == "__main__":
    run_all_experiments()
