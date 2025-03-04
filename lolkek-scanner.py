import argparse
import subprocess
import sys
from datetime import datetime
import os

# ┌──(kali㉿kali)-[~]
# └─$ python web.py -t testphp.vulnweb.com --subfinder "" --sqlmap "--crawl=2 --random-agent --batch" --nuclei "-es unknown" --wapiti ""

# Словарь для хранения путей к исполняемым файлам, флагов для цели и необходимости протокола
TOOLS = {
    "sqlmap": {"path": "sqlmap", "target_flag": "-u", "requires_protocol": False},
    "nuclei": {"path": "nuclei", "target_flag": "-u", "requires_protocol": False},
    "subfinder": {"path": "subfinder", "target_flag": "-d", "requires_protocol": False},
    "wapiti": {"path": "wapiti", "target_flag": "-u", "requires_protocol": True}
}

# Директория для сохранения отчетов
REPORT_DIR = "/home/kali"

def generate_report_filename(tool_name):
    """
    Генерирует имя файла для отчета на основе даты и времени.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{REPORT_DIR}/web-scan_{tool_name}_{timestamp}.txt"

def run_tool(tool_name, target, tool_params):
    """
    Запускает указанное приложение с заданными параметрами и сохраняет результат в файл.
    """
    if tool_name not in TOOLS:
        print(f"Ошибка: Приложение '{tool_name}' не поддерживается.")
        return

    # Формируем команду для запуска
    tool_config = TOOLS[tool_name]
    command = [tool_config["path"], tool_config["target_flag"], target]
    if tool_params:
        command.extend(tool_params.split())

    # Генерируем имя файла для отчета
    report_file = generate_report_filename(tool_name)
    print(f"Запуск {tool_name} с параметрами: {' '.join(command)}")
    print(f"Результат будет сохранен в: {report_file}")

    try:
        # Выполняем команду и перенаправляем вывод в файл
        with open(report_file, "w") as f:
            result = subprocess.run(
                command,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- Ошибки ---\n")
                f.write(result.stderr)
        print(f"Результат выполнения {tool_name} успешно сохранен в {report_file}")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении {tool_name}:")
        print(e.stderr)

def main():
    # Парсер аргументов командной строки
    parser = argparse.ArgumentParser(description="Автоматизация запуска sqlmap, nuclei, wapiti и subfinder.")
    parser.add_argument("-t", "--target", required=True, help="Цель для всех приложений (например, target.com).")
    parser.add_argument("--sqlmap", nargs='?', const="", help="Параметры для sqlmap (необязательно).")
    parser.add_argument("--nuclei", nargs='?', const="", help="Параметры для nuclei (необязательно).")
    parser.add_argument("--subfinder", nargs='?', const="", help="Параметры для subfinder (необязательно).")
    parser.add_argument("--wapiti", nargs='?', const="", help="Параметры для wapiti (необязательно).")

    args = parser.parse_args()

    # Проверяем, что хотя бы один инструмент указан
    if not any([args.sqlmap is not None, args.nuclei is not None, args.wapiti is not None, args.subfinder is not None]):
        print("Ошибка: Укажите параметры хотя бы для одного инструмента (--sqlmap, --nuclei, --wapiti, --subfinder).")
        sys.exit(1)

    # Запускаем инструменты последовательно
    if args.sqlmap is not None:
        run_tool("sqlmap", args.target, args.sqlmap)
    if args.nuclei is not None:
        run_tool("nuclei", args.target, args.nuclei)
    if args.subfinder is not None:
        run_tool("subfinder", args.target, args.subfinder)
    if args.wapiti is not None:
        # Корректировка цели для wapiti (добавляем протокол, если его нет)
        if not args.target.startswith(("http://", "https://")):
            args.target = f"http://{args.target}"
        run_tool("wapiti", args.target, args.wapiti)
   

if __name__ == "__main__":
    main()
