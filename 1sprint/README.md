# CryptoCore

Инструмент командной строки для операций блочного шифра AES-128 в режиме ECB.

## Инструкции по сборке

1. Склонируйте репозиторий и перейдите в его каталог:

   ```bash
   git clone <repository-url>
   cd CryptoCore/1sprint
   ```

2. (Рекомендуется) Создайте и активируйте виртуальное окружение:

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # В Windows: .venv\Scripts\activate
   ```

3. Установите проект и его зависимости:

   ```bash
   pip install .
   ```

   Это установит команду `cryptocore` в `PATH`. Для разработки
   (редактируемая установка плюс зависимости для тестов) используйте:

   ```bash
   pip install -e ".[dev]"
   ```

## Использование

```bash
cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt \
  --output ciphertext.enc
```

```bash
cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.enc \
  --output plaintext.txt
```

Если `--output` не указан, имя выходного файла определяется автоматически
на основе `--input` (`<input>.enc` для шифрования, `<input>.dec` для
расшифрования).

### Аргументы

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | Используемый шифр. В этом спринте поддерживается только `aes`. |
| `--mode` | Режим работы. В этом спринте поддерживается только `ecb`. |
| `--encrypt` / `--decrypt` | Должен быть указан ровно один из этих флагов. |
| `--key` | Ключ AES-128 в виде 32-символьной шестнадцатеричной строки (16 байт). |
| `--input` | Путь к входному файлу. |
| `--output` | Путь к выходному файлу (необязательный). |

## Проверка цикла шифрования/расшифрования

Основной приёмочный тест: если зашифровать файл, а затем расшифровать
результат, должен получиться файл, полностью идентичный исходному:

```bash
KEY=000102030405060708090a0b0c0d0e0f

cryptocore --algorithm aes --mode ecb --encrypt \
  --key $KEY --input original_file.txt --output ciphertext.bin

cryptocore --algorithm aes --mode ecb --decrypt \
  --key $KEY --input ciphertext.bin --output decrypted_file.txt

diff original_file.txt decrypted_file.txt && echo "Round-trip OK"
```

`diff` не должен показывать никаких отличий.

### Сверка с эталонной реализацией

Шифртекст, полученный CryptoCore, можно сверить с собственной реализацией
`aes-128-ecb` из OpenSSL, поскольку обе используют дополнение PKCS#7 по
умолчанию:

```bash
cryptocore --algorithm aes --mode ecb --encrypt \
  --key $KEY --input original_file.txt --output cryptocore.enc

openssl enc -aes-128-ecb -e -K $KEY -in original_file.txt -out openssl.enc

cmp cryptocore.enc openssl.enc && echo "Ciphertext matches OpenSSL"
```

Оба файла шифртекста побайтово идентичны, и каждый инструмент способен
расшифровать вывод другого.

## Зависимости

- Python 3.8+
- [pycryptodome](https://pypi.org/project/pycryptodome/) (предоставляет примитив блочного шифра AES)
- [pytest](https://pypi.org/project/pytest/) (для запуска набора тестов; только для разработки)

## Запуск тестов

```bash
pip install -e ".[dev]"
pytest
```

## Структура проекта

```
1sprint/
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py     # Точка входа CLI
│       ├── cli_parser.py   # Разбор и проверка аргументов
│       ├── file_io.py      # Вспомогательные функции чтения/записи бинарных файлов
│       └── modes/
│           └── ecb.py      # Режим ECB: дополнение, разбиение на блоки, вызовы AES
├── tests/
├── pyproject.toml
├── requirements.txt
└── README.md
```
