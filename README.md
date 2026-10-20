# CryptoCore

Учебный инструмент командной строки `cryptocore` на Python: шифрование файлов AES-128 (ECB, CBC, CFB, OFB, CTR, GCM),
криптостойкая генерация ключей и векторов инициализации, хеши SHA-256 и SHA3-256, коды аутентификации HMAC и AES-CMAC,
шифрование с аутентификацией (GCM, Encrypt-then-MAC). Блочный шифр AES берётся из pycryptodome, всё остальное
(режимы, хеши, MAC, AEAD) реализовано с нуля.

## Структура репозитория

Каждая папка `Nsprint` — самостоятельный проект: снимок работы **после N-го спринта**, в котором собраны результаты всех
предыдущих спринтов (в `3sprint` есть спринты 1, 2 и 3, в `6sprint` — все шесть). Внутри у каждой папки свои `README.md`,
`pyproject.toml`, `requirements.txt`, `src/` и `tests/`; предыдущие папки при переходе к следующему спринту не меняются.

| Папка | Содержимое (нарастающим итогом) | Тесты |
| --- | --- | --- |
| [`1sprint`](1sprint) | Спринт 1: AES-128 в режиме ECB, дополнение PKCS#7, CLI, чтение и запись файлов | 29 |
| [`2sprint`](2sprint) | + режимы CBC, CFB, OFB, CTR, IV в начале файла, совместимость с OpenSSL | 232 |
| [`3sprint`](3sprint) | + CSPRNG, автоматическая генерация ключа, предупреждение о слабом ключе, проверка NIST STS | 291 |
| [`4sprint`](4sprint) | + команда `dgst`: SHA-256 и SHA3-256 | 398 |
| [`5sprint`](5sprint) | + HMAC, AES-CMAC, проверка `--verify` | 582 |
| [`6sprint`](6sprint) | + GCM с AAD, Encrypt-then-MAC, HKDF | 1068 |

Актуальная версия — [`6sprint`](6sprint).

## Быстрый старт

```bash
cd 6sprint
pip install .

cryptocore --algorithm aes --mode gcm --encrypt --input plaintext.txt --output ciphertext.bin
cryptocore dgst --algorithm sha256 --input plaintext.txt
```

Подробные инструкции по сборке, описание всех аргументов, примеры и сведения о безопасности — в `README.md`
нужной папки, результаты проверок — в её `TESTING.md` (начиная с `3sprint`).

## Требования

- Python 3.8+
- [pycryptodome](https://pypi.org/project/pycryptodome/)
- для тестов: pytest; необязательно: OpenSSL, `cryptography`, `sha256sum`

## Тесты

```bash
cd 6sprint
pip install -e ".[dev]"
pytest
```

Долгие тесты на файлах больше 1 ГБ по умолчанию пропускаются (`CRYPTOCORE_LARGE_TEST=1` включает их).
