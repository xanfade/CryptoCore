# CryptoCore

Инструмент командной строки для шифрования файлов блочным шифром AES-128 в режимах ECB, CBC, CFB, OFB и CTR
с криптостойкой генерацией ключей и векторов инициализации, а также для вычисления хешей файлов
(SHA-256 и SHA3-256) и кодов аутентификации сообщений (HMAC и AES-CMAC); всё реализовано с нуля.

## Инструкции по сборке

1. Склонируйте репозиторий и перейдите в каталог спринта:

   ```bash
   git clone <repository-url>
   cd CryptoCore/5sprint
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
cryptocore --algorithm aes --mode <режим> (--encrypt | --decrypt) \
  [--key <ключ_hex>] [--iv <iv_hex>] --input <файл> [--output <файл>]
```

### Аргументы

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | Используемый шифр. Поддерживается только `aes` (AES-128). |
| `--mode` | Режим работы: `ecb`, `cbc`, `cfb`, `ofb` или `ctr`. |
| `--encrypt` / `--decrypt` | Должен быть указан ровно один из этих флагов. |
| `--key` | Ключ AES-128 в виде 32-символьной шестнадцатеричной строки (16 байт). **При шифровании можно не указывать** (ключ будет сгенерирован), **при расшифровании обязателен**. |
| `--iv` | Вектор инициализации в hex (32 символа, 16 байт). Только для `--decrypt` и только в режимах `cbc`, `cfb`, `ofb`, `ctr`. |
| `--input` | Путь к входному файлу. |
| `--output` | Путь к выходному файлу (необязательный; по умолчанию `<input>.enc` при шифровании и `<input>.dec` при расшифровании). |

### Режимы работы

| Режим | Тип | Дополнение PKCS#7 | IV |
| --- | --- | --- | --- |
| `ecb` | блочный | да | нет |
| `cbc` | блочный, с цепочкой блоков | да | да |
| `cfb` | потоковый (сегмент 128 бит) | нет | да |
| `ofb` | потоковый | нет | да |
| `ctr` | потоковый (счётчик из IV, +1 на каждый блок) | нет | да |

В потоковых режимах длина шифртекста равна длине открытого текста: последний
неполный блок обрабатывается без изменения размера.

### Обработка IV

- **Шифрование** (`cbc`, `cfb`, `ofb`, `ctr`): IV генерируется автоматически
  функцией `generate_random_bytes(16)` из модуля CSPRNG и записывается в **первые 16 байт**
  выходного файла. Формат файла: `<IV (16 байт)><шифртекст>`. Флаг `--iv` при
  шифровании запрещён — программа завершится с ошибкой.
- **Расшифрование** без `--iv`: IV читается из первых 16 байт входного файла,
  остальное — шифртекст. Если файл короче 16 байт, выводится ошибка.
- **Расшифрование** с `--iv`: используется указанный IV, а входной файл целиком
  считается шифртекстом (без IV в начале). Так расшифровываются файлы,
  созданные другими программами, например OpenSSL.
- Режим `ecb` IV не использует: формат файла остаётся `<шифртекст>`, а `--iv` для него запрещён.

### Примеры

Шифрование с указанным ключом (IV генерируется и записывается в начало файла):

```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt --output ciphertext.bin
```

Расшифрование, IV берётся из файла:

```bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin --output decrypted.txt
```

Расшифрование с явно указанным IV (в файле только шифртекст):

```bash
cryptocore --algorithm aes --mode ctr --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv aabbccddeeff00112233445566778899 \
  --input openssl_cipher.bin --output decrypted.txt
```

## Автоматическая генерация ключа

Если при **шифровании** флаг `--key` не указан, программа:

1. генерирует случайный 16-байтовый (128-битный) ключ через `generate_random_bytes(16)`;
2. печатает его в **stdout** ровно один раз, сразу после генерации, в виде строки
   `[INFO] Generated random key: <32 hex-символа>`;
3. выполняет шифрование этим ключом.

Пример:

```bash
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

```text
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

(Ключ в примере условный: при каждом запуске генерируется новый.)

Сгенерированный ключ **не записывается** в выходной файл — сохраните его из терминала сами,
без него файл расшифровать нельзя. Расшифровать можно только с явным ключом:

```bash
cryptocore --algorithm aes --mode ctr --decrypt \
  --key 1a2b3c4d5e6f7890fedcba9876543210 \
  --input ciphertext.bin --output decrypted.txt
```

При расшифровании без `--key` программа выводит ошибку и завершается с ненулевым кодом.

Строка с ключом печатается в stdout, а все сообщения об ошибках и предупреждения идут в stderr,
поэтому ключ можно отделить от остального вывода: `cryptocore ... > key.txt`.

### Предупреждение о слабом ключе

Если ключ указан пользователем и выглядит слабым (все нулевые байты, все байты одинаковы,
байты идут подряд по возрастанию или убыванию, например `000102030405060708090a0b0c0d0e0f`),
в stderr выводится предупреждение. Работа при этом продолжается. Чтобы избежать предупреждения,
не указывайте `--key` при шифровании или используйте действительно случайный ключ.

## Криптостойкий генератор случайных чисел (CSPRNG)

Модуль [`src/cryptocore/csprng.py`](src/cryptocore/csprng.py) содержит функцию
`generate_random_bytes(num_bytes: int) -> bytes`. Она используется для:

- генерации ключа, когда `--key` не указан;
- генерации всех IV при шифровании в режимах CBC, CFB, OFB и CTR.

**Свойства безопасности:**

- Источник случайности — `os.urandom()`, то есть криптостойкий генератор операционной системы
  (Linux: `getrandom()` / `/dev/urandom`, macOS: `getentropy()`, Windows: системный криптографический генератор).
  Он засевается энтропией ядра и рассчитан на криптографическое применение.
- Модуль `random` и другие несекретные генераторы не используются нигде в проекте
  (это проверяет автоматический тест). Начального значения (seed) пользователь задать не может, поэтому
  последовательность невозможно воспроизвести или предсказать по прошлым значениям.
- Ключ имеет полные 128 бит энтропии, IV — 128 бит. IV не секретен, но обязан быть непредсказуемым
  и не повторяться для одного ключа, поэтому для каждого шифрования генерируется новый.
- Ошибки источника (недоступен `os.urandom`, получено меньше байт, чем запрошено) приводят к понятному
  сообщению об ошибке и завершению с ненулевым кодом; шифрование без надёжной случайности не выполняется.
- Стойкость зависит от самой ОС и её источников энтропии; сгенерированный ключ выводится в терминал открытым
  текстом, поэтому следите за историей оболочки и логами.

## Вычисление хеша файла (команда `dgst`)

Отдельная подкоманда `dgst` вычисляет контрольную сумму файла или код аутентификации (HMAC, AES-CMAC).
Она не принимает аргументы шифрования (`--mode`, `--encrypt`/`--decrypt`, `--iv`): при их указании программа
выводит ошибку. Флаг `--key` здесь допустим только вместе с `--hmac` или `--cmac`.

```bash
cryptocore dgst --algorithm <алгоритм> --input <файл> [--output <файл>]
cryptocore dgst --algorithm sha256 --hmac --key <ключ_hex> --input <файл> [--output <файл> | --verify <файл>]
cryptocore dgst --cmac --key <ключ_hex_16_байт> --input <файл> [--output <файл> | --verify <файл>]
```

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | `sha256` или `sha3-256` (с `--hmac` — хеш-функция для HMAC). С `--cmac` можно не указывать или указать `aes`. |
| `--input` | Путь к входному файлу. Значение `-` означает чтение из стандартного ввода. |
| `--output` | Необязательный. Записать результат в файл вместо вывода в stdout (формат строки тот же). |
| `--hmac` | Вычислить HMAC (RFC 2104). Требует `--key`. |
| `--cmac` | Вычислить AES-CMAC (бонус). Требует `--key` ровно из 16 байт. |
| `--key` | Ключ в hex. Для `--hmac` — любой длины, для `--cmac` — 32 hex-символа. Без `--hmac`/`--cmac` не допускается. |
| `--verify` | Файл с ожидаемым значением MAC: вычисленное значение сравнивается с ним. Нельзя использовать вместе с `--output`. |

Вывод — одна строка в формате утилит `sha256sum`/`sha3sum`: `<значение в нижнем регистре><два пробела><путь>`.
Для HMAC и CMAC формат тот же.

### Примеры

```bash
cryptocore dgst --algorithm sha256 --input document.pdf
```

```text
5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5  document.pdf
```

(значение условное, у вашего файла будет своё)

Запись результата в файл:

```bash
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

Чтение из стандартного ввода (значения из тестовых векторов NIST):

```bash
echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
```

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -
```

Сверка с системной утилитой (различий быть не должно):

```bash
cryptocore dgst --algorithm sha256 --input large_file.iso > my_hash.txt
sha256sum --text large_file.iso > system_hash.txt
diff my_hash.txt system_hash.txt
```

Для SHA3-256 сверку можно сделать через OpenSSL:

```bash
cryptocore dgst --algorithm sha3-256 --input large_file.iso
openssl dgst -sha3-256 -r large_file.iso
```

### Реализованные алгоритмы

| Алгоритм | Стандарт | Конструкция | Размер блока | Выход |
| --- | --- | --- | --- | --- |
| `sha256` | NIST FIPS 180-4 | Меркла — Дамгора, блоки по 512 бит, 64 раунда | 64 байта | 256 бит |
| `sha3-256` | NIST FIPS 202 | губка Keccak-f[1600], rate 1088 бит, суффикс `01` | 136 байт | 256 бит |

Обе функции написаны с нуля в `src/cryptocore/hash/`: константы SHA-256 вычисляются из простых чисел
(дробные части квадратных и кубических корней), константы Keccak — из регистра сдвига по FIPS 202.
Файл читается кусками по 8192 байта, поэтому расход памяти не зависит от размера файла (поддерживаются пустые и очень большие файлы).

**Свойства безопасности.**

- Обе функции считаются криптографически стойкими: 256-битный выход даёт порядка 2^128 операций для поиска
  коллизии и 2^256 для поиска прообраза; известных практических атак нет.
- **SHA-256** построен по схеме Меркла — Дамгора, поэтому подвержен *атаке удлинением сообщения*
  (зная `H(m)` и длину `m`, можно вычислить `H(m || pad || x)` без знания `m`). Для аутентификации сообщений
  используйте HMAC, а не `H(ключ || сообщение)`.
- **SHA3-256** построен на губке Keccak и от этой атаки не страдает; выбран NIST как структурно независимая
  альтернатива семейству SHA-2.
- Хеш проверяет **целостность**, а не **подлинность**: злоумышленник, меняющий файл, может пересчитать
  и хеш. Для подлинности нужны MAC или цифровая подпись.
- Для хранения паролей обычные хеши не подходят (слишком быстрые): нужны bcrypt, scrypt или Argon2.
- Реализации учебные, на чистом Python и не защищены от атак по сторонним каналам; скорость ~0,4–0,5 МБ/с
  (в тысячи раз медленнее `hashlib` и `sha256sum`), см. [TESTING.md](TESTING.md).

## Код аутентификации сообщения: HMAC

HMAC подтверждает и **целостность**, и **подлинность** данных: подделать значение может только тот, кто знает секретный ключ.

### Генерация и проверка HMAC

Генерация (ключ — hex-строка произвольной длины):

```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

```text
<64 hex-символа HMAC>  message.txt
```

Пример из RFC 4231 (тестовый случай 1; ключ из 20 байт `0b`):

```bash
echo -n "Hi There" > test_file.txt
cryptocore dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input test_file.txt
```

```text
b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7  test_file.txt
```

Сохранение значения в файл и проверка через `--verify`:

```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output expected_hmac.txt
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected_hmac.txt
```

```text
[OK] HMAC verification successful
```

При успехе код возврата 0. При несовпадении (файл изменён или указан другой ключ) в stderr выводится
`[ERROR] HMAC verification failed`, код возврата 1. Если файл с ожидаемым значением не читается или в нём нет
шестнадцатеричного значения, выводится `[ERROR] ...` и код возврата тоже ненулевой.

Файл с ожидаемым значением читается гибко: берётся первое слово, регистр и имя файла игнорируются, поэтому
подходит как вывод самой программы (`ЗНАЧЕНИЕ  ИМЯ`), так и просто значение.

Проверка вручную через `diff`:

```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt > computed_hmac.txt
diff computed_hmac.txt expected_hmac.txt
```

Обнаружение подделки:

```bash
echo "original content" > file.txt
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input file.txt > original_hmac.txt
echo "modified content" > file.txt
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input file.txt --verify original_hmac.txt
echo "код возврата: $?"
```

```text
[ERROR] HMAC verification failed
код возврата: 1
```

Сверка с OpenSSL:

```bash
openssl dgst -sha256 -mac HMAC -macopt hexkey:00112233445566778899aabbccddeeff -r message.txt
```

### Как устроен HMAC

HMAC реализован с нуля по RFC 2104 поверх собственного SHA-256 из спринта 4 (`src/cryptocore/mac/hmac.py`):

```text
HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m))
```

где `H` — SHA-256, `ipad` — байт `0x36`, повторённый по размеру блока (64 байта), `opad` — байт `0x5c`.
Обработка ключа: ключ длиннее блока (64 байта) сначала хешируется, ключ короче блока дополняется нулями до 64 байт,
поэтому поддерживаются ключи любой длины. Входной файл читается порциями по 8192 байта и подаётся во «внутренний»
хеш по мере чтения, так что память не зависит от размера файла. С `--algorithm sha3-256` HMAC строится на SHA3-256
(размер блока 136 байт).

### Свойства безопасности HMAC

- Без знания ключа нельзя ни вычислить корректный HMAC, ни подделать значение для изменённого сообщения;
  изменение даже одного бита сообщения или ключа полностью меняет результат.
- В отличие от `H(ключ || сообщение)`, конструкция HMAC не подвержена атаке удлинением сообщения, хотя SHA-256
  построен по схеме Меркла — Дамгора.
- Стойкость HMAC определяется длиной и случайностью ключа: используйте ключ не короче 16 байт, сгенерированный
  криптостойким генератором (например, из `cryptocore --encrypt` без `--key`). Ключ длиннее блока не даёт
  дополнительной стойкости: он сводится к своему хешу.
- Значения сравниваются за постоянное время (`secrets.compare_digest`), чтобы не раскрывать, сколько первых
  символов совпало.
- HMAC не обеспечивает неотказуемости (не является электронной подписью: проверяющий знает тот же ключ) и не
  скрывает содержимое сообщения (для конфиденциальности нужно шифрование).
- Реализация учебная, на чистом Python, и не защищена от атак по сторонним каналам.

## AES-CMAC (бонус)

AES-CMAC (NIST SP 800-38B, RFC 4493) — код аутентификации на основе блочного шифра AES-128
(`src/cryptocore/mac/cmac.py`, используется AES-примитив из первых спринтов). Реализованы генерация подключей K1 и K2
(удвоение в поле GF(2^128) с константой `0x87`), цепочка CBC-MAC и XOR последнего блока с K1 (полный блок)
или с K2 (блок с дополнением `0x80 00…00`). Ключ — ровно 16 байт.

```bash
cryptocore dgst --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.bin
cryptocore dgst --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.bin --output cmac.txt
cryptocore dgst --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.bin --verify cmac.txt
```

Сообщение при успешной проверке: `[OK] CMAC verification successful`, при ошибке: `[ERROR] CMAC verification failed`.
Сверка с OpenSSL:

```bash
openssl mac -cipher AES-128-CBC -macopt hexkey:2b7e151628aed2a6abf7158809cf4f3c -in message.bin CMAC
```

## Проверка цикла шифрования/расшифрования

Зашифрованный и затем расшифрованный файл должен полностью совпадать с исходным. Ключ можно
не задавать — тогда он берётся из вывода программы:

```bash
KEY=$(cryptocore --algorithm aes --mode cfb --encrypt \
  --input original_file.txt --output ciphertext.bin | sed -n 's/^\[INFO\] Generated random key: //p')

cryptocore --algorithm aes --mode cfb --decrypt \
  --key $KEY --input ciphertext.bin --output decrypted_file.txt

diff original_file.txt decrypted_file.txt && echo "Round-trip OK"
```

## Статистическое тестирование (NIST STS)

Качество генератора проверяется набором статистических тестов NIST STS. Кратко:

1. Сгенерируйте 10 МБ данных генератором проекта:

   ```bash
   python scripts/generate_nist_data.py --size-mb 10 --output nist_test_data.bin
   ```

2. Скачайте NIST Statistical Test Suite с сайта NIST (раздел Random Bit Generation → Documentation and Software),
   соберите его (`make`; нужен компилятор C, в Windows удобнее WSL) и запустите все 15 тестов:

   ```bash
   ./assess 1000000
   ```

   В интерактивном меню выберите входной файл `nist_test_data.bin`, «Apply All Statistical Tests», число
   последовательностей (для 10 МБ — до 80) и формат входных данных «Binary».

3. Отчёт появится в `experiments/AlgorithmTesting/finalAnalysisReport.txt`. Тест считается пройденным,
   если p-значение ≥ 0.01, а доля прошедших последовательностей попадает в допустимый интервал.

Подробная процедура, критерии и результаты — в [TESTING.md](TESTING.md). Там же описана быстрая
самопроверка `scripts/quick_stats.py` (три теста из NIST SP 800-22 на чистом Python; она не заменяет STS).

## Совместимость с OpenSSL

Результаты CryptoCore можно сверить с OpenSSL (`openssl enc -aes-128-<режим>`)
в обе стороны. OpenSSL по умолчанию использует дополнение PKCS#7 в режиме CBC и
не дополняет данные в CFB, OFB и CTR, как и CryptoCore. В этих проверках ключ всегда
задаётся через `--key`, генератор случайных чисел не участвует.

### 1. Шифруем CryptoCore, расшифровываем OpenSSL

```bash
KEY=000102030405060708090a0b0c0d0e0f

cryptocore --algorithm aes --mode cbc --encrypt \
  --key $KEY --input plain.txt --output cipher.bin

# IV — первые 16 байт файла, остальное — шифртекст
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1

openssl enc -aes-128-cbc -d -K $KEY \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext_only.bin -out decrypted.txt

cmp plain.txt decrypted.txt && echo "CryptoCore -> OpenSSL OK"
```

### 2. Шифруем OpenSSL, расшифровываем CryptoCore

```bash
IV=AABBCCDDEEFF00112233445566778899

openssl enc -aes-128-cbc -K $KEY -iv $IV -in plain.txt -out openssl_cipher.bin

cryptocore --algorithm aes --mode cbc --decrypt \
  --key $KEY --iv $IV \
  --input openssl_cipher.bin --output decrypted.txt

cmp plain.txt decrypted.txt && echo "OpenSSL -> CryptoCore OK"
```

### Скрипт для всех четырёх режимов

```bash
KEY=000102030405060708090a0b0c0d0e0f
IV=AABBCCDDEEFF00112233445566778899
echo "Тестовое сообщение для проверки совместимости" > plain.txt

for MODE in cbc cfb ofb ctr; do
  cryptocore --algorithm aes --mode $MODE --encrypt --key $KEY \
    --input plain.txt --output cipher.bin
  dd if=cipher.bin of=iv.bin bs=16 count=1 2>/dev/null
  dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1 2>/dev/null
  openssl enc -aes-128-$MODE -d -K $KEY -iv $(xxd -p iv.bin | tr -d '\n') \
    -in ciphertext_only.bin -out decrypted.txt
  cmp plain.txt decrypted.txt && echo "$MODE: CryptoCore -> OpenSSL OK"

  openssl enc -aes-128-$MODE -K $KEY -iv $IV -in plain.txt -out openssl_cipher.bin
  cryptocore --algorithm aes --mode $MODE --decrypt --key $KEY --iv $IV \
    --input openssl_cipher.bin --output decrypted.txt
  cmp plain.txt decrypted.txt && echo "$MODE: OpenSSL -> CryptoCore OK"
done
```

Те же проверки автоматизированы в `tests/test_interop.py` (для четырёх режимов,
в обе стороны, на файлах разной длины; тесты пропускаются, если `openssl` не найден в `PATH`).
Предупреждения о слабом ключе `000102…0f` в этих примерах выводятся в stderr и на результат не влияют.

## Зависимости

- Python 3.8+
- [pycryptodome](https://pypi.org/project/pycryptodome/) (предоставляет примитив блочного шифра AES)
- [pytest](https://pypi.org/project/pytest/) (для запуска тестов; только для разработки)
- OpenSSL (необязательно; для тестов совместимости)
- NIST Statistical Test Suite (необязательно; для статистического тестирования)
- `sha256sum` (необязательно; для сверки хешей, входит в GNU coreutils)

## Запуск тестов

```bash
pip install -e ".[dev]"
pytest
```

## Структура проекта

```
5sprint/
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py     # Точка входа CLI, ключ и IV
│       ├── cli_parser.py   # Разбор и проверка аргументов
│       ├── csprng.py       # CSPRNG: generate_random_bytes
│       ├── dgst.py         # Команда dgst: хеш, HMAC, CMAC, --verify
│       ├── hash/
│       │   ├── sha256.py   # SHA-256 (FIPS 180-4)
│       │   └── sha3_256.py # SHA3-256 (FIPS 202, Keccak)
│       ├── mac/
│       │   ├── hmac.py     # HMAC (RFC 2104)
│       │   └── cmac.py     # AES-CMAC (NIST SP 800-38B)
│       ├── key_checks.py   # Обнаружение слабых ключей
│       ├── file_io.py      # Чтение/запись бинарных файлов
│       └── modes/
│           ├── common.py   # Примитив AES, XOR, проверка IV
│           ├── ecb.py      # ECB и дополнение PKCS#7
│           ├── cbc.py      # CBC
│           ├── cfb.py      # CFB (сегмент 128 бит)
│           ├── ofb.py      # OFB
│           └── ctr.py      # CTR
├── scripts/
│   ├── generate_nist_data.py  # Файл случайных данных для NIST STS
│   ├── quick_stats.py         # Быстрая самопроверка (подмножество NIST SP 800-22)
│   └── benchmark_hash.py      # Сравнение скорости хешей с hashlib и sha256sum
├── tests/
├── TESTING.md
├── pyproject.toml
├── requirements.txt
└── README.md
```
