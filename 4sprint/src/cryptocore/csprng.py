import os


class CSPRNGError(RuntimeError):
    pass


def generate_random_bytes(num_bytes: int) -> bytes:
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise ValueError(f"число байт должно быть целым числом, получено: {num_bytes!r}")
    if num_bytes < 0:
        raise ValueError(f"число байт не может быть отрицательным: {num_bytes}")

    try:
        data = os.urandom(num_bytes)
    except (OSError, NotImplementedError) as exc:
        raise CSPRNGError(
            f"не удалось получить случайные байты от операционной системы (os.urandom): {exc}. "
            "Проверьте, что системный источник случайности доступен (/dev/urandom в Linux и macOS, "
            "системный криптографический генератор в Windows)"
        ) from exc

    if len(data) != num_bytes:
        raise CSPRNGError(
            f"источник случайности вернул {len(data)} байт вместо запрошенных {num_bytes}"
        )
    return data
