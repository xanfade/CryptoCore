
def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
