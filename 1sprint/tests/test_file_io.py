from cryptocore import file_io


def test_write_then_read_roundtrip_binary_data(tmp_path):
    path = str(tmp_path / "data.bin")
    data = bytes(range(256))
    file_io.write_file(path, data)
    assert file_io.read_file(path) == data


def test_write_overwrites_existing_file(tmp_path):
    path = str(tmp_path / "data.bin")
    file_io.write_file(path, b"first")
    file_io.write_file(path, b"second")
    assert file_io.read_file(path) == b"second"
