def pad(data: bytes, block_size):
    pad_len = block_size - len(data) % block_size
    return data + (bytes([pad_len]) * pad_len)


def unpad(data: bytes):
    return data[: -ord(data[-1:])]
