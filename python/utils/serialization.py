"""
该模块实现项目中的一个功能组件。
"""

import struct
from typing import List, Tuple


def bytes_to_bits(data: bytes) -> str:
    """bytes_to_bits 函数。"""
    return "".join(format(b, "08b") for b in data)


def bits_to_bytes(bits: str) -> bytes:
    """bits_to_bytes 函数。"""
    # 中文注释。
    padded = bits + "0" * ((8 - len(bits) % 8) % 8)
    return bytes(int(padded[i : i + 8], 2) for i in range(0, len(padded), 8))


def pack_covert_header(
    strategy_id: int,
    path_id: int,
    sequence_number: int,
    total_fragments: int = 1,
    is_redundant: bool = False,
) -> bytes:
    """
    pack_covert_header 函数。
    """
    header = struct.pack(
        "!BHBBB",
        (strategy_id << 5) | (path_id << 1) | 0,  # 中文注释。
        sequence_number & 0xFFFF,  # 中文注释。
        total_fragments & 0xFF,  # 中文注释。
        0xFE | (1 if is_redundant else 0),  # 中文注释。
        0x00,  # 中文注释。
    )
    return header


def unpack_covert_header(header: bytes) -> dict:
    """
    unpack_covert_header 函数。
    """
    if len(header) < 6:
        raise ValueError(f"Header too short: {len(header)} bytes, need 6")

    b0, seq, total, flags, _ = struct.unpack("!BHBBB", header[:6])
    return {
        "strategy_id": (b0 >> 5) & 0x07,
        "path_id": (b0 >> 1) & 0x0F,
        "sequence_number": seq,
        "total_fragments": total,
        "is_redundant": bool(flags & 0x01),
    }


def split_data(data: bytes, chunk_size: int) -> List[bytes]:
    """split_data 函数。"""
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b"\x00" * (chunk_size - len(chunk))
        chunks.append(chunk)
    return chunks


def reassemble_data(chunks: List[bytes], original_length: int) -> bytes:
    """reassemble_data 函数。"""
    data = b"".join(chunks)
    return data[:original_length]
