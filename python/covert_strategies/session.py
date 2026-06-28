"""
全局隐蔽会话切块与重组。

该层位于具体策略之上。发送端先把原始隐蔽数据切成带编号的 chunk，再把
每个 chunk 交给策略0/1/2/3/4/5之一发送；接收端先由策略分发器恢复出 chunk，
再按 chunk_id 重组为最终隐蔽数据。
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import struct
from typing import Dict, Iterable, List, Optional, Tuple
import zlib


SESSION_MAGIC = b"CS"
SESSION_VERSION = 1
SESSION_HEADER_FORMAT = "!2sBBHHHHI"
SESSION_HEADER_LEN = struct.calcsize(SESSION_HEADER_FORMAT)


@dataclass(frozen=True)
class CovertChunk:
    """一段带全局顺序信息的隐蔽数据块。"""

    session_id: int
    chunk_id: int
    total_chunks: int
    payload: bytes

    def encode(self) -> bytes:
        """把 chunk 编成可交给任意策略发送的字节串。"""
        payload_len = len(self.payload)
        crc = zlib.crc32(self.payload) & 0xFFFFFFFF
        header = struct.pack(
            SESSION_HEADER_FORMAT,
            SESSION_MAGIC,
            SESSION_VERSION,
            self.session_id & 0xFF,
            self.chunk_id & 0xFFFF,
            self.total_chunks & 0xFFFF,
            payload_len & 0xFFFF,
            SESSION_HEADER_LEN,
            crc,
        )
        return header + self.payload


@dataclass
class ParsedChunk:
    """接收端解析出的有效 chunk。"""

    session_id: int
    chunk_id: int
    total_chunks: int
    payload: bytes
    crc: int


@dataclass
class AssemblyResult:
    """一次全局重组结果。"""

    success: bool
    complete: bool
    session_id: Optional[int]
    decoded: Optional[bytes]
    received_chunks: int
    total_chunks: Optional[int]
    missing_chunks: List[int]
    duplicate_chunks: int
    invalid_chunks: int
    reason: str

    def to_dict(self) -> dict:
        """转换成 JSON 友好的摘要。"""
        return {
            "success": self.success,
            "complete": self.complete,
            "session_id": self.session_id,
            "decoded_bytes": len(self.decoded) if self.decoded is not None else 0,
            "received_chunks": self.received_chunks,
            "total_chunks": self.total_chunks,
            "missing_chunks": self.missing_chunks,
            "duplicate_chunks": self.duplicate_chunks,
            "invalid_chunks": self.invalid_chunks,
            "reason": self.reason,
        }


class CovertSessionFramer:
    """发送端全局切块器。"""

    def __init__(self, session_id: int = 1, chunk_payload_size: int = 8):
        self.session_id = int(session_id) & 0xFF
        self.chunk_payload_size = max(1, int(chunk_payload_size))

    def split(self, data: bytes) -> List[CovertChunk]:
        """按固定 payload 大小切分原始隐蔽数据。"""
        total_chunks = max(1, math.ceil(len(data) / self.chunk_payload_size))
        chunks: List[CovertChunk] = []
        for chunk_id in range(total_chunks):
            start = chunk_id * self.chunk_payload_size
            payload = data[start : start + self.chunk_payload_size]
            chunks.append(
                CovertChunk(
                    session_id=self.session_id,
                    chunk_id=chunk_id,
                    total_chunks=total_chunks,
                    payload=payload,
                )
            )
        return chunks


class CovertSessionAssembler:
    """接收端全局重组器。"""

    def __init__(self):
        self._chunks: Dict[Tuple[int, int], ParsedChunk] = {}
        self._total_chunks: Dict[int, int] = {}
        self.duplicate_chunks = 0
        self.invalid_chunks = 0
        self.invalid_reasons: List[str] = []

    def add_decoded_payload(self, payload: Optional[bytes]) -> Optional[ParsedChunk]:
        """把某个策略 decode() 输出的 payload 加入全局重组缓冲。"""
        if payload is None:
            return None
        parsed = parse_chunk(payload)
        if parsed is None:
            self.invalid_chunks += 1
            self.invalid_reasons.append("chunk帧头或CRC校验失败")
            return None

        key = (parsed.session_id, parsed.chunk_id)
        if key in self._chunks:
            self.duplicate_chunks += 1
            return parsed

        known_total = self._total_chunks.get(parsed.session_id)
        if known_total is not None and known_total != parsed.total_chunks:
            self.invalid_chunks += 1
            self.invalid_reasons.append("同一session内total_chunks不一致")
            return None

        self._total_chunks[parsed.session_id] = parsed.total_chunks
        self._chunks[key] = parsed
        return parsed

    def add_many(self, payloads: Iterable[Optional[bytes]]) -> List[ParsedChunk]:
        """批量加入策略解码结果。"""
        parsed_chunks: List[ParsedChunk] = []
        for payload in payloads:
            parsed = self.add_decoded_payload(payload)
            if parsed is not None:
                parsed_chunks.append(parsed)
        return parsed_chunks

    def assemble(self, session_id: Optional[int] = None) -> AssemblyResult:
        """按 chunk_id 顺序重组指定 session。"""
        if session_id is None:
            session_id = self._select_session_id()
        if session_id is None:
            return AssemblyResult(
                success=False,
                complete=False,
                session_id=None,
                decoded=None,
                received_chunks=0,
                total_chunks=None,
                missing_chunks=[],
                duplicate_chunks=self.duplicate_chunks,
                invalid_chunks=self.invalid_chunks,
                reason="没有有效chunk",
            )

        total_chunks = self._total_chunks.get(session_id)
        if total_chunks is None:
            return AssemblyResult(
                success=False,
                complete=False,
                session_id=session_id,
                decoded=None,
                received_chunks=0,
                total_chunks=None,
                missing_chunks=[],
                duplicate_chunks=self.duplicate_chunks,
                invalid_chunks=self.invalid_chunks,
                reason="缺少total_chunks",
            )

        missing = [
            chunk_id
            for chunk_id in range(total_chunks)
            if (session_id, chunk_id) not in self._chunks
        ]
        received = total_chunks - len(missing)
        if missing:
            return AssemblyResult(
                success=False,
                complete=False,
                session_id=session_id,
                decoded=None,
                received_chunks=received,
                total_chunks=total_chunks,
                missing_chunks=missing,
                duplicate_chunks=self.duplicate_chunks,
                invalid_chunks=self.invalid_chunks,
                reason="chunk未收齐",
            )

        decoded = b"".join(
            self._chunks[(session_id, chunk_id)].payload
            for chunk_id in range(total_chunks)
        )
        return AssemblyResult(
            success=True,
            complete=True,
            session_id=session_id,
            decoded=decoded,
            received_chunks=received,
            total_chunks=total_chunks,
            missing_chunks=[],
            duplicate_chunks=self.duplicate_chunks,
            invalid_chunks=self.invalid_chunks,
            reason="重组成功",
        )

    def _select_session_id(self) -> Optional[int]:
        if not self._total_chunks:
            return None
        return sorted(self._total_chunks.keys())[0]


def parse_chunk(data: bytes) -> Optional[ParsedChunk]:
    """解析并校验一个全局 chunk。"""
    if len(data) < SESSION_HEADER_LEN:
        return None
    try:
        (
            magic,
            version,
            session_id,
            chunk_id,
            total_chunks,
            payload_len,
            header_len,
            crc,
        ) = struct.unpack(SESSION_HEADER_FORMAT, data[:SESSION_HEADER_LEN])
    except struct.error:
        return None

    if magic != SESSION_MAGIC or version != SESSION_VERSION:
        return None
    if header_len != SESSION_HEADER_LEN:
        return None
    if total_chunks == 0 or chunk_id >= total_chunks:
        return None
    end = header_len + payload_len
    if end > len(data):
        return None

    payload = data[header_len:end]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        return None
    return ParsedChunk(
        session_id=session_id,
        chunk_id=chunk_id,
        total_chunks=total_chunks,
        payload=payload,
        crc=crc,
    )
