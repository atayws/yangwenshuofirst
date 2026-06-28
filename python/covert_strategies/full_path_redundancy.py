"""
策略4：IP-ID 喷泉码多路径协同隐蔽传输。

该策略把 IPv4 Identification 字段作为轻量承载位：
flag + strategy_id + frame_id + symbol_id + encrypted coded_nibble。
发送端生成喷泉码符号，P4 通过内部轮询或加权轮询分发到多条链路；接收端不关心路径，
只要在每个 frame 中收到足够多独立符号，就可以恢复原始隐蔽数据。
"""

import hashlib
import math
import random
import zlib
from typing import Dict, List, Optional, Tuple

from .base import CovertStrategy, PacketSpec, StrategyMetrics, PathState, StrategyID
from .strategy_registry import register_strategy


STRATEGY4_VALID_MASK = 0x8000
STRATEGY4_STRATEGY_SHIFT = 12
STRATEGY4_FRAME_SHIFT = 8
STRATEGY4_SYMBOL_SHIFT = 4
STRATEGY4_VALUE_MASK = 0x000F
STRATEGY4_MAX_FRAMES = 16
STRATEGY4_MAX_SYMBOLS = 16
FRAME_MAGIC = b"F4"
FRAME_HEADER_BYTES = 8


@register_strategy
class FullPathRedundancyStrategy(CovertStrategy):
    """策略4：IP-ID 喷泉码多路径协同隐蔽传输。"""

    strategy_id = StrategyID.FULL_PATH_REDUNDANCY
    name = "full_path_redundancy"
    description = (
        "IP-ID 喷泉码多路径协同：IP ID 携带 frame/symbol/4bit 编码符号，"
        "P4 通过内部加权轮询跨两条或三条链路分发，接收端收到足够多符号即可解码。"
    )

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self._k = int(self._config.get("k", 12))
        self._num_output = int(self._config.get("num_output", 16))
        self._payload_len = int(self._config.get("business_payload_len", 32))
        self._path_weights = self._normalize_weights(self._config.get("path_weights", [1, 1, 1]))
        key = self._config.get("secret_key", b"low-altitude-ipid-fountain-v1")
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._secret_key = key

        self._k = max(2, min(self._k, 15))
        self._num_output = max(self._k, min(self._num_output, STRATEGY4_MAX_SYMBOLS))
        self.last_decode_info: Dict[str, object] = {}

    def encode(
        self, data: bytes, path_id: int = 0, seq_num: int = 0
    ) -> List[PacketSpec]:
        """把隐蔽数据编码成一组带 IP-ID 喷泉码符号的业务包。"""
        framed = self._build_frame_payload(data)
        source_nibbles = self._bytes_to_nibbles(framed)
        total_frames = math.ceil(len(source_nibbles) / self._k)
        if total_frames > STRATEGY4_MAX_FRAMES:
            max_bytes = (STRATEGY4_MAX_FRAMES * self._k) // 2 - FRAME_HEADER_BYTES
            raise ValueError(f"策略4当前 IP-ID 帧号只有4 bit，单次最多承载约 {max_bytes} 字节")

        packets: List[PacketSpec] = []
        packet_counter = 0
        for frame_id in range(total_frames):
            start = frame_id * self._k
            source = list(source_nibbles[start:start + self._k])
            if len(source) < self._k:
                source.extend([0] * (self._k - len(source)))

            for symbol_id in range(self._num_output):
                indices = self._indices_for_symbol(frame_id, symbol_id)
                coded_nibble = 0
                for idx in indices:
                    coded_nibble ^= source[idx]
                cipher_nibble = coded_nibble ^ self._nibble_mask(frame_id, symbol_id)
                ip_id = self._pack_ip_id(frame_id, symbol_id, cipher_nibble)
                assigned_path = self._weighted_path(packet_counter)
                payload = self._build_business_payload(seq_num, frame_id, symbol_id, packet_counter)

                packets.append(
                    PacketSpec(
                        payload=payload,
                        sequence_num=seq_num,
                        fragment_id=packet_counter,
                        total_fragments=total_frames * self._num_output,
                        is_redundant=symbol_id >= self._k,
                        ip_id_field=ip_id,
                        path_id=assigned_path,
                        strategy_id=int(self.strategy_id),
                    )
                )
                packet_counter += 1

        self._bytes_encoded += len(data)
        return packets

    def decode(
        self,
        packets: List[bytes],
        metadata: Optional[List[dict]] = None,
    ) -> Optional[bytes]:
        """从 IP-ID 候选包中收集喷泉码符号并恢复原始隐蔽数据。"""
        if metadata is None:
            self.last_decode_info = {"complete": False, "reason": "缺少 IP-ID 元数据"}
            return None

        frame_symbols: Dict[int, Dict[int, int]] = {}
        candidate_packets = 0
        for meta in metadata:
            ip_id = meta.get("ip_id")
            if ip_id is None:
                continue
            parsed = self._unpack_ip_id(int(ip_id))
            if parsed is None:
                continue
            candidate_packets += 1
            frame_id = parsed["frame_id"]
            symbol_id = parsed["symbol_id"]
            coded_nibble = parsed["cipher_nibble"] ^ self._nibble_mask(frame_id, symbol_id)
            frame_symbols.setdefault(frame_id, {})[symbol_id] = coded_nibble & 0x0F

        if not frame_symbols:
            self.last_decode_info = {"complete": False, "reason": "没有策略4候选包"}
            return None

        decoded_nibbles: List[int] = []
        decoded_frames: List[int] = []
        expected_frames: Optional[int] = None
        original_len: Optional[int] = None
        crc_expected: Optional[int] = None
        failed_frames: List[int] = []

        for frame_id in range(STRATEGY4_MAX_FRAMES):
            source = self._decode_frame(frame_id, frame_symbols.get(frame_id, {}))
            if source is None:
                failed_frames.append(frame_id)
                if expected_frames is not None and frame_id < expected_frames:
                    self.last_decode_info = self._decode_failure(candidate_packets, decoded_frames, failed_frames, "frame 解码失败")
                    return None
                break

            decoded_nibbles.extend(source)
            decoded_frames.append(frame_id)
            decoded_bytes = self._nibbles_to_bytes(decoded_nibbles)

            if original_len is None and len(decoded_bytes) >= FRAME_HEADER_BYTES:
                if decoded_bytes[:2] != FRAME_MAGIC:
                    self.last_decode_info = self._decode_failure(candidate_packets, decoded_frames, failed_frames, "帧头 magic 错误")
                    return None
                original_len = int.from_bytes(decoded_bytes[2:4], "big")
                crc_expected = int.from_bytes(decoded_bytes[4:8], "big")
                total_nibbles = (FRAME_HEADER_BYTES + original_len) * 2
                expected_frames = math.ceil(total_nibbles / self._k)
                if expected_frames > STRATEGY4_MAX_FRAMES:
                    self.last_decode_info = self._decode_failure(candidate_packets, decoded_frames, failed_frames, "frame 数超过4bit范围")
                    return None

            if expected_frames is not None and len(decoded_frames) >= expected_frames:
                break

        if expected_frames is None or original_len is None or crc_expected is None:
            self.last_decode_info = self._decode_failure(candidate_packets, decoded_frames, failed_frames, "未能解析完整帧头")
            return None

        if len(decoded_frames) < expected_frames:
            self.last_decode_info = self._decode_failure(candidate_packets, decoded_frames, failed_frames, "可解码 frame 数不足")
            return None

        framed = self._nibbles_to_bytes(decoded_nibbles)[:FRAME_HEADER_BYTES + original_len]
        payload = framed[FRAME_HEADER_BYTES:]
        crc_actual = zlib.crc32(payload) & 0xFFFFFFFF
        if crc_actual != crc_expected:
            self.last_decode_info = self._decode_failure(candidate_packets, decoded_frames, failed_frames, "CRC 校验失败")
            return None

        self._bytes_decoded += len(payload)
        self.last_decode_info = {
            "scheme": "strategy4-ipid-fountain-v1",
            "complete": True,
            "candidate_packets": candidate_packets,
            "decoded_frames": decoded_frames,
            "expected_frames": expected_frames,
            "failed_frames": failed_frames,
            "k": self._k,
            "num_output": self._num_output,
            "decoded_bytes": len(payload),
        }
        return payload

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """估计当前网络状态下该策略的性能指标。"""
        redundancy_ratio = self._num_output / max(1, self._k)
        capacity = (4.0 * self._k / self._num_output) * 80.0
        if network_state.loss_rate <= 0.10:
            reliability = 0.96
        elif network_state.loss_rate <= 0.30:
            reliability = max(0.72, 0.96 - network_state.loss_rate * 0.8)
        else:
            reliability = max(0.25, 0.82 - network_state.loss_rate * 1.4)

        covertness = 0.70
        if network_state.bw_utilization > 0.75:
            covertness = 0.78

        return StrategyMetrics(
            covertness_score=covertness,
            capacity_bps=capacity / redundancy_ratio,
            reliability_score=max(0.0, min(1.0, reliability)),
            delay_tolerance_ms=600.0,
            loss_tolerance=0.35,
        )

    def _decode_frame(self, frame_id: int, symbols: Dict[int, int]) -> Optional[List[int]]:
        """用 GF(2) 高斯消元恢复单个 frame 的 K 个4bit源符号。"""
        if len(symbols) < self._k:
            return None

        basis_mask: Dict[int, int] = {}
        basis_value: Dict[int, int] = {}
        for symbol_id, coded_nibble in sorted(symbols.items()):
            indices = self._indices_for_symbol(frame_id, symbol_id)
            mask = 0
            for idx in indices:
                mask |= 1 << idx
            value = coded_nibble & 0x0F

            while mask:
                pivot = (mask & -mask).bit_length() - 1
                if pivot not in basis_mask:
                    basis_mask[pivot] = mask
                    basis_value[pivot] = value
                    break
                mask ^= basis_mask[pivot]
                value ^= basis_value[pivot]

            if len(basis_mask) >= self._k:
                break

        if len(basis_mask) < self._k:
            return None

        solution = [0] * self._k
        for pivot in sorted(basis_mask.keys(), reverse=True):
            mask = basis_mask[pivot]
            value = basis_value[pivot]
            rest = mask & ~(1 << pivot)
            while rest:
                lsb = rest & -rest
                idx = lsb.bit_length() - 1
                value ^= solution[idx]
                rest ^= lsb
            solution[pivot] = value & 0x0F
        return solution

    def _indices_for_symbol(self, frame_id: int, symbol_id: int) -> List[int]:
        """根据 frame_id 和 symbol_id 确定该喷泉符号连接的源符号集合。"""
        if symbol_id < self._k:
            return [symbol_id]

        if self._k <= 4:
            # 小 frame 使用固定组合表，避免随机符号在高丢包下秩不足。
            return self._small_frame_indices(symbol_id)

        material = self._secret_key + b"idx" + bytes([frame_id & 0x0F, symbol_id & 0x0F, self._k & 0x0F])
        seed = int.from_bytes(hashlib.blake2s(material, digest_size=4).digest(), "big")
        rng = random.Random(seed)
        max_degree = min(self._k, 5)
        degree = 2 + (seed % max(1, max_degree - 1))
        degree = min(degree, self._k)
        return sorted(rng.sample(range(self._k), degree))

    def _small_frame_indices(self, symbol_id: int) -> List[int]:
        """为小 frame 生成固定高秩组合，提升策略4在丢包链路上的可解码概率。"""
        max_mask = (1 << self._k) - 1
        masks = [1 << idx for idx in range(self._k)]
        masks.extend(mask for mask in range(1, max_mask + 1) if mask not in masks)
        mask = masks[symbol_id % len(masks)]
        return [idx for idx in range(self._k) if (mask & (1 << idx)) != 0]

    def _pack_ip_id(self, frame_id: int, symbol_id: int, cipher_nibble: int) -> int:
        return (
            STRATEGY4_VALID_MASK
            | ((int(self.strategy_id) & 0x07) << STRATEGY4_STRATEGY_SHIFT)
            | ((frame_id & 0x0F) << STRATEGY4_FRAME_SHIFT)
            | ((symbol_id & 0x0F) << STRATEGY4_SYMBOL_SHIFT)
            | (cipher_nibble & STRATEGY4_VALUE_MASK)
        )

    def _unpack_ip_id(self, ip_id: int) -> Optional[dict]:
        if (ip_id & STRATEGY4_VALID_MASK) == 0:
            return None
        strategy_id = (ip_id >> STRATEGY4_STRATEGY_SHIFT) & 0x07
        if strategy_id != int(self.strategy_id):
            return None
        return {
            "strategy_id": strategy_id,
            "frame_id": (ip_id >> STRATEGY4_FRAME_SHIFT) & 0x0F,
            "symbol_id": (ip_id >> STRATEGY4_SYMBOL_SHIFT) & 0x0F,
            "cipher_nibble": ip_id & STRATEGY4_VALUE_MASK,
        }

    def _nibble_mask(self, frame_id: int, symbol_id: int) -> int:
        material = self._secret_key + b"mask" + bytes([frame_id & 0x0F, symbol_id & 0x0F])
        return hashlib.blake2s(material, digest_size=1).digest()[0] & 0x0F

    def _build_frame_payload(self, data: bytes) -> bytes:
        if len(data) > 0xFFFF:
            raise ValueError("策略4单帧批次暂不支持超过 65535 字节")
        return FRAME_MAGIC + len(data).to_bytes(2, "big") + (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big") + data

    def _build_business_payload(self, seq_num: int, frame_id: int, symbol_id: int, packet_counter: int) -> bytes:
        length = max(1, self._payload_len)
        material = (
            self._secret_key
            + b"payload"
            + bytes([seq_num & 0xFF, frame_id & 0x0F, symbol_id & 0x0F])
            + int(packet_counter & 0xFFFFFFFF).to_bytes(4, "big")
        )
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(hashlib.blake2s(material + counter.to_bytes(2, "big"), digest_size=32).digest())
            counter += 1
        return bytes(output[:length])

    def _weighted_path(self, packet_counter: int) -> int:
        total = sum(self._path_weights)
        if total <= 0:
            return 0
        pos = packet_counter % total
        acc = 0
        for path_id, weight in enumerate(self._path_weights):
            acc += weight
            if pos < acc:
                return path_id
        return 0

    @staticmethod
    def _normalize_weights(raw_weights) -> List[int]:
        weights = [0, 0, 0]
        if raw_weights is None:
            return [1, 1, 1]
        for idx, value in enumerate(list(raw_weights)[:3]):
            weights[idx] = max(0, int(value))
        if sum(weights) == 0:
            return [1, 1, 1]
        return weights

    @staticmethod
    def _bytes_to_nibbles(data: bytes) -> List[int]:
        nibbles: List[int] = []
        for value in data:
            nibbles.append((value >> 4) & 0x0F)
            nibbles.append(value & 0x0F)
        return nibbles

    @staticmethod
    def _nibbles_to_bytes(nibbles: List[int]) -> bytes:
        values = list(nibbles)
        if len(values) % 2:
            values.append(0)
        output = bytearray()
        for index in range(0, len(values), 2):
            output.append(((values[index] & 0x0F) << 4) | (values[index + 1] & 0x0F))
        return bytes(output)

    def _decode_failure(self, candidate_packets: int, decoded_frames: List[int], failed_frames: List[int], reason: str) -> dict:
        return {
            "scheme": "strategy4-ipid-fountain-v1",
            "complete": False,
            "reason": reason,
            "candidate_packets": candidate_packets,
            "decoded_frames": decoded_frames,
            "failed_frames": failed_frames,
            "k": self._k,
            "num_output": self._num_output,
        }
