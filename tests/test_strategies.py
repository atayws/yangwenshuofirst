"""
隐蔽策略单元测试。
"""

import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from python.covert_strategies.base import StrategyID, PathState
from python.covert_strategies.full_path_redundancy import FullPathRedundancyStrategy
from python.covert_strategies.ip_id_codec import IPIDCodec
from python.covert_strategies.path_sequence import PathSequenceStrategy
from python.covert_strategies.protocol_high_reliability import ProtocolHighReliabilityStrategy
from python.covert_strategies.session import (
    CovertSessionAssembler,
    CovertSessionFramer,
    parse_chunk,
)
from python.covert_strategies.statistical_fusion import StatisticalFusionStrategy
from python.covert_strategies.strategy_registry import get_strategy, list_available
from python.covert_strategies.timing_high_capacity import TimingHighCapacityStrategy
from python.covert_strategies.timing_high_covert import TimingHighCovertStrategy
from experiments.udp_covert_proxy import parse_proxy_tag
from experiments.live_manual_policy_receiver import Strategy2FragmentTracker
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


def build_timing_metadata(packets):
    """根据发送计划构造理想接收时间戳。"""
    metadata = []
    current = 0.0
    for pkt in packets:
        if metadata:
            current += pkt.send_delay_ms
        metadata.append({"arrival_time_ms": current})
    return metadata


class TestIPIDCodec(unittest.TestCase):
    """测试IP ID字段编解码。"""

    def setUp(self):
        self.codec = IPIDCodec()

    def test_pack_unpack_roundtrip(self):
        ip_id = self.codec.pack_ip_id(strategy_id=2, path_id=1, data_byte=0x41)
        info = self.codec.unpack_ip_id(ip_id)

        self.assertTrue(info["covert_valid"])
        self.assertTrue(info["tag_valid"])
        self.assertEqual(info["strategy_id"], 2)
        self.assertEqual(info["path_id"], 1)
        self.assertEqual(info["data_byte"], 0x41)

    def test_payload_is_encrypted(self):
        ip_id = self.codec.pack_ip_id(2, 0, 0xFF, nonce=7)
        info = self.codec.unpack_ip_id(ip_id, nonce=7)
        self.assertNotEqual(info["cipher_byte"], 0xFF)
        self.assertEqual(info["data_byte"], 0xFF)

    def test_plain_ip_id_is_not_covert(self):
        info = self.codec.unpack_ip_id(0x1234)
        self.assertFalse(info["covert_valid"])
        self.assertIsNone(info["data_byte"])

    def test_encode_decode_stream(self):
        data = b"HELLO"
        ip_ids = self.codec.encode_stream(data, strategy_id=2, path_id=0)
        decoded, meta = self.codec.decode_stream(ip_ids)

        self.assertEqual(decoded, data)
        self.assertEqual(len(meta), len(data))

    def test_all_strategy_ids(self):
        for sid in range(6):
            ip_id = self.codec.pack_ip_id(sid, 0, 0x00)
            info = self.codec.unpack_ip_id(ip_id)
            self.assertEqual(info["strategy_id"], sid)


class TestTimingHighCovert(unittest.TestCase):
    """测试策略0：高隐蔽相对时序。"""

    def setUp(self):
        self.strategy = TimingHighCovertStrategy()

    def test_encode(self):
        packets = self.strategy.encode(b"A", path_id=0, seq_num=1)
        self.assertGreater(len(packets), 0)
        self.assertEqual(packets[0].send_delay_ms, 0.0)
        for pkt in packets:
            self.assertEqual(pkt.strategy_id, 0)
        self.assertEqual(len(packets), 11)
        times = [item["arrival_time_ms"] for item in build_timing_metadata(packets)]
        score0 = self.strategy._window_score(times[0:4])
        score1 = self.strategy._window_score(times[1:5])
        self.assertLess(score0, -self.strategy._decision_threshold_ms)
        self.assertGreater(score1, self.strategy._decision_threshold_ms)

    def test_decode_with_perfect_timing(self):
        data = b"AB"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        decoded = self.strategy.decode(
            [p.payload for p in packets],
            build_timing_metadata(packets),
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_scheme_b_resync_after_one_lost_packet(self):
        data = b"\xff"
        strategy = TimingHighCovertStrategy(config={"expected_bytes": len(data)})
        packets = strategy.encode(data, path_id=0, seq_num=1)
        metadata_all = build_timing_metadata(packets)

        received = []
        metadata = []
        lost_fragment_id = 4
        for pkt, meta in zip(packets, metadata_all):
            if pkt.fragment_id == lost_fragment_id:
                continue
            received.append(pkt.payload)
            metadata.append(meta)

        decoded = strategy.decode(received, metadata)
        self.assertIsNotNone(decoded)
        self.assertEqual(len(decoded), len(data))
        self.assertFalse(strategy.last_decode_info["complete"])
        self.assertTrue({1, 2, 3, 4}.intersection(strategy.last_decode_info["unknown_bits"]))

    def test_metrics_good_path(self):
        good_path = PathState(path_id=0, delay_ms=5, jitter_ms=2, loss_rate=0.001, bw_utilization=0.3)
        metrics = self.strategy.get_metrics(good_path)
        self.assertGreater(metrics.covertness_score, 0.8)
        self.assertGreater(metrics.reliability_score, 0.7)

    def test_metrics_bad_path(self):
        bad_path = PathState(path_id=0, delay_ms=50, jitter_ms=25, loss_rate=0.05, bw_utilization=0.7)
        metrics = self.strategy.get_metrics(bad_path)
        self.assertLess(metrics.reliability_score, 0.7)


class TestTimingHighCapacity(unittest.TestCase):
    """测试策略1：高容量排序时序。"""

    def setUp(self):
        self.strategy = TimingHighCapacityStrategy()

    def test_encode_4_levels(self):
        data = bytes([0b00011011, 0b10000001])
        packets = self.strategy.encode(data, path_id=0, seq_num=1)

        self.assertEqual(packets[0].send_delay_ms, 0.0)
        self.assertEqual(len(packets), 11)
        times = [item["arrival_time_ms"] for item in build_timing_metadata(packets)]
        symbols = [
            self.strategy._classify_score(self.strategy._window_score(times[index : index + 4]))
            for index in range(4)
        ]
        self.assertEqual(symbols, [0b00, 0b01, 0b10, 0b11])

    def test_decode_perfect(self):
        data = b"XY"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        decoded = self.strategy.decode(
            [p.payload for p in packets],
            build_timing_metadata(packets),
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_scheme_b_resync_after_one_lost_packet(self):
        data = b"\xff"
        strategy = TimingHighCapacityStrategy(config={"expected_bytes": len(data)})
        packets = strategy.encode(data, path_id=0, seq_num=1)
        metadata_all = build_timing_metadata(packets)

        received = []
        metadata = []
        lost_fragment_id = 4
        for pkt, meta in zip(packets, metadata_all):
            if pkt.fragment_id == lost_fragment_id:
                continue
            received.append(pkt.payload)
            metadata.append(meta)

        decoded = strategy.decode(received, metadata)
        self.assertIsNotNone(decoded)
        self.assertEqual(len(decoded), len(data))
        self.assertFalse(strategy.last_decode_info["complete"])
        self.assertTrue({1, 2, 3, 4}.intersection(strategy.last_decode_info["unknown_symbols"]))

    def test_missing_first_packet_marks_local_windows_unknown(self):
        """接收端启动时如果漏掉anchor，首个符号仍可由窗口内部间隔推断。"""
        data = b"\xbd"
        strategy = TimingHighCapacityStrategy(config={"expected_bytes": len(data)})
        packets = strategy.encode(data, path_id=0, seq_num=1)
        metadata_all = build_timing_metadata(packets)

        received = []
        metadata = []
        for pkt, meta in zip(packets, metadata_all):
            if pkt.fragment_id == 0:
                continue
            received.append(pkt.payload)
            metadata.append(meta)

        decoded = strategy.decode(received, metadata)
        self.assertIsNotNone(decoded)
        self.assertEqual(len(decoded), len(data))
        self.assertFalse(strategy.last_decode_info["complete"])
        self.assertIn(0, strategy.last_decode_info["unknown_symbols"])


class TestProtocolHighReliability(unittest.TestCase):
    """测试策略2：可靠 IP-ID 存储信道。"""

    def setUp(self):
        self.strategy = ProtocolHighReliabilityStrategy()

    def _metadata(self, packets):
        return [
            {"ip_id": p.ip_id_field, "fragment_id": p.fragment_id}
            for p in packets
        ]

    def test_encode(self):
        packets = self.strategy.encode(b"TEST_DATA_16B!", path_id=0, seq_num=1)
        self.assertGreater(len(packets), 0)
        for pkt in packets:
            self.assertIsNotNone(pkt.ip_id_field)
            self.assertEqual((pkt.ip_id_field >> 12) & 0x07, 2)

    def test_decode(self):
        data = b"HELLO_WORLD_1234"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)

        decoded = self.strategy.decode(
            [p.payload for p in packets],
            self._metadata(packets),
        )
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_decode_out_of_order(self):
        data = b"OUT_OF_ORDER_IPID_BLOCK_TEST_1234567890"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        shuffled = list(reversed(packets[3::4] + packets[1::4] + packets[::4] + packets[2::4]))

        decoded = self.strategy.decode(
            [p.payload for p in shuffled],
            self._metadata(shuffled),
        )
        self.assertEqual(decoded, data)

    def test_live_fragment_tracker_handles_repeats_and_wrap(self):
        data = b"LIVE_FRAGMENT_TRACKER_OK"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        tracker = Strategy2FragmentTracker()
        metadata = []
        inferred = []

        for pkt in packets:
            fragment_id = tracker.infer(chunk_id=0, ip_id=pkt.ip_id_field)
            inferred.append(fragment_id)
            metadata.append({"ip_id": pkt.ip_id_field, "fragment_id": fragment_id})

        self.assertEqual(inferred[:6], [0, 0, 0, 1, 1, 1])
        self.assertEqual(inferred[45:51], [15, 15, 15, 16, 16, 16])

        decoded = self.strategy.decode([p.payload for p in packets], metadata)
        self.assertEqual(decoded, data)

    def test_decode_recovers_one_loss_per_xor_group(self):
        data = b"LOSS_RECOVERY_WITH_XOR_PARITY_1234567890"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        dropped_seq = {2, 6, 10}
        received = [p for p in packets if not (p.fragment_id // 16 == 0 and p.fragment_id % 16 in dropped_seq)]

        decoded = self.strategy.decode(
            [p.payload for p in received],
            self._metadata(received),
        )
        self.assertEqual(decoded, data)
        recovered = self.strategy.last_decode_info["recovered_by_parity"]
        self.assertEqual(sorted(recovered[0]), [2, 6, 10])

    def test_block_auth_rejects_corrupted_value(self):
        data = b"AUTH_REJECTS_CORRUPTION"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        meta = self._metadata(packets)
        meta[3] = dict(meta[3])
        meta[3]["ip_id"] ^= 0x0001

        decoded = self.strategy.decode([p.payload for p in packets], meta)
        self.assertIsNone(decoded)
        self.assertFalse(self.strategy.last_decode_info["complete"])

    def test_metrics_tolerates_loss(self):
        path = PathState(path_id=0, delay_ms=10, jitter_ms=5, loss_rate=0.05, bw_utilization=0.4)
        metrics = self.strategy.get_metrics(path)
        self.assertGreater(metrics.loss_tolerance, 0.2)
        self.assertGreater(metrics.reliability_score, 0.8)


class TestRuleBasedPolicySelector(unittest.TestCase):
    """测试阶段二规则策略选择器。"""

    def test_selects_stable_and_lossy_paths(self):
        selector = RuleBasedPolicySelector()
        plan = selector.select(
            {
                0: {"delay_ms": 5.0, "jitter_ms": 0.2, "loss_rate": 0.0, "bw_utilization": 0.1},
                1: {"delay_ms": 15.0, "jitter_ms": 0.5, "loss_rate": 0.08, "bw_utilization": 0.2},
                2: {"delay_ms": 30.0, "jitter_ms": 12.0, "loss_rate": 0.02, "bw_utilization": 0.3},
            }
        )

        single_path = [entry for entry in plan if entry.strategy_id != 4]
        by_path = {entry.paths[0]: entry.strategy_id for entry in single_path}
        self.assertEqual(by_path[0], 3)
        self.assertEqual(by_path[1], 2)

        fountain = [entry for entry in plan if entry.strategy_id == 4]
        self.assertTrue(fountain)
        self.assertGreaterEqual(len(fountain[0].paths), 2)

    def test_fallback_plan_keeps_strategy4_multipath(self):
        selector = RuleBasedPolicySelector()
        plan = selector.select({})
        fountain = [entry for entry in plan if entry.strategy_id == 4]
        self.assertEqual(len(fountain), 1)
        self.assertGreaterEqual(len(fountain[0].paths), 2)


class TestStatisticalFusion(unittest.TestCase):
    """测试策略3：统计分布包长融合。"""

    def setUp(self):
        self.strategy = StatisticalFusionStrategy()

    def test_encode_lengths(self):
        data = bytes([0b00011011])
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        self.assertEqual(len(packets), 4 * self.strategy._repeat_count)
        for pkt in packets:
            self.assertIsNotNone(pkt.target_packet_length)
            self.assertIsNotNone(self.strategy._classify_packet_length(pkt.target_packet_length))
            self.assertNotEqual(pkt.payload[:2], b"S3")

    def test_decode_by_length(self):
        data = b"CD"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        decoded = self.strategy.decode([p.payload for p in packets])
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_decode_out_of_order(self):
        data = b"STATISTICAL_LENGTH_REORDER"
        packets = self.strategy.encode(data, path_id=0, seq_num=7)
        shuffled = list(reversed(packets[2::3] + packets[1::3] + packets[::3]))
        decoded = self.strategy.decode([p.payload for p in shuffled])
        self.assertEqual(decoded, data)

    def test_decode_after_losing_one_repeat_round(self):
        data = b"LOSS_OK_FOR_STRATEGY3"
        packets = self.strategy.encode(data, path_id=0, seq_num=3)
        total_symbols = len(data) * 4
        received = [p for p in packets if p.fragment_id >= total_symbols]
        decoded = self.strategy.decode([p.payload for p in received])
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_corrupted_tag_is_ignored(self):
        data = b"TAG_AUTH"
        packets = self.strategy.encode(data, path_id=0, seq_num=2)
        corrupted = bytearray(packets[0].payload)
        corrupted[0] ^= 0x7F
        tag = self.strategy._parse_tag(bytes(corrupted[:12]))
        self.assertIsNone(tag)



class TestFullPathRedundancy(unittest.TestCase):
    """测试策略4：IP-ID 喷泉码多路径协同。"""

    def setUp(self):
        self.strategy = FullPathRedundancyStrategy(config={"k": 8, "num_output": 16})

    def _metadata(self, packets):
        return [{"ip_id": p.ip_id_field} for p in packets]

    def test_encode_multiple_links_and_ip_id_layout(self):
        data = b"FULL_PATH_REDUNDANCY_TEST"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        self.assertGreater(len(packets), 0)
        link_ids = {p.path_id for p in packets}
        self.assertEqual(link_ids, {0, 1, 2})
        for pkt in packets:
            self.assertIsNotNone(pkt.ip_id_field)
            self.assertEqual((pkt.ip_id_field >> 12) & 0x07, 4)
            self.assertEqual((pkt.ip_id_field >> 15) & 0x01, 1)

    def test_decode_all_packets(self):
        data = b"TEST_DATA_FOR_IPID_FOUNTAIN"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        decoded = self.strategy.decode([p.payload for p in packets], self._metadata(packets))
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_decode_from_out_of_order_symbols(self):
        data = b"MIXED_LINK_DATA_FOR_TEST_123456"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        shuffled = list(reversed(packets[2::3] + packets[1::3] + packets[::3]))
        decoded = self.strategy.decode([p.payload for p in shuffled], self._metadata(shuffled))
        self.assertEqual(decoded, data)

    def test_decode_after_regular_packet_loss(self):
        data = b"LOSS_TOLERANT_FOUNTAIN"
        packets = self.strategy.encode(data, path_id=0, seq_num=2)
        received = [p for index, p in enumerate(packets) if index % 5 != 0]
        decoded = self.strategy.decode([p.payload for p in received], self._metadata(received))
        self.assertEqual(decoded, data)

    def test_two_path_weighted_mode(self):
        data = b"TWO_PATH_MODE"
        strategy = FullPathRedundancyStrategy(config={"k": 8, "num_output": 16, "path_weights": [1, 1, 0]})
        packets = strategy.encode(data, path_id=0, seq_num=3)
        self.assertEqual({p.path_id for p in packets}, {0, 1})
        decoded = strategy.decode([p.payload for p in packets], [{"ip_id": p.ip_id_field} for p in packets])
        self.assertEqual(decoded, data)

    def test_insufficient_packets(self):
        data = b"SHORT"
        packets = self.strategy.encode(data, path_id=0, seq_num=1)
        decoded = self.strategy.decode(
            [p.payload for p in packets[:4]],
            self._metadata(packets[:4]),
        )
        self.assertIsNone(decoded)

    def test_metrics_poor_links(self):
        poor_path = PathState(path_id=0, delay_ms=80, jitter_ms=30, loss_rate=0.15, bw_utilization=0.8)
        metrics = self.strategy.get_metrics(poor_path)
        self.assertGreater(metrics.reliability_score, 0.7)
        self.assertGreater(metrics.loss_tolerance, 0.25)


class TestPathSequence(unittest.TestCase):
    """测试策略5：多路径路径序列信道。"""

    def setUp(self):
        self.strategy = PathSequenceStrategy()

    def _metadata(self, packets):
        return [
            {"path_id": p.path_id, "fragment_id": p.fragment_id, "ip_id": p.ip_id_field}
            for p in packets
        ]

    def test_encode_uses_path_permutations(self):
        packets = self.strategy.encode(b"A", path_id=0, seq_num=1)
        self.assertEqual(len(packets) % 3, 0)
        self.assertEqual({p.path_id for p in packets[:12]}, {0, 1, 2})
        for pkt in packets:
            self.assertEqual(pkt.strategy_id, 5)
            self.assertIsNotNone(pkt.ip_id_field)
            parsed = self.strategy.parse_ip_id(pkt.ip_id_field)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed["strategy_id"], 5)
            self.assertEqual(parsed["path_id"], pkt.path_id)
            self.assertEqual(parsed["fragment_id_mod"], pkt.fragment_id & 0xFF)

    def test_decode_perfect_path_sequence(self):
        data = b"PATH_SEQUENCE_DATA"
        packets = self.strategy.encode(data, path_id=0, seq_num=2)
        decoded = self.strategy.decode([p.payload for p in packets], self._metadata(packets))
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_decode_out_of_order_with_fragment_id(self):
        data = b"REORDERED_PATH_SEQUENCE"
        packets = self.strategy.encode(data, path_id=0, seq_num=3)
        shuffled = list(reversed(packets[2::3] + packets[1::3] + packets[::3]))
        decoded = self.strategy.decode([p.payload for p in shuffled], self._metadata(shuffled))
        self.assertEqual(decoded, data)

    def test_decode_from_ip_id_metadata(self):
        data = b"IPID_PATH_SEQUENCE"
        packets = self.strategy.encode(data, path_id=0, seq_num=5)
        metadata = [{"ip_id": p.ip_id_field} for p in packets]
        decoded = self.strategy.decode([p.payload for p in packets], metadata)
        self.assertEqual(decoded, data)
        self.assertTrue(self.strategy.last_decode_info["complete"])

    def test_missing_one_window_marks_incomplete(self):
        data = b"LOSS_AFTER_HEADER"
        packets = self.strategy.encode(data, path_id=0, seq_num=4)
        dropped_window = 34
        received = [p for p in packets if p.fragment_id != dropped_window * 3 + 1]
        decoded = self.strategy.decode([p.payload for p in received], self._metadata(received))
        self.assertIsNotNone(decoded)
        self.assertFalse(self.strategy.last_decode_info["complete"])
        self.assertIn(dropped_window, self.strategy.last_decode_info["unknown_symbols"])

    def test_metrics_prefers_low_loss_links(self):
        metrics = self.strategy.get_metrics(
            PathState(path_id=0, delay_ms=10, jitter_ms=3, loss_rate=0.01, bw_utilization=0.4)
        )
        self.assertGreater(metrics.covertness_score, 0.8)
        self.assertGreater(metrics.reliability_score, 0.8)

class TestStrategyRegistry(unittest.TestCase):
    """测试策略注册表。"""

    def test_all_strategies_registered(self):
        available = list_available()
        self.assertEqual(len(available), 6)

        for sid in range(6):
            strategy = get_strategy(StrategyID(sid))
            self.assertEqual(int(strategy.strategy_id), sid)


class TestCovertSession(unittest.TestCase):
    """测试全局隐蔽会话切块和重组。"""

    def test_split_parse_and_assemble_out_of_order(self):
        data = b"GLOBAL_SESSION_LAYER_DATA"
        framer = CovertSessionFramer(session_id=9, chunk_payload_size=5)
        chunks = framer.split(data)
        assembler = CovertSessionAssembler()

        for chunk in reversed(chunks):
            parsed = assembler.add_decoded_payload(chunk.encode())
            self.assertIsNotNone(parsed)

        result = assembler.assemble()
        self.assertTrue(result.success)
        self.assertEqual(result.decoded, data)
        self.assertEqual(result.total_chunks, len(chunks))

    def test_corrupted_chunk_is_rejected(self):
        chunk = CovertSessionFramer(session_id=1, chunk_payload_size=8).split(b"ABCDEFGH")[0]
        corrupted = bytearray(chunk.encode())
        corrupted[-1] ^= 0x01

        self.assertIsNone(parse_chunk(bytes(corrupted)))


class TestUdpCovertProxyHelpers(unittest.TestCase):
    """测试UDP业务流代理的标签判定。"""

    def test_proxy_tag_accepts_current_frame(self):
        strategy = TimingHighCovertStrategy(config={"business_payload_len": 2})
        packet = strategy.encode(b"A", path_id=0, seq_num=7)[1]
        self.assertTrue(
            parse_proxy_tag(
                packet.payload + b"business",
                strategy_id=0,
                seq_num=7,
                expected_units=8,
                sync_key=0x5A17,
            )
        )

    def test_proxy_tag_rejects_plain_business_payload(self):
        self.assertFalse(
            parse_proxy_tag(
                b"plain iperf payload",
                strategy_id=0,
                seq_num=7,
                expected_units=8,
                sync_key=0x5A17,
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
