import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from python.control_plane.int_parser import HopSnapshot, IntReport, LinkMetricsCalculator
from python.control_plane.path_state_db import PathStateDB


def make_hop(
    swid,
    port_ingress,
    port_egress,
    count_ingress,
    count_egress,
    byte_ingress=0,
    byte_egress=0,
    curr_time_ingress=0,
    curr_time_egress=0,
):
    return HopSnapshot(
        swid=swid,
        port_ingress=port_ingress,
        port_egress=port_egress,
        byte_ingress=byte_ingress,
        byte_egress=byte_egress,
        count_ingress=count_ingress,
        count_egress=count_egress,
        last_time_ingress=0,
        last_time_egress=0,
        curr_time_ingress=curr_time_ingress,
        curr_time_egress=curr_time_egress,
        qdepth=0,
    )


def make_report(trace_id, source_hop, sink_hop):
    return IntReport(
        ver=1,
        hop_count=2,
        original_protocol=17,
        original_total_len=0,
        domain_id=0,
        flags=0,
        trace_id=trace_id,
        hops=[source_hop, sink_hop],
        receive_timestamp=0.0,
    )


class TestLinkMetricsCalculator(unittest.TestCase):
    def test_loss_rate_uses_port_counter_delta_before_trace_gap(self):
        calc = LinkMetricsCalculator(port_to_link={2: 0}, source_swid=2, sink_swid=1)
        calc.compute(
            make_report(
                100,
                make_hop(2, 1, 2, 0, 1000, byte_egress=100_000, curr_time_egress=1_000_000),
                make_hop(1, 2, 1, 980, 0, byte_ingress=98_000, curr_time_ingress=1_010_000),
            )
        )

        metrics = calc.compute(
            make_report(
                105,
                make_hop(2, 1, 2, 0, 1100, byte_egress=110_000, curr_time_egress=2_000_000),
                make_hop(1, 2, 1, 1070, 0, byte_ingress=107_000, curr_time_ingress=2_010_000),
            )
        )
        metric = metrics[0]

        self.assertEqual(metric.sent_delta, 100)
        self.assertEqual(metric.recv_delta, 90)
        self.assertAlmostEqual(metric.loss_rate, 0.10)
        self.assertEqual(metric.sequence_gap, 5)
        self.assertAlmostEqual(metric.sample_loss_rate, 0.80)


class TestPathStateDB(unittest.TestCase):
    def test_loss_rate_uses_window_counter_totals(self):
        db = PathStateDB(num_paths=1, window_size_ms=60_000)
        db.update(
            path_id=0,
            delay_us=1000,
            jitter_us=0,
            loss_rate=1.0,
            bw_bytes_per_s=0,
            sent_delta=10,
            recv_delta=0,
        )
        db.update(
            path_id=0,
            delay_us=1000,
            jitter_us=0,
            loss_rate=0.0,
            bw_bytes_per_s=0,
            sent_delta=1000,
            recv_delta=1000,
        )

        state = db.get_path_state(0)

        self.assertIsNotNone(state)
        self.assertEqual(state.loss_sent_delta, 1010)
        self.assertEqual(state.loss_recv_delta, 1000)
        self.assertAlmostEqual(state.loss_rate, 10 / 1010)


if __name__ == "__main__":
    unittest.main()
