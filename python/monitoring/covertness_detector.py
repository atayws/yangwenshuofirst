"""
隐蔽性检测仿真器。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import numpy as np


@dataclass
class DetectionResult:
    """DetectionResult 类。"""
    detected: bool
    confidence: float          # 中文注释。
    method: str                # 中文注释。
    anomaly_score: float       # 中文注释。
    evidence: Dict[str, float] = field(default_factory=dict)
    details: str = ""


@dataclass
class TrafficFeatures:
    """TrafficFeatures 类。"""
    # 中文注释。
    ipd_mean_ms: float = 0.0
    ipd_std_ms: float = 0.0
    ipd_entropy: float = 0.0    # 中文注释。

    # 中文注释。
    pkt_len_mean: float = 0.0
    pkt_len_std: float = 0.0
    pkt_len_bimodality: float = 0.0  # 中文注释。

    # 中文注释。
    packet_count: int = 0
    bytes_total: int = 0

    # 中文注释。
    ip_id_randomness: float = 0.0  # 中文注释。

    # 中文注释。
    strategy_entropy: float = 0.0  # 中文注释。

    def to_vector(self) -> np.ndarray:
        return np.array([
            self.ipd_mean_ms / 200.0,
            self.ipd_std_ms / 50.0,
            self.ipd_entropy,
            self.pkt_len_mean / 1500.0,
            self.pkt_len_std / 500.0,
            self.pkt_len_bimodality,
            self.ip_id_randomness,
            min(self.packet_count / 100.0, 1.0),
            self.strategy_entropy,
        ], dtype=np.float32)


class CovertnessDetector:
    """
    CovertnessDetector 类。
    """

    METHODS = ["statistical", "ml_based", "rule_based", "ensemble"]

    def __init__(
        self,
        method: str = "ensemble",
        sensitivity: float = 0.5,
        seed: Optional[int] = None,
    ):
        """
        __init__ 函数。
        """
        if method not in self.METHODS:
            raise ValueError(f"Unknown method: {method}. Use: {self.METHODS}")

        self.method = method
        self.sensitivity = np.clip(sensitivity, 0.0, 1.0)

        if seed is not None:
            np.random.seed(seed)

        # 中文注释。
        self._baseline = self._default_baseline()

    def evaluate(
        self,
        features: TrafficFeatures,
        strategy_ids: Optional[List[int]] = None,
    ) -> DetectionResult:
        """
        evaluate 函数。
        """
        if self.method == "statistical":
            result = self._detect_statistical(features)
        elif self.method == "ml_based":
            result = self._detect_ml(features)
        elif self.method == "rule_based":
            result = self._detect_rule_based(features, strategy_ids)
        elif self.method == "ensemble":
            result = self._detect_ensemble(features, strategy_ids)
        else:
            result = DetectionResult(
                detected=False, confidence=0.0, method=self.method,
                anomaly_score=0.0,
            )

        # 中文注释。
        result.detected = result.anomaly_score > (0.7 - 0.2 * self.sensitivity)
        return result

    def extract_features(
        self,
        packet_delays_ms: List[float],
        packet_lengths: List[int],
        ip_ids: Optional[List[int]] = None,
        strategy_ids: Optional[List[int]] = None,
    ) -> TrafficFeatures:
        """
        extract_features 函数。
        """
        features = TrafficFeatures()
        delays = np.array(packet_delays_ms) if packet_delays_ms else np.array([0])
        lengths = np.array(packet_lengths) if packet_lengths else np.array([0])

        # 中文注释。
        features.ipd_mean_ms = float(np.mean(delays))
        features.ipd_std_ms = float(np.std(delays))
        features.ipd_entropy = self._compute_entropy(delays, bins=10)

        # 中文注释。
        features.pkt_len_mean = float(np.mean(lengths))
        features.pkt_len_std = float(np.std(lengths))

        # 中文注释。
        short_ratio = np.mean(lengths < 300)
        long_ratio = np.mean(lengths >= 300)
        features.pkt_len_bimodality = 1.0 - abs(short_ratio - 0.5) * 2  # 中文注释。

        # 中文注释。
        features.packet_count = len(packet_delays_ms)
        features.bytes_total = sum(packet_lengths)

        # 中文注释。
        if ip_ids and len(ip_ids) > 1:
            ip_id_arr = np.array(ip_ids, dtype=np.float64)
            ip_id_arr = (ip_id_arr - ip_id_arr.min()) / max(ip_id_arr.max() - ip_id_arr.min(), 1)
            features.ip_id_randomness = self._compute_entropy(ip_id_arr, bins=16)
        else:
            features.ip_id_randomness = 0.8  # 中文注释。

        # 中文注释。
        if strategy_ids:
            features.strategy_entropy = self._compute_discrete_entropy(strategy_ids)

        return features

    # 中文注释。

    def _detect_statistical(self, features: TrafficFeatures) -> DetectionResult:
        """
        _detect_statistical 函数。
        """
        baseline = self._baseline
        evidence = {}

        # 中文注释。
        ipd_cv = features.ipd_std_ms / max(features.ipd_mean_ms, 0.1)  # 中文注释。
        ipd_anomaly = max(0, 1.0 - ipd_cv / baseline["ipd_cv_baseline"])
        evidence["ipd_regularity"] = ipd_anomaly

        # 中文注释。
        len_anomaly = features.pkt_len_bimodality * 0.8
        evidence["length_bimodality"] = len_anomaly

        # 中文注释。
        id_anomaly = max(0, 1.0 - features.ip_id_randomness)
        evidence["ip_id_anomaly"] = id_anomaly

        anomaly_score = (
            ipd_anomaly * 0.4 + len_anomaly * 0.35 + id_anomaly * 0.25
        )

        return DetectionResult(
            detected=False,  # 中文注释。
            confidence=anomaly_score,
            method="statistical",
            anomaly_score=anomaly_score,
            evidence=evidence,
        )

    def _detect_ml(self, features: TrafficFeatures) -> DetectionResult:
        """
        _detect_ml 函数。
        """
        vec = features.to_vector()

        # 中文注释。
        weights = np.array([
            1.5,   # 中文注释。
            2.0,   # 中文注释。
            -1.0,  # 中文注释。
            0.5,   # 中文注释。
            0.3,   # 中文注释。
            3.0,   # 中文注释。
            -1.5,  # 中文注释。
            0.2,   # 中文注释。
            0.0,   # 中文注释。
        ])

        logit = np.dot(vec, weights) - 1.5  # 中文注释。
        probability = 1.0 / (1.0 + np.exp(-logit))  # 中文注释。

        return DetectionResult(
            detected=False,
            confidence=float(probability),
            method="ml_based",
            anomaly_score=float(probability),
        )

    def _detect_rule_based(
        self,
        features: TrafficFeatures,
        strategy_ids: Optional[List[int]] = None,
    ) -> DetectionResult:
        """
        _detect_rule_based 函数。
        """
        flags = []

        # 中文注释。
        ipd_cv = features.ipd_std_ms / max(features.ipd_mean_ms, 0.1)
        if ipd_cv < 0.15:
            flags.append(("very_regular_timing", 0.8))

        # 中文注释。
        if features.pkt_len_bimodality > 0.8:
            flags.append(("bimodal_lengths", 0.7))

        # 中文注释。
        if features.ip_id_randomness < 0.3:
            flags.append(("nonrandom_ip_id", 0.6))

        # 中文注释。
        if strategy_ids:
            if 0 in strategy_ids or 1 in strategy_ids:
                flags.append(("timing_strategy_active", 0.4))
            if 2 in strategy_ids:
                flags.append(("protocol_strategy_active", 0.5))
            if 3 in strategy_ids:
                flags.append(("statistical_strategy_active", 0.3))

        if not flags:
            return DetectionResult(
                detected=False, confidence=0.0, method="rule_based",
                anomaly_score=0.0,
            )

        # 中文注释。
        anomaly_score = sum(score for _, score in flags) / max(len(flags), 1)
        anomaly_score = min(1.0, anomaly_score)

        return DetectionResult(
            detected=False,
            confidence=anomaly_score,
            method="rule_based",
            anomaly_score=anomaly_score,
            details="; ".join(name for name, _ in flags),
        )

    def _detect_ensemble(
        self,
        features: TrafficFeatures,
        strategy_ids: Optional[List[int]] = None,
    ) -> DetectionResult:
        """
        _detect_ensemble 函数。
        """
        stat_result = self._detect_statistical(features)
        ml_result = self._detect_ml(features)
        rule_result = self._detect_rule_based(features, strategy_ids)

        # 中文注释。
        scores = [
            stat_result.anomaly_score,
            ml_result.anomaly_score,
            rule_result.anomaly_score,
        ]
        weights = [0.3, 0.4, 0.3]  # 中文注释。

        ensemble_score = sum(s * w for s, w in zip(scores, weights))

        return DetectionResult(
            detected=False,
            confidence=ensemble_score,
            method="ensemble",
            anomaly_score=ensemble_score,
            evidence={
                "statistical": stat_result.anomaly_score,
                "ml_based": ml_result.anomaly_score,
                "rule_based": rule_result.anomaly_score,
            },
        )

    # 中文注释。

    @staticmethod
    def _compute_entropy(data: np.ndarray, bins: int = 10) -> float:
        """_compute_entropy 函数。"""
        if len(data) < 2:
            return 0.0
        hist, _ = np.histogram(data, bins=bins, density=True)
        hist = hist[hist > 0]
        hist = hist / hist.sum()
        return float(-np.sum(hist * np.log2(hist + 1e-10)))

    @staticmethod
    def _compute_discrete_entropy(values: List[int]) -> float:
        """_compute_discrete_entropy 函数。"""
        if not values:
            return 0.0
        counts = np.bincount(values, minlength=5)
        probs = counts / counts.sum()
        probs = probs[probs > 0]
        return float(-np.sum(probs * np.log2(probs + 1e-10)))

    @staticmethod
    def _default_baseline() -> dict:
        """_default_baseline 函数。"""
        return {
            "ipd_cv_baseline": 0.5,    # 中文注释。
            "ipd_mean_baseline_ms": 50,
            "len_mean_baseline": 500,
            "len_std_baseline": 300,
        }

    def reset_baseline(self):
        """reset_baseline 函数。"""
        self._baseline = self._default_baseline()
