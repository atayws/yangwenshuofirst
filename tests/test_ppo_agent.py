"""
该模块实现项目中的一个功能组件。
"""

import sys
from pathlib import Path
import unittest
import numpy as np
import torch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from python.rl_agent.policy_network import PolicyNetwork
from python.rl_agent.buffer import RolloutBuffer
from python.rl_agent.state_processor import StateProcessor
from python.rl_agent.action_mapper import ActionMapper
from python.rl_agent.reward_calculator import RewardCalculator, TransmissionFeedback


class TestPolicyNetwork(unittest.TestCase):
    """TestPolicyNetwork 类。"""

    def setUp(self):
        self.state_dim = 12
        self.num_paths = 3
        self.net = PolicyNetwork(
            state_dim=self.state_dim,
            num_paths=self.num_paths,
            num_strategies=5,
        )

    def test_forward_shape(self):
        state = torch.randn(1, self.state_dim)
        logits, value = self.net(state)

        self.assertEqual(logits.shape, (1, self.num_paths, 5))
        self.assertEqual(value.shape, (1, 1))

    def test_get_action_shape(self):
        state = torch.randn(1, self.state_dim)
        action, log_prob, value = self.net.get_action(state)

        self.assertEqual(action.shape, (self.num_paths,))
        self.assertIsInstance(log_prob.item(), float)
        self.assertIsInstance(value.item(), float)

    def test_get_action_deterministic(self):
        state = torch.randn(1, self.state_dim)
        action1, _, _ = self.net.get_action(state, deterministic=True)
        action2, _, _ = self.net.get_action(state, deterministic=True)

        # 中文注释。
        self.assertTrue(torch.equal(action1, action2))

    def test_evaluate(self):
        state = torch.randn(4, self.state_dim)
        action = torch.randint(0, 5, (4, self.num_paths))

        log_prob, entropy, value = self.net.evaluate(state, action)

        self.assertEqual(log_prob.shape, (4,))
        self.assertEqual(entropy.shape, (4,))
        self.assertEqual(value.shape, (4,))


class TestRolloutBuffer(unittest.TestCase):
    """TestRolloutBuffer 类。"""

    def setUp(self):
        self.buffer = RolloutBuffer(
            capacity=256,
            state_dim=12,
            num_paths=3,
            gamma=0.99,
            gae_lambda=0.95,
        )

    def test_add_and_size(self):
        for i in range(50):
            self.buffer.add(
                state=np.random.randn(12).astype(np.float32),
                action=np.random.randint(0, 5, 3).astype(np.int32),
                reward=0.5,
                done=False,
                value=0.3,
                log_prob=-1.5,
            )
        self.assertEqual(self.buffer.size, 50)

    def test_compute_gae(self):
        # 中文注释。
        for i in range(10):
            self.buffer.add(
                state=np.random.randn(12).astype(np.float32),
                action=np.random.randint(0, 5, 3).astype(np.int32),
                reward=1.0 if i < 5 else -1.0,
                done=(i == 9),
                value=0.0,
                log_prob=-1.0,
            )

        states, actions, returns, advantages, old_log_probs = (
            self.buffer.compute_returns_and_advantages(
                last_value=0.0,
                last_done=True,
            )
        )

        self.assertEqual(states.shape[0], 10)
        self.assertEqual(actions.shape[0], 10)
        self.assertEqual(returns.shape[0], 10)
        self.assertEqual(advantages.shape[0], 10)

        # 中文注释。
        self.assertAlmostEqual(advantages.mean().item(), 0.0, places=5)
        self.assertAlmostEqual(advantages.std().item(), 1.0, places=0)  # 中文注释。


class TestStateProcessor(unittest.TestCase):
    """TestStateProcessor 类。"""

    def setUp(self):
        self.processor = StateProcessor(num_paths=3)

    def test_normalization(self):
        raw_state = np.array([
            50.0, 10.0, 0.01, 0.3,   # 中文注释。
            100.0, 20.0, 0.05, 0.5,  # 中文注释。
            150.0, 30.0, 0.10, 0.8,  # 中文注释。
        ], dtype=np.float32)

        processed = self.processor.process(raw_state)

        # 中文注释。
        self.assertTrue(np.all(processed >= 0.0))
        self.assertTrue(np.all(processed <= 1.0))

        # 中文注释。
        self.assertEqual(processed.shape, (12,))

    def test_smoothing(self):
        raw = np.ones(12, dtype=np.float32) * 0.5
        p1 = self.processor.process(raw)
        p2 = self.processor.process(raw)

        # 中文注释。
        np.testing.assert_array_almost_equal(p1, p2, decimal=3)


class TestActionMapper(unittest.TestCase):
    """TestActionMapper 类。"""

    def setUp(self):
        self.mapper = ActionMapper(num_paths=3)

    def test_map_to_assignments(self):
        action = np.array([0, 2, 4], dtype=np.int32)
        assignments = self.mapper.map_to_assignments(action)

        self.assertEqual(len(assignments), 3)
        self.assertEqual(assignments[0].strategy_id, 0)
        self.assertEqual(assignments[1].strategy_id, 2)
        self.assertEqual(assignments[2].strategy_id, 4)

    def test_roundtrip(self):
        action = np.array([1, 3, 0], dtype=np.int32)
        assignments = self.mapper.map_to_assignments(action)
        recovered = self.mapper.assignments_to_action(assignments)
        np.testing.assert_array_equal(action, recovered)

    def test_random_action(self):
        action = self.mapper.random_action()
        self.assertEqual(action.shape, (3,))
        self.assertTrue(np.all(action >= 0))
        self.assertTrue(np.all(action <= 4))


class TestRewardCalculator(unittest.TestCase):
    """TestRewardCalculator 类。"""

    def setUp(self):
        self.calc = RewardCalculator()

    def test_perfect_transmission(self):
        feedback = TransmissionFeedback(
            detected=False,
            success_ratio=1.0,
            bytes_delivered=16,
            bytes_total=16,
            throughput_bps=150.0,
        )
        reward = self.calc.compute(feedback)
        # 中文注释。
        self.assertGreater(reward, 0.5)

    def test_detected_transmission(self):
        feedback = TransmissionFeedback(
            detected=True,
            success_ratio=1.0,
            throughput_bps=150.0,
        )
        reward = self.calc.compute(feedback)
        # 中文注释。
        self.assertLess(reward, 0.0)

    def test_failed_transmission(self):
        feedback = TransmissionFeedback(
            detected=False,
            success_ratio=0.0,
            throughput_bps=0.0,
        )
        reward = self.calc.compute(feedback)
        # 中文注释。
        self.assertLess(reward, 0.2)

    def test_diversity_bonus(self):
        strategies = np.array([0, 1, 2])  # 中文注释。
        bonus = self.calc._compute_strategy_diversity_bonus(strategies)
        self.assertGreater(bonus, 0.0)

        strategies_same = np.array([0, 0, 0])  # 中文注释。
        bonus_same = self.calc._compute_strategy_diversity_bonus(strategies_same)
        self.assertLess(bonus_same, bonus)


if __name__ == "__main__":
    unittest.main(verbosity=2)
