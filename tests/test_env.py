"""
该模块实现项目中的一个功能组件。
"""

import sys
from pathlib import Path
import unittest
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from python.simulation.covert_env import CovertMultiPathEnv


class TestCovertEnv(unittest.TestCase):
    """TestCovertEnv 类。"""

    def setUp(self):
        self.env = CovertMultiPathEnv(num_links=3, scenario="static_good", max_steps=100)

    def test_reset(self):
        obs, info = self.env.reset()
        self.assertEqual(obs.shape, (12,))
        self.assertTrue(np.all(obs >= 0.0))
        self.assertTrue(np.all(obs <= 1.0))
        self.assertIn("scenario", info)
        self.assertEqual(info["scenario"], "static_good")

    def test_step(self):
        self.env.reset()
        action = np.array([0, 1, 2], dtype=np.int32)
        obs, reward, terminated, truncated, info = self.env.step(action)
        self.assertEqual(obs.shape, (12,))
        self.assertIsInstance(reward, float)
        self.assertIn("strategies_used", info)
        self.assertIn("throughput_bps", info)

    def test_action_space(self):
        self.env.reset()
        action = self.env.action_space.sample()
        self.assertEqual(action.shape, (3,))
        self.assertTrue(np.all(action >= 0) and np.all(action <= 4))

    def test_episode_termination(self):
        self.env.reset()
        done, step_count = False, 0
        while not done and step_count < 150:
            _, _, terminated, truncated, _ = self.env.step(np.random.randint(0, 5, 3))
            done = terminated or truncated
            step_count += 1
        self.assertLessEqual(step_count, 100)

    def test_all_strategies_valid(self):
        self.env.reset()
        for strat_id in range(5):
            action = np.array([strat_id] * 3, dtype=np.int32)
            obs, reward, _, _, _ = self.env.step(action)
            self.assertEqual(obs.shape, (12,))
            self.assertTrue(np.isfinite(reward))

    def test_reproducibility(self):
        """test_reproducibility 函数。"""
        env1 = CovertMultiPathEnv(num_links=3, scenario="static_good", max_steps=5)
        env2 = CovertMultiPathEnv(num_links=3, scenario="static_good", max_steps=5)
        obs1, _ = env1.reset(seed=42)
        obs2, _ = env2.reset(seed=42)
        np.testing.assert_array_almost_equal(obs1, obs2)
        env1.close()
        env2.close()

    def tearDown(self):
        self.env.close()


class TestEnvScenarios(unittest.TestCase):
    """TestEnvScenarios 类。"""

    def test_all_scenarios_reset(self):
        for scenario in ["static_good", "dynamic_fluctuation", "link_failure", "high_mobility"]:
            env = CovertMultiPathEnv(num_links=3, scenario=scenario, max_steps=10)
            obs, info = env.reset()
            self.assertEqual(obs.shape, (12,))
            for _ in range(3):
                env.step(np.random.randint(0, 5, 3))
            env.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
