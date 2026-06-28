"""
隐蔽策略注册与按编号实例化。
"""

from typing import Dict, Optional, Type

from .base import CovertStrategy, StrategyID

# 策略编号到策略类的注册表。
_registry: Dict[StrategyID, Type[CovertStrategy]] = {}


def register_strategy(cls: Type[CovertStrategy]) -> Type[CovertStrategy]:
    """
    register_strategy 函数。
    """
    if not hasattr(cls, "strategy_id"):
        raise TypeError(
            f"Strategy class {cls.__name__} must define 'strategy_id'"
        )
    _registry[cls.strategy_id] = cls
    return cls


def get_strategy(
    strategy_id: StrategyID, config: Optional[dict] = None
) -> CovertStrategy:
    """
    get_strategy 函数。
    """
    if strategy_id not in _registry:
        # 策略编号到策略类的注册表。
        _import_all_strategies()

    if strategy_id not in _registry:
        raise KeyError(f"Strategy {strategy_id} not registered. "
                       f"Available: {list(_registry.keys())}")

    return _registry[strategy_id](config)


def list_available() -> Dict[int, str]:
    """list_available 函数。"""
    # 策略编号到策略类的注册表。
    if not _registry:
        _import_all_strategies()
    return {int(sid): cls.name for sid, cls in _registry.items()}


def is_registered(strategy_id: StrategyID) -> bool:
    """is_registered 函数。"""
    return strategy_id in _registry


def _import_all_strategies():
    """
    _import_all_strategies 函数。
    """
    try:
        from . import timing_high_covert       # noqa: F401
        from . import timing_high_capacity     # noqa: F401
        from . import protocol_high_reliability  # noqa: F401
        from . import statistical_fusion       # noqa: F401
        from . import full_path_redundancy     # noqa: F401
        from . import path_sequence            # noqa: F401
    except ImportError:
        pass
