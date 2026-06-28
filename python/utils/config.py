"""
该模块实现项目中的一个功能组件。
"""

import os
import yaml
from typing import Any, Dict, Optional


class ConfigDict(dict):
    """ConfigDict 类。"""

    def __getitem__(self, key: str) -> Any:
        if "." in key:
            keys = key.split(".")
            value = self
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else:
                    raise KeyError(f"Cannot traverse non-dict value at key '{k}'")
            return value
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, TypeError, AttributeError):
            return default


def load_config(config_path: str) -> ConfigDict:
    """load_config 函数。"""
    if not os.path.isabs(config_path):
        # 中文注释。
        project_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        config_path = os.path.join(project_root, config_path)

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return _to_configdict(data)


def _to_configdict(obj: Any) -> Any:
    """_to_configdict 函数。"""
    if isinstance(obj, dict):
        return ConfigDict({k: _to_configdict(v) for k, v in obj.items()})
    elif isinstance(obj, list):
        return [_to_configdict(item) for item in obj]
    return obj


def merge_configs(base: ConfigDict, override: Dict) -> ConfigDict:
    """merge_configs 函数。"""
    result = dict(base)
    _deep_merge(result, override)
    return _to_configdict(result)


def _deep_merge(base: dict, override: dict) -> None:
    """_deep_merge 函数。"""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
