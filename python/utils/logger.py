"""
该模块实现项目中的一个功能组件。
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class CovertLogger:
    """CovertLogger 类。"""

    _instance: Optional["CovertLogger"] = None

    def __init__(
        self,
        name: str = "covert_transmission",
        log_dir: str = "logs",
        level: int = logging.INFO,
        to_file: bool = True,
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # 中文注释。
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(module)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # 中文注释。
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # 中文注释。
        if to_file:
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_handler = logging.FileHandler(
                log_path / f"{name}_{timestamp}.log", encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    @classmethod
    def get_logger(cls, name: str = "covert_transmission") -> logging.Logger:
        """get_logger 函数。"""
        if cls._instance is None:
            cls._instance = cls(name=name)
        return cls._instance.logger


def get_logger(name: str = "covert_transmission") -> logging.Logger:
    """get_logger 函数。"""
    return CovertLogger.get_logger(name)
