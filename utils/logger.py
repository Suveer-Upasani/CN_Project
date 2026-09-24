"""Logging configuration and utilities for PortSentinel.

Logs all activities, Nmap commands, scan milestones, and errors to logs/portsentinel.log.
"""

import logging
from pathlib import Path
from typing import Optional

_LOGGER_INSTANCE: Optional[logging.Logger] = None


def setup_logger(log_dir: str = "logs", log_file: str = "portsentinel.log", verbose: bool = False) -> logging.Logger:
    """Initialize and configure the PortSentinel logger.

    Args:
        log_dir: Directory where log file will reside.
        log_file: Name of the log file.
        verbose: If True, also log debug information.

    Returns:
        Configured logging.Logger instance.
    """
    global _LOGGER_INSTANCE

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    full_log_file = log_path / log_file

    logger = logging.getLogger("PortSentinel")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        file_handler = logging.FileHandler(full_log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _LOGGER_INSTANCE = logger
    return logger


def get_logger() -> logging.Logger:
    """Retrieve current logger instance, creating default if not yet initialized."""
    global _LOGGER_INSTANCE
    if _LOGGER_INSTANCE is None:
        _LOGGER_INSTANCE = setup_logger()
    return _LOGGER_INSTANCE
