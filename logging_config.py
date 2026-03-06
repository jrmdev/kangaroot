"""Logging configuration for Kangaroot.

This module sets up centralized logging for the application with
file and console handlers.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Configure application logging.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (defaults to ~/.kangaroot/logs/kangaroot.log)
    """
    # Determine log file path
    if log_file is None:
        new_dir = Path.home() / '.kangaroot' / 'logs'
        log_dir = new_dir
        log_name = 'kangaroot.log'

        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = str(log_dir / log_name)

    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # File handler with rotation (max 10MB, keep 5 backups)
    try:
        assert log_file is not None
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)  # Log everything to file
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create log file: {e}", file=sys.stderr)

    # Console handler (only for warnings and errors)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)

    # Log startup message
    logging.info("=" * 70)
    logging.info("Kangaroot TUI started")
    logging.info(f"Log level: {log_level}")
    logging.info(f"Log file: {log_file}")
    logging.info("=" * 70)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Module name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
