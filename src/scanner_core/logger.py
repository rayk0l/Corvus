"""
logger.py - Centralized logging for the security scanner.
Provides dual output: console (colored) + file (detailed).
"""

import os
import sys
import logging
from datetime import datetime


# Custom formatter for console output (matches existing scanner style)
class ConsoleFormatter(logging.Formatter):
    """Console formatter that matches the scanner's existing output style."""

    LEVEL_PREFIXES = {
        logging.DEBUG: "  [D]",
        logging.INFO: "  [i]",
        logging.WARNING: "  [!]",
        logging.ERROR: "  [!]",
        logging.CRITICAL: "  [!!]",
    }

    def format(self, record):
        prefix = self.LEVEL_PREFIXES.get(record.levelno, "  [?]")
        return f"{prefix} {record.getMessage()}"


# File formatter with timestamps
class FileFormatter(logging.Formatter):
    """Detailed file formatter with timestamps and levels."""

    def format(self, record):
        ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level = record.levelname.ljust(8)
        module = record.name.ljust(20)
        return f"{ts} | {level} | {module} | {record.getMessage()}"


# Global logger instance
_logger = None
_log_file_path = None


def setup_logger(output_dir: str = ".", log_level: str = "INFO") -> logging.Logger:
    """
    Initialize the global scanner logger.

    Args:
        output_dir: Directory for the log file
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    global _logger, _log_file_path

    if _logger is not None:
        return _logger

    logger = logging.getLogger("scanner")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Prevent duplicate handlers on re-init
    logger.handlers.clear()

    # Console handler (INFO+ by default, matches existing output style)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(ConsoleFormatter())
    logger.addHandler(console_handler)

    # File handler (DEBUG+, all details)
    try:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        _log_file_path = os.path.join(output_dir, f"scan_log_{timestamp}.txt")
        file_handler = logging.FileHandler(_log_file_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileFormatter())
        logger.addHandler(file_handler)
    except OSError:
        # Can't write log file - continue with console only
        pass

    _logger = logger
    return logger


def get_logger(name: str = "scanner") -> logging.Logger:
    """
    Get a child logger for a specific module.

    Args:
        name: Module name (e.g., "file_scanner", "network_scanner")

    Returns:
        Logger instance (child of the main scanner logger)
    """
    global _logger
    if _logger is None:
        # Auto-setup with defaults if not initialized
        setup_logger()
    return logging.getLogger(f"scanner.{name}")


def get_log_file_path() -> str:
    """Return the current log file path, or empty string if no file logging."""
    return _log_file_path or ""
