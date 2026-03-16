"""
ICSForge logging configuration.

Provides structured logging for all ICSForge components.
Usage:
    from icsforge.log import get_logger
    log = get_logger(__name__)
    log.info("Receiver started", extra={"port": 502, "proto": "modbus"})
"""

import logging
import os
import sys

_CONFIGURED = False

LOG_FORMAT = "[%(asctime)s] %(levelname)-7s %(name)s — %(message)s"
LOG_FORMAT_DEBUG = "[%(asctime)s] %(levelname)-7s %(name)s:%(lineno)d — %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure(
    level: str | None = None,
    log_file: str | None = None,
    force: bool = False,
) -> None:
    """Configure ICSForge logging.

    Call once at startup. Safe to call multiple times (no-op unless *force*).

    Parameters
    ----------
    level : str, optional
        Logging level (DEBUG, INFO, WARNING, ERROR). Defaults to INFO.
        Can also be set via ``ICSFORGE_LOG_LEVEL`` environment variable.
    log_file : str, optional
        Path to log file. If set, logs to both file and stderr.
        Can also be set via ``ICSFORGE_LOG_FILE`` environment variable.
    force : bool
        Reconfigure even if already configured.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    _CONFIGURED = True

    level = (level or os.environ.get("ICSFORGE_LOG_LEVEL", "INFO")).upper()
    log_file = log_file or os.environ.get("ICSFORGE_LOG_FILE")
    numeric_level = getattr(logging, level, logging.INFO)

    fmt = LOG_FORMAT_DEBUG if numeric_level <= logging.DEBUG else LOG_FORMAT

    root = logging.getLogger("icsforge")
    root.setLevel(numeric_level)
    root.handlers.clear()

    # stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(numeric_level)
    stderr_handler.setFormatter(logging.Formatter(fmt, datefmt=LOG_DATE_FORMAT))
    root.addHandler(stderr_handler)

    # optional file handler
    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=LOG_DATE_FORMAT))
        root.addHandler(file_handler)

    # suppress noisy third-party loggers
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``icsforge`` namespace.

    Automatically calls :func:`configure` with defaults if not yet configured.
    """
    if not _CONFIGURED:
        configure()
    if not name.startswith("icsforge"):
        name = f"icsforge.{name}"
    return logging.getLogger(name)
