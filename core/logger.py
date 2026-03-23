import logging
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from colorlog import ColoredFormatter


# ==============================================================
# PATHS & DIRECTORIES
# ==============================================================
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)


# ==============================================================
# LOG FORMATS
# ==============================================================
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
COLOR_FORMAT = "%(log_color)s%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

LOG_COLORS = {
    "DEBUG": "cyan",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold_red,bg_white",
}


# ==============================================================
# HANDLERS
# ==============================================================

# Console Handler (for colored terminal logs)
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter(COLOR_FORMAT, log_colors=LOG_COLORS))

# Rotating File Handler (Info logs)
info_handler = RotatingFileHandler(
    LOG_DIR / "info.log",
    maxBytes=5 * 1024 * 1024,   # 5 MB
    backupCount=5,
    encoding="utf-8",
)
info_handler.setLevel(logging.INFO)
info_handler.setFormatter(logging.Formatter(LOG_FORMAT))

# Rotating File Handler (Error logs)
error_handler = RotatingFileHandler(
    LOG_DIR / "error.log",
    maxBytes=2 * 1024 * 1024,   # 2 MB
    backupCount=3,
    encoding="utf-8",
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter(LOG_FORMAT))


# ==============================================================
# BASE LOGGING CONFIGURATION
# ==============================================================
logging.basicConfig(
    level=logging.DEBUG,
    handlers=[console_handler, info_handler, error_handler],
    format=LOG_FORMAT,
)


# ==============================================================
# GET LOGGER FUNCTION
# ==============================================================
def get_logger(name: str):
    """
    Returns a centralized logger for any module.
    Example:
        logger = get_logger(__name__)
        logger.info("Message")
    """
    return logging.getLogger(name)
