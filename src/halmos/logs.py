# SPDX-License-Identifier: AGPL-3.0

import logging
from dataclasses import dataclass

from rich.logging import RichHandler

#
# Basic logging
#

logging.basicConfig(
    format="%(message)s",
    handlers=[RichHandler(level=logging.NOTSET, show_time=False, show_path=False)],
)

logger = logging.getLogger("halmos")


#
# Logging with filtering out duplicate log messages
#


class UniqueLoggingFilter(logging.Filter):
    def __init__(self):
        self.records = set()

    def filter(self, record):
        if record.msg in self.records:
            return False
        self.records.add(record.msg)
        return True


logger_unique = logging.getLogger("halmos.unique")
logger_unique.addFilter(UniqueLoggingFilter())


def logger_for(allow_duplicate=True) -> logging.Logger:
    return logger if allow_duplicate else logger_unique


def debug(text: str, allow_duplicate=True) -> None:
    logger_for(allow_duplicate).debug(text)


def info(text: str, allow_duplicate=True) -> None:
    logger_for(allow_duplicate).info(text)


def warn(text: str, allow_duplicate=True) -> None:
    logger_for(allow_duplicate).warning(text)


def error(text: str, allow_duplicate=True) -> None:
    logger_for(allow_duplicate).error(text)


def debug_once(text: str) -> None:
    debug(text, allow_duplicate=False)


#
# Warnings with error code
#

WARNINGS_BASE_URL = "https://github.com/a16z/halmos/wiki/warnings"


@dataclass
class ErrorCode:
    code: str

    def url(self) -> str:
        return f"{WARNINGS_BASE_URL}#{self.code}"


PARSING_ERROR = ErrorCode("parsing-error")
INTERNAL_ERROR = ErrorCode("internal-error")
LIBRARY_PLACEHOLDER = ErrorCode("library-placeholder")
COUNTEREXAMPLE_INVALID = ErrorCode("counterexample-invalid")
COUNTEREXAMPLE_UNKNOWN = ErrorCode("counterexample-unknown")
UNSUPPORTED_OPCODE = ErrorCode("unsupported-opcode")
REVERT_ALL = ErrorCode("revert-all")
LOOP_BOUND = ErrorCode("loop-bound")


def warn_code(error_code: ErrorCode, msg: str, allow_duplicate=True):
    logger_for(allow_duplicate).warning(f"{msg}\n(see {error_code.url()})")
