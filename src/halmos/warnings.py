import logging
from dataclasses import dataclass

from rich.logging import RichHandler

from .utils import color_warn


class UniqueLoggingFilter(logging.Filter):
    def __init__(self):
        self.records = set()

    def filter(self, record):
        if record.msg in self.records:
            return False
        self.records.add(record.msg)
        return True


logging.basicConfig(
    format="%(message)s",
    handlers=[RichHandler(level=logging.NOTSET, show_time=False, show_level=False)],
)

logger = logging.getLogger("halmos")

# logger with filtering out duplicate log messages
logger_unique = logging.getLogger("halmos.unique")
logger_unique.addFilter(UniqueLoggingFilter())


def debug(text: str) -> None:
    logger.debug(text)


def debug_once(text: str) -> None:
    logger_unique.debug(text)


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


def warn_code(error_code: ErrorCode, msg: str):
    logger.warning(f"{color_warn(msg)}\n(see {error_code.url()})")
