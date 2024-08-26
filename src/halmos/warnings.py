import logging
from dataclasses import dataclass

from .utils import color_warn

logger = logging.getLogger("halmos")
logging.basicConfig()

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
