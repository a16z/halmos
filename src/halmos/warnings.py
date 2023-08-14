import logging

from dataclasses import dataclass

from .utils import color_warn

logger = logging.getLogger("Halmos")
logging.basicConfig()

WARNINGS_BASE_URL = "https://github.com/a16z/halmos/wiki/warnings"


@dataclass
class ErrorCode:
    code: str

    def url(self) -> str:
        return f"{WARNINGS_BASE_URL}#{self.code}"


COUNTEREXAMPLE_INVALID = ErrorCode("counterexample-invalid")
COUNTEREXAMPLE_UNKNOWN = ErrorCode("counterexample-unknown")
INTERNAL_ERROR = ErrorCode("internal-error")
UNSUPPORTED_OPCODE = ErrorCode("unsupported-opcode")
LIBRARY_PLACEHOLDER = ErrorCode("library-placeholder")

LOOP_BOUND = ErrorCode("loop-bound")
UNINTERPRETED_UNKNOWN_CALLS = ErrorCode("uninterpreted-unknown-calls")


def warn(error_code: ErrorCode, msg: str):
    logger.warning(f"{color_warn(msg)}\n(see {error_code.url()})")
