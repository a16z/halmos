from z3 import BitVec, BitVecRef

from .logs import (
    info,
    warn,
)
from .utils import (
    con_addr,
    extract_bytes,
    extract_bytes_argument,
    extract_funsig,
    extract_string_argument,
    hexify,
    int_of,
    magenta,
    render_address,
    render_bool,
    render_bytes,
    render_int,
    render_uint,
)


def log_uint256(arg: BitVec) -> None:
    b = extract_bytes(arg, 4, 32)
    console.log(render_uint(b))


def log_string(arg: BitVec) -> None:
    str_val = extract_string_argument(arg, 0)
    console.log(str_val)


def log_bytes(arg: BitVec) -> None:
    b = extract_bytes_argument(arg, 0)
    console.log(render_bytes(b))


def log_string_address(arg: BitVec) -> None:
    str_val = extract_string_argument(arg, 0)
    addr = extract_bytes(arg, 36, 32)
    console.log(f"{str_val} {render_address(addr)}")


def log_address(arg: BitVec) -> None:
    addr = extract_bytes(arg, 4, 32)
    console.log(render_address(addr))


def log_string_bool(arg: BitVec) -> None:
    str_val = extract_string_argument(arg, 0)
    bool_val = extract_bytes(arg, 36, 32)
    console.log(f"{str_val} {render_bool(bool_val)}")


def log_bool(arg: BitVec) -> None:
    bool_val = extract_bytes(arg, 4, 32)
    console.log(render_bool(bool_val))


def log_string_string(arg: BitVec) -> None:
    str1_val = extract_string_argument(arg, 0)
    str2_val = extract_string_argument(arg, 1)
    console.log(f"{str1_val} {str2_val}")


def log_bytes32(arg: BitVec) -> None:
    b = extract_bytes(arg, 4, 32)
    console.log(hexify(b))


def log_string_int256(arg: BitVec) -> None:
    str_val = extract_string_argument(arg, 0)
    int_val = extract_bytes(arg, 36, 32)
    console.log(f"{str_val} {render_int(int_val)}")


def log_int256(arg: BitVec) -> None:
    int_val = extract_bytes(arg, 4, 32)
    console.log(render_int(int_val))


def log_string_uint256(arg: BitVec) -> None:
    str_val = extract_string_argument(arg, 0)
    uint_val = extract_bytes(arg, 36, 32)
    console.log(f"{str_val} {render_uint(uint_val)}")


class console:
    # see forge-std/console2.sol
    address: BitVecRef = con_addr(0x000000000000000000636F6E736F6C652E6C6F67)

    handlers = {
        0xF82C50F1: log_uint256,
        0xF5B1BBA9: log_uint256,  # alias for 'log(uint)'
        0x41304FAC: log_string,
        0x0BE77F56: log_bytes,
        0x319AF333: log_string_address,
        0x2C2ECBC2: log_address,
        0xC3B55635: log_string_bool,
        0x32458EED: log_bool,
        0x4B5C4277: log_string_string,
        0x27B7CF85: log_bytes32,
        0x3CA6268E: log_string_int256,
        0x2D5B6CB9: log_int256,
        0xB60E72CC: log_string_uint256,
    }

    @staticmethod
    def log(what: str) -> None:
        print(f"[console.log] {magenta(what)}")

    @staticmethod
    def handle(ex, arg: BitVec) -> None:
        try:
            funsig: int = int_of(
                extract_funsig(arg), "symbolic console function selector"
            )

            if handler := console.handlers.get(funsig):
                return handler(arg)

            info(
                f"Unsupported console function: selector = 0x{funsig:0>8x}, "
                f"calldata = {hexify(arg)}"
            )
        except Exception as e:
            # we don't want to fail execution because of an issue during console.log
            warn(f"console.handle: {repr(e)} with arg={hexify(arg)}")
