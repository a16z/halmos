import re
from dataclasses import dataclass

from halmos.logs import logger

# Regular expression for capturing halmos variables
halmos_pattern = re.compile(
    r"""
    \(\s*define-fun\s+           # Match "(define-fun"
    \|?(halmos_[^ |]+)\|?\s+     # Capture the full variable name, optionally wrapped in "|"
    \(\)\s+\(_\s+([^ ]+)\s+      # Capture the SMTLIB type (e.g., "BitVec 256")
    (\d+)\)\s+                   # Capture the bit-width or type argument
    (                            # Group for the value
        \#b[01]+                 # Binary value (e.g., "#b1010")
        |\#x[0-9a-fA-F]+         # Hexadecimal value (e.g., "#xFF")
        |\(_\s+bv\d+\s+\d+\)     # Decimal value (e.g., "(_ bv42 256)")
    )
    """,
    re.VERBOSE,
)


@dataclass
class ModelVariable:
    full_name: str
    variable_name: str
    solidity_type: str
    smt_type: str
    size_bits: int
    value: int


def parse_file(file_path: str) -> dict:
    with open(file_path) as file:
        return parse_string(file.read())


def parse_const_value(value: str) -> int:
    if value.startswith("#b"):
        return int(value[2:], 2)

    if value.startswith("#x"):
        return int(value[2:], 16)

    # we may have a group like (_ bv123 256)
    tokens = value.split()
    for token in tokens:
        if token.startswith("bv"):
            return int(token[2:])

    raise ValueError(f"unknown value format: {value}")


def parse_match(match: re.Match) -> ModelVariable:
    full_name = match.group(1).strip()
    smt_type = f"{match.group(2)} {match.group(3)}"
    size_bits = int(match.group(3))
    value = parse_const_value(match.group(4))

    # Extract name and typename from the variable name
    parts = full_name.split("_")
    variable_name = parts[1]
    solidity_type = parts[2]

    return ModelVariable(
        full_name=full_name,
        variable_name=variable_name,
        solidity_type=solidity_type,
        smt_type=smt_type,
        size_bits=size_bits,
        value=value,
    )


def parse_string(smtlib_str: str) -> dict[str, ModelVariable]:
    model_variables: dict[str, ModelVariable] = {}

    # use a regex to find all the variables
    # for now we explicitly don't try to properly parse the smtlib output
    # because of idiosyncrasies of different solvers:
    # - ignores the initial sat/unsat on the first line
    # - ignores the occasional `(model)` command used by yices, stp, cvc4, etc.

    for match in halmos_pattern.finditer(smtlib_str):
        try:
            variable = parse_match(match)
            model_variables[variable.full_name] = variable
        except Exception as e:
            logger.error(f"error parsing smtlib string '{match.string.strip()}': {e}")
            raise e

    return model_variables
