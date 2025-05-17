from collections import defaultdict

from .exceptions import (
    HalmosException,
)
from .mapper import SingletonMeta
from .sevm import Contract, Instruction


class CoverageReporter(metaclass=SingletonMeta):
    """Singleton class for tracking instruction coverage across contracts."""

    def __init__(self) -> None:
        # (contract_name or _fastcode) -> pc -> count
        self._coverage_data: dict[str | bytes, dict[int, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # (contract_name or _fastcode) -> length
        self._contract_lengths: dict[str | bytes, int] = {}

    def _get_key(self, contract: Contract) -> str | bytes | None:
        """Get key from Contract using contract_name or _fastcode."""
        return contract.contract_name or contract._fastcode

    def record_instruction(self, instruction: Instruction, contract: Contract) -> None:
        key = self._get_key(contract)
        if key:
            self._coverage_data[key][instruction.pc] += 1
            # Record contract length if not already recorded
            if key not in self._contract_lengths:
                # TODO: len(contract) is not accurate. It's more than the number of instructions, because push opcodes consist of multiple bytes
                self._contract_lengths[key] = len(contract)

    def get_coverage_stats(self, contract: Contract | None = None) -> dict:
        if contract is None:
            return self._coverage_data
        key = self._get_key(contract)
        if not key:
            raise HalmosException("Cannot use Contract with None _fastcode as key")
        return self._coverage_data[key]

    def get_contract_lengths(self, contract: Contract | None = None) -> dict:
        """Get the length of each contract or a specific contract."""
        if contract is None:
            return self._contract_lengths
        key = self._get_key(contract)
        if not key:
            raise HalmosException("Cannot use Contract with None _fastcode as key")
        return self._contract_lengths[key]
