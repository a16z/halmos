from collections import defaultdict
from typing import TypeAlias

from .exceptions import (
    HalmosException,
)
from .mapper import SingletonMeta
from .sevm import Contract, Instruction


class CoverageReporter(metaclass=SingletonMeta):
    """Singleton class for tracking instruction coverage across contracts."""

    def __init__(self) -> None:
        # file_path -> line_number -> count
        self._instruction_coverage_data: dict[str, dict[int, int]] = (
            defaultdict(lambda: defaultdict(int))
        )

    def record_instruction(self, instruction: Instruction, contract: Contract) -> None:
        # Record instruction coverage by file path and line number
        if instruction.source_file and instruction.source_line:
            self._instruction_coverage_data[instruction.source_file][instruction.source_line] += 1

    def get_instruction_coverage_stats(self, contract: Contract | None = None) -> dict:
        return self._instruction_coverage_data

    def generate_lcov(self) -> str:
        """Generate lcov format coverage report."""
        lcov_lines = []
        
        for file_path, line_coverage in self._instruction_coverage_data.items():
            # SF: Source file
            lcov_lines.append(f"SF:{file_path}")
            
            # DA: Line data (line number, execution count)
            for line_number, count in sorted(line_coverage.items()):
                lcov_lines.append(f"DA:{line_number},{count}")
            
            # LF: Lines found
            lcov_lines.append(f"LF:{len(line_coverage)}")
            
            # LH: Lines hit (lines with count > 0)
            lines_hit = sum(1 for count in line_coverage.values() if count > 0)
            lcov_lines.append(f"LH:{lines_hit}")
            
            # End of file
            lcov_lines.append("end_of_record")
        
        return "\n".join(lcov_lines)
