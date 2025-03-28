import subprocess
import traceback

from halmos.logs import debug, warn
from halmos.sevm import CallContext, CallSequence, Message
from halmos.traces import rendered_address
from halmos.utils import hexify


def extract_identifier(message: Message) -> str:
    target = rendered_address(message.target)

    if message.is_create():
        return f"{target}.constructor"

    if (fun_info := message.fun_info) is not None:
        return f"{fun_info.contract_name}::{fun_info.name}"

    return f"{target}.{hexify(message.data[:4])}"


def extract_stacks(
    call: CallContext,
    stacks: list[str],
    *,
    prefix: str = "",
    mark_as_fail: bool = False,
) -> list[str]:
    """
    Expands a call context (i.e. a call tree) into a flat list of stack traces.

    For example, if we have a call tree that looks like this:

        A
        ├─ B
        │  └─ D
        └─ C

    This will be represented as:

        "A"
        "A;B"
        "A;B;D"
        "A;C"

    Parameters:
        call: The call context that will be converted into a collection of stack traces
        stacks: Where the produced stack traces will be stored (mutable input/output argument)
        prefix: The prefix to add to the stack (optional)
    """

    identifier = extract_identifier(call.message)

    if mark_as_fail:
        identifier = f"[FAIL] {identifier}"

    prefix = f"{prefix};{identifier}" if prefix else identifier
    stacks.append(prefix)

    for trace_element in call.trace:
        if isinstance(trace_element, CallContext):
            extract_stacks(trace_element, stacks, prefix=prefix)
    return stacks


def extract_sequence(seq: CallSequence, stacks: list[str]) -> list[str]:
    """
    Extracts a sequence of call contexts into a list of stack traces.
    """

    for call in seq:
        extract_stacks(call, stacks)

    return stacks


# TODO: show SSTORE/LOG for stateless flamegraphs
class FlamegraphAccumulator:
    __slots__ = ["title", "colors", "debug", "stacks"]

    def __init__(self, *, title: str, colors: str = "hot", debug: bool = False):
        self.title = title
        self.colors = colors
        self.debug = debug
        self.stacks = []

    def __len__(self) -> int:
        return len(self.stacks)

    def add(self, call: CallContext):
        extract_stacks(call, self.stacks)

    def generate_flamegraph(self, filename: str) -> None:
        if not self.stacks:
            print(f"No stacks collected for {self.title}, ")
            return

        with_counts = "\n".join([f"{line} 1" for line in self.stacks])

        if self.debug:
            debug(with_counts)

        try:
            with open(filename, "w") as f:
                # stderr not captured, errors will be printed to console
                stdout = subprocess.check_output(
                    [
                        "flamegraph.pl",
                        "--title",
                        self.title,
                        "--colors",
                        self.colors,
                    ],
                    input=with_counts,
                    text=True,
                )
                f.write(stdout)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            warn(f"Failed to generate flamegraph: {e}")
            if self.debug:
                traceback.print_exc()


class CallSequenceFlamegraph(FlamegraphAccumulator):
    def __init__(self, *, title: str, colors: str = "aqua", debug: bool = False):
        super().__init__(title=title, colors=colors, debug=debug)

    def add_with_sequence(
        self, seq: CallSequence, call: CallContext, mark_as_fail: bool = False
    ):
        fun_infos = [call_context.message.fun_info for call_context in seq]

        prefix = ";".join([f"{f.contract_name}::{f.name}" for f in fun_infos])
        extract_stacks(call, self.stacks, prefix=prefix, mark_as_fail=mark_as_fail)


# useful for stateless/single-function tests
exec_flamegraph = FlamegraphAccumulator(title="Execution Flamegraph")

# useful for invariant tests
call_flamegraph = CallSequenceFlamegraph(title="Call Flamegraph")
