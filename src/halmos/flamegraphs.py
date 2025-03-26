import subprocess

from halmos.logs import debug
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
    ctx: CallContext, stacks: list[str], *, prefix: str = "", mark_as_fail: bool = False
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
        ctx: The call context that will be converted into a collection of stack traces
        stacks: Where the produced stack traces will be stored (mutable input/output argument)
        prefix: The prefix to add to the stack (optional)
    """

    id = extract_identifier(ctx.message)

    if mark_as_fail:
        id = f"[FAIL] {id}"

    prefix = f"{prefix};{id}" if prefix else id
    stacks.append(prefix)

    for trace_element in ctx.trace:
        if isinstance(trace_element, CallContext):
            extract_stacks(trace_element, stacks, prefix=prefix)
    return stacks


def extract_sequence(seq: CallSequence, stacks: list[str]) -> list[str]:
    """
    Extracts a sequence of call contexts into a list of stack traces.
    """

    for ctx in seq:
        extract_stacks(ctx, stacks)

    return stacks


class FlamegraphAccumulator:
    stacks: list[str]
    debug: bool

    def __init__(self, debug: bool = False):
        self.stacks = []
        self.debug = True

    def add(self, ctx: CallContext):
        extract_stacks(ctx, self.stacks)

    def add_with_sequence(
        self, seq: CallSequence, ctx: CallContext, mark_as_fail: bool = False
    ):
        fun_infos = [call_context.message.fun_info for call_context in seq]

        prefix = ";".join([f"{f.contract_name}::{f.name}" for f in fun_infos])
        extract_stacks(ctx, self.stacks, prefix=prefix, mark_as_fail=mark_as_fail)

    def generate_flamegraph(self, filename: str) -> None:
        with_counts = "\n".join([f"{line} 1" for line in self.stacks])

        if self.debug:
            debug(with_counts)

        try:
            with open(filename, "w") as f:
                # stderr not captured
                stdout = subprocess.check_output(
                    [
                        "flamegraph.pl",
                        "--title",
                        "Exploration Flamegraph",
                        "--colors",
                        "aqua",
                    ],
                    input=with_counts,
                    text=True,
                )
                f.write(stdout)
        except subprocess.CalledProcessError as e:
            if self.debug:
                raise RuntimeError(f"Failed to generate flamegraph: {e}") from e


flamegraph = FlamegraphAccumulator()
