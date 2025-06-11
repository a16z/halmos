# SPDX-License-Identifier: AGPL-3.0

import pathlib
import subprocess
import threading
import time
import traceback
from dataclasses import dataclass, field

from halmos.logs import debug, warn
from halmos.sevm import CallContext, CallSequence, Message
from halmos.traces import rendered_address
from halmos.utils import hexify

AUTO_REFRESH_INTERVAL_SECONDS = 0.250


class TimedThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.start_time = None
        self.end_time = None
        self.exception = None

    def run(self):
        self.start_time = time.perf_counter()
        try:
            if self._target:
                self._target(*self._args, **self._kwargs)
        except Exception as e:
            self.exception = e
        finally:
            self.end_time = time.perf_counter()


def run_with_tmp_output(command: list[str], out_filepath: pathlib.Path) -> None:
    # first write to a temporary file to avoid corrupting the output file
    tmp_filepath = out_filepath.with_suffix(".tmp")

    with open(tmp_filepath, "w") as tmp_fd:
        subprocess.run(
            command,
            stdout=tmp_fd,
            text=True,
            check=True,  # raise CalledProcessError if the command fails
        )

    # rename the temporary file to the output file if the command succeeded
    tmp_filepath.rename(out_filepath)


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


@dataclass(slots=True, frozen=True, eq=False, order=False)
class FlamegraphAccumulator:
    title: str
    src_filepath: pathlib.Path | None = None
    out_filepath: pathlib.Path | None = None

    colors: str = "hot"
    stacks: list[str] = field(default_factory=list)
    auto_flush: bool = False
    debug: bool = False
    bg_threads: list[TimedThread] = field(default_factory=list)

    def __post_init__(self):
        if (src := self.src_filepath) and src.exists():
            src.unlink()

        if (out := self.out_filepath) and out.exists():
            out.unlink()

    def __len__(self) -> int:
        return len(self.stacks)

    def add(self, call: CallContext):
        extract_stacks(call, self.stacks)

        if self.auto_flush:
            self.flush()

    def flush(self, force: bool = False) -> None:
        stacks = self.stacks

        if not stacks:
            if self.debug:
                debug(f"No stacks collected for {self.title}, skipping")
            return

        if not self.src_filepath or not self.out_filepath:
            raise RuntimeError(f"missing filepath for {self.title}")

        with open(self.src_filepath, "a") as src_fd:
            src_fd.writelines([f"{line} 1\n" for line in stacks])

        stacks.clear()

        if self.bg_threads:
            last_thread = self.bg_threads[-1]

            # don't start a new thread if the last one is still running
            if last_thread.is_alive() or not last_thread.end_time:
                if force:
                    last_thread.join()
                else:
                    return

            # check if the last thread failed
            if last_thread.exception:
                warn(f"Failed to generate flamegraph: {last_thread.exception}")
                if self.debug:
                    traceback.print_exc()

            # don't start a new thread if the last one finished recently
            elapsed = time.perf_counter() - last_thread.end_time
            if elapsed < AUTO_REFRESH_INTERVAL_SECONDS and not force:
                return

            self.bg_threads.pop()

        # start flamegraph generation in a background thread
        command = [
            "flamegraph.pl",
            "--title",
            self.title,
            "--colors",
            self.colors,
            "--cp",
            str(self.src_filepath),
        ]

        thread = TimedThread(
            target=run_with_tmp_output, args=(command, self.out_filepath)
        )
        thread.daemon = True
        thread.start()

        self.bg_threads.append(thread)

        if force:
            thread.join()


class CallSequenceFlamegraph(FlamegraphAccumulator):
    def add_with_sequence(
        self, seq: CallSequence, call: CallContext, mark_as_fail: bool = False
    ):
        fun_infos = [call_context.message.fun_info for call_context in seq]

        prefix = ";".join([f"{f.contract_name}::{f.name}" for f in fun_infos])
        extract_stacks(call, self.stacks, prefix=prefix, mark_as_fail=mark_as_fail)

        if self.auto_flush:
            self.flush()


# useful for stateless/single-function tests
exec_flamegraph = FlamegraphAccumulator(
    title="Execution Flamegraph",
    src_filepath=pathlib.Path("exec.stacks"),
    out_filepath=pathlib.Path("exec-flamegraph.svg"),
    auto_flush=False,
)

# useful for invariant tests
# auto_flush is enabled because invariant tests can be long running and
# we want to be able to visualize intermediate results
call_flamegraph = CallSequenceFlamegraph(
    title="Call Flamegraph",
    colors="aqua",
    src_filepath=pathlib.Path("call.stacks"),
    out_filepath=pathlib.Path("call-flamegraph.svg"),
    auto_flush=True,
)
