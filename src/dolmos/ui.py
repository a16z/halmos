# SPDX-License-Identifier: AGPL-3.0

import sys
import threading
from dataclasses import dataclass, field

from rich import get_console
from rich.console import Console
from rich.prompt import Confirm
from rich.status import Status


class suspend_status:
    """Context manager to temporarily suspend a Status."""

    def __init__(self, status: Status):
        self.status = status

    def __enter__(self):
        with OUTPUT_LOCK:
            _retire_stdout()
            self.status.stop()

    def __exit__(self, exc_type, exc_value, traceback):
        with OUTPUT_LOCK:
            _retire_stdout()
            self.status.start()


# Serializes the output of the solver callbacks with the start and stop of the status
# (halmos#557). While the status is live, rich replaces sys.stdout with a FileProxy, and
# restores it when the status stops, which can free the proxy. A thread printing at
# that moment can use the freed object: `print` holds a borrowed reference to
# sys.stdout in some CPython versions, which surfaced as "AttributeError: 'cell' object
# has no attribute '_FileProxy__buffer'" in a solver callback.
OUTPUT_LOCK = threading.RLock()

# the stdout proxies replaced by a status change, kept alive for the same reason
_retired_stdouts: list = []


def _retire_stdout() -> None:
    if sys.stdout is not sys.__stdout__:
        _retired_stdouts.append(sys.stdout)
        del _retired_stdouts[:-16]


@dataclass(frozen=True, eq=False, order=False, slots=True)
class UI:
    status: Status
    console: Console = field(default_factory=get_console)

    @property
    def is_interactive(self) -> bool:
        return self.console.is_interactive

    def clear_live(self):
        self.console.clear_live()

    def start_status(self):
        with OUTPUT_LOCK:
            _retire_stdout()
            # clear any remaining live display before starting a new instance
            self.clear_live()
            self.status.start()

    def update_status(self, status: str):
        self.status.update(status)

    def stop_status(self):
        with OUTPUT_LOCK:
            _retire_stdout()
            self.status.stop()

    def prompt(self, prompt: str) -> bool:
        # non-interactive sessions (e.g. redirected output) will block on input
        if not self.is_interactive:
            return False

        with suspend_status(self.status):
            return Confirm.ask(prompt)

    def print(self, *args, **kwargs):
        self.console.print(*args, **kwargs)


ui: UI = UI(Status(""))


if __name__ == "__main__":
    import time

    print(f"{ui.is_interactive=}")

    # things basically break down if start a rogue status (not managed by the UI class)
    # time.sleep(1)
    # print("starting a rogue status")
    # rogue_status = Status("Rogue status")
    # rogue_status.start()

    # time.sleep(1)
    # print("clearing live")
    # ui.clear_live()

    time.sleep(1)
    print("starting 'official' status")
    ui.start_status()

    time.sleep(1)
    print("updating status")
    ui.update_status("Status update demo")

    # using the managed prompt should suspend the status
    # (otherwise the prompt will get clobbered by the next status update)
    time.sleep(1)
    answer = ui.prompt("Prompt demo")
    print(f"{answer=}")

    # status updates should resume after the prompt returns
    time.sleep(1)
    print("stopping status")
    ui.stop_status()

    time.sleep(1)
