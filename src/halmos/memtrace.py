import io
import linecache
import threading
import time
import tracemalloc

from rich.console import Console

from halmos.logs import debug

console = Console()


def readable_size(num: int | float) -> str:
    if num < 1024:
        return f"{num}B"

    if num < 1024 * 1024:
        return f"{num/1024:.1f}KiB"

    return f"{num/(1024*1024):.1f}MiB"


def pretty_size(num: int | float) -> str:
    return f"[magenta]{readable_size(num)}[/magenta]"


def pretty_count_diff(num: int | float) -> str:
    if num > 0:
        return f"[red]+{num}[/red]"
    elif num < 0:
        return f"[green]{num}[/green]"
    else:
        return "[gray]0[/gray]"


def pretty_line(line: str):
    return f"[white]    {line}[/white]" if line else ""


def pretty_frame_info(
    frame: tracemalloc.Frame, result_number: int | None = None
) -> str:
    result_number_str = (
        f"[grey37]# {result_number+1}:[/grey37] " if result_number is not None else ""
    )
    filename_str = f"[grey37]{frame.filename}:[/grey37]"
    lineno_str = f"[grey37]{frame.lineno}:[/grey37]"
    return f"{result_number_str}{filename_str}{lineno_str}"


class MemTracer:
    curr_snapshot: tracemalloc.Snapshot | None = None
    prev_snapshot: tracemalloc.Snapshot | None = None
    running: bool = False

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        if MemTracer._instance is not None:
            raise RuntimeError("Use MemTracer.get() to access the singleton instance.")
        self.curr_snapshot = None
        self.prev_snapshot = None
        self.running = False

    @classmethod
    def get(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def take_snapshot(self):
        debug("memtracer: taking snapshot")
        self.prev_snapshot = self.curr_snapshot
        self.curr_snapshot = tracemalloc.take_snapshot()
        self.display_stats()

    def display_stats(self):
        """Display statistics about the current memory snapshot."""
        if not self.running:
            return

        if self.curr_snapshot is None:
            debug("memtracer: no current snapshot")
            return

        out = io.StringIO()

        # Show top memory consumers by line
        out.write("[cyan][ Top memory consumers ][/cyan]\n")
        stats = self.curr_snapshot.statistics("lineno")
        for i, stat in enumerate(stats[:10]):
            frame = stat.traceback[0]
            line = linecache.getline(frame.filename, frame.lineno).strip()
            out.write(f"{pretty_frame_info(frame, i)} " f"{pretty_size(stat.size)}\n")
            out.write(f"{pretty_line(line)}\n")
        out.write("\n")

        # Get total memory usage
        total = sum(stat.size for stat in self.curr_snapshot.statistics("filename"))
        out.write(f"Total memory used in snapshot: {pretty_size(total)}\n\n")

        console.print(out.getvalue())

    def start(self, interval_seconds=60):
        """Start tracking memory usage at the specified interval."""
        if not tracemalloc.is_tracing():
            nframes = 1
            tracemalloc.start(nframes)
        self.running = True

        self.take_snapshot()
        threading.Thread(
            target=self._run, args=(interval_seconds,), daemon=True
        ).start()

    def stop(self):
        """Stop the memory tracer."""
        self.running = False

    def _run(self, interval_seconds):
        """Run the tracer periodically."""
        while self.running:
            time.sleep(interval_seconds)
            self.take_snapshot()
            self._display_differences()

    def _display_differences(self):
        """Display top memory differences between snapshots."""

        if not self.running:
            return

        if self.prev_snapshot is None or self.curr_snapshot is None:
            debug("memtracer: no snapshots to compare")
            return

        out = io.StringIO()

        top_stats = self.curr_snapshot.compare_to(
            self.prev_snapshot, "lineno", cumulative=True
        )
        out.write("[cyan][ Top differences ][/cyan]\n")
        for i, stat in enumerate(top_stats[:10]):
            frame = stat.traceback[0]
            line = linecache.getline(frame.filename, frame.lineno).strip()
            out.write(
                f"{pretty_frame_info(frame, i)} "
                f"{pretty_size(stat.size_diff)} "
                f"[{pretty_count_diff(stat.count_diff)}]\n"
            )
            out.write(f"{pretty_line(line)}\n")

        total_diff = sum(stat.size_diff for stat in top_stats)
        out.write(f"Total size difference: {pretty_size(total_diff)}\n")

        console.print(out.getvalue())


def main():
    tracer = MemTracer.get()
    tracer.start(interval_seconds=2)

    # Simulate some workload
    import random

    memory_hog = []
    try:
        while True:
            memory_hog.append([random.random() for _ in range(1000)])
            time.sleep(0.1)
    except KeyboardInterrupt:
        # Stop the tracer on exit
        tracer.stop()


if __name__ == "__main__":
    main()
