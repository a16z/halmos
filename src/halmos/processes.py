# SPDX-License-Identifier: AGPL-3.0

import concurrent.futures
import contextlib
import subprocess
import threading
import time
import weakref
from subprocess import PIPE, Popen

import psutil


class ExecutorRegistry:
    _instance = None

    # Singleton pattern
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._executors = weakref.WeakSet()
        return cls._instance

    def register(self, executor):
        self._executors.add(executor)

    def shutdown_all(self):
        """Shuts down all registered executors."""

        for ex in list(self._executors):
            ex.shutdown(wait=False)


class PopenFuture(concurrent.futures.Future):
    cmd: list[str]
    timeout: float | None  # in seconds, None means no timeout
    process: subprocess.Popen | None
    stdout: str | None
    stderr: str | None
    returncode: int | None
    start_time: float | None
    end_time: float | None
    _exception: Exception | None

    def __init__(self, cmd: list[str], timeout: float | None = None):
        super().__init__()
        self.cmd = cmd
        self.timeout = timeout
        self.process = None
        self.stdout = None
        self.stderr = None
        self.returncode = None
        self.start_time = None
        self.end_time = None
        self._exception = None

    def start(self):
        """Starts the subprocess and immediately returns."""

        def run():
            try:
                self.start_time = time.time()
                self.process = Popen(self.cmd, stdout=PIPE, stderr=PIPE, text=True)

                # blocks until the process terminates
                self.stdout, self.stderr = self.process.communicate(
                    timeout=self.timeout
                )
                self.end_time = time.time()
                self.returncode = self.process.returncode
            except subprocess.TimeoutExpired as e:
                self._exception = e
            except Exception as e:
                self._exception = e
            finally:
                # ensure process is properly cleaned up for any exception or timeout
                if self.process:
                    self.cancel()

                self.set_result((self.stdout, self.stderr, self.returncode))

        # avoid daemon threads because they can cause issues during shutdown
        # we don't expect them to actually prevent halmos from terminating,
        # as long as the underlying processes are terminated (either by natural
        # causes or by forceful termination)
        threading.Thread(target=run, daemon=False).start()

        return self

    def cancel(self):
        """Attempts to terminate and then kill the process and its children."""
        if not self.is_running():
            return

        # use psutil to kill the entire process tree (including children)
        try:
            parent_process = psutil.Process(self.process.pid)
            processes = parent_process.children(recursive=True)
            processes.append(parent_process)

            # ask politely to terminate first
            for process in processes:
                process.terminate()

            # termination grace period
            with contextlib.suppress(psutil.TimeoutExpired, subprocess.TimeoutExpired):
                parent_process.wait(timeout=0.5)

            # after grace period, force kill
            for process in processes:
                if process.is_running():
                    process.kill()

        except psutil.NoSuchProcess:
            # process already terminated, nothing to do
            pass

        # ensure file descriptors are closed after process termination.
        # note: when a process is killed via psutil, the file descriptors remain open on the Python side,
        # leading to resource leaks. see: https://github.com/a16z/halmos/issues/523
        if self.process:
            for stream in [
                self.process.stdout,
                self.process.stderr,
                self.process.stdin,
            ]:
                try:
                    if stream and not stream.closed:
                        stream.close()
                except Exception:
                    # ignore any errors during cleanup
                    pass

    def exception(self) -> Exception | None:
        """Returns any exception raised during the process."""

        return self._exception

    def result(self, timeout=None) -> tuple[str | None, str | None, int]:
        """Blocks until the process is finished and returns the result (stdout, stderr, returncode).

        Can raise TimeoutError or some Exception raised during execution"""

        return super().result(timeout=timeout)

    def done(self):
        """Returns True if the process has finished."""

        return super().done()

    def is_running(self):
        """Returns True if the process is still running.

        Returns False before start() and after termination."""

        return self.process and self.process.poll() is None


class ShutdownError(RuntimeError):
    """Raised when submitting a future to an executor that has been shutdown."""


class PopenExecutor(concurrent.futures.Executor):
    """
    An executor that runs commands in subprocesses.

    Simple implementation that has no concept of max workers or pending futures.

    The explicit goal is to support killing running subprocesses.
    """

    def __init__(self, max_workers: int = 1):
        self._futures: list[PopenFuture] = list()
        self._shutdown = threading.Event()
        self._lock = threading.Lock()

        # TODO: support max_workers

    @property
    def futures(self):
        return self._futures

    def submit(self, future: PopenFuture) -> PopenFuture:
        """Accepts an unstarted PopenFuture and schedules it for execution.

        Raises ShutdownError if the executor has been shutdown."""

        if self._shutdown.is_set():
            raise ShutdownError()

        with self._lock:
            self._futures.append(future)
            future.start()
            return future

    def is_shutdown(self) -> bool:
        return self._shutdown.is_set()

    def shutdown(self, wait=True, cancel_futures=False):
        # TODO: support max_workers / pending futures

        self._shutdown.set()

        # we have no concept of pending futures,
        # therefore no cancellation of pending futures
        if wait:
            self._join()

        # if asked for immediate shutdown we cancel everything
        else:
            with self._lock, concurrent.futures.ThreadPoolExecutor() as executor:
                # kick off all cancellations in parallel
                cancel_tasks = [executor.submit(f.cancel) for f in self._futures]

                # wait for them to finish
                concurrent.futures.wait(cancel_tasks)

    def map(self, fn, *iterables, timeout=None, chunksize=1):
        raise NotImplementedError()

    def _join(self):
        """Wait until all futures are finished or cancelled."""

        # submitting new futures after join() would be bad,
        # so we make this internal and only call it from shutdown()
        with contextlib.suppress(concurrent.futures.CancelledError):
            for future in list(self._futures):
                future.result()


def main():
    with PopenExecutor() as executor:
        # example usage
        def done_callback(future: PopenFuture):
            stdout, stderr, exitcode = future.result()
            cmd = " ".join(future.cmd)
            elapsed = future.end_time - future.start_time
            print(
                f"{cmd}\n"
                f"  exitcode={exitcode}\n"
                f"  stdout={stdout.strip()}\n"
                f"  stderr={stderr.strip()}\n"
                f"  elapsed={elapsed:.2f}s"
            )
            executor.shutdown(wait=False)

        # Submit multiple commands
        commands = [
            "sleep 1",
            "sleep 10",
            "echo hello",
        ]

        futures = [PopenFuture(command.split()) for command in commands]

        for future in futures:
            future.add_done_callback(done_callback)
            executor.submit(future)

        # exiting the context manager will shutdown the executor with wait=True
        # so no new futures can be submitted
        # the first call to done_callback will cause the remaining futures to be cancelled
        # (and the underlying processes to be terminated)


if __name__ == "__main__":
    main()
