import threading
import time

from dolmos.ui import OUTPUT_LOCK, UI, suspend_status


class FakeStatus:
    def __init__(self):
        self.events = []

    def start(self):
        self.events.append("start")

    def stop(self):
        self.events.append("stop")

    def update(self, status):
        pass


def test_status_changes_wait_for_the_output_lock():
    """a status change must not happen while a solver callback prints (halmos#557)"""
    status = FakeStatus()
    ui = UI(status)
    order = []

    def printer():
        with OUTPUT_LOCK:
            order.append("print start")
            time.sleep(0.1)
            order.append("print end")

    t = threading.Thread(target=printer)
    t.start()
    time.sleep(0.02)  # the printer holds the lock
    ui.stop_status()
    order.append("stopped")
    t.join()

    assert order == ["print start", "print end", "stopped"]
    assert status.events == ["stop"]


def test_suspend_status_is_reentrant_with_the_lock():
    status = FakeStatus()
    with OUTPUT_LOCK, suspend_status(status):
        pass
    assert status.events == ["stop", "start"]
