# SPDX-License-Identifier: AGPL-3.0

from unittest.mock import Mock

from halmos.processes import PopenFuture, get_global_executor


def test_popen_future_with_tag():
    """Test that PopenFuture accepts and stores tag parameter."""
    cmd = ["echo", "hello"]
    tag = "test-tag"

    future = PopenFuture(cmd, tag)

    assert future.cmd == cmd
    assert future.tag == tag


def test_popen_future_with_minimal_args():
    """Test that PopenFuture works with minimal required parameters."""
    cmd = ["echo", "hello"]
    tag = "test-minimal"

    future = PopenFuture(cmd, tag)

    assert future.cmd == cmd
    assert future.tag == tag


def test_popen_future_empty_tag_assertion():
    """Test that PopenFuture raises assertion error for empty tag."""
    cmd = ["echo", "hello"]

    try:
        PopenFuture(cmd, "")
        raise AssertionError("Expected AssertionError for empty tag")
    except AssertionError:
        pass  # Expected


def test_interrupt_by_tag():
    """Test that interrupt() cancels futures with matching tags."""
    executor = get_global_executor()

    # Create mock futures with different tags
    future1 = Mock(spec=PopenFuture)
    future1.tag = "tag1"
    future2 = Mock(spec=PopenFuture)
    future2.tag = "tag2"
    future3 = Mock(spec=PopenFuture)
    future3.tag = "tag1"
    future4 = Mock(spec=PopenFuture)
    future4.tag = "tag3"

    # Add to executor's futures list
    executor._futures = [future1, future2, future3, future4]

    # Interrupt tag1
    executor.interrupt("tag1")

    # Check that only futures with tag1 were cancelled
    future1.cancel.assert_called_once()
    future2.cancel.assert_not_called()
    future3.cancel.assert_called_once()
    future4.cancel.assert_not_called()


def test_interrupt_nonexistent_tag():
    """Test that interrupt() with non-existent tag does nothing."""
    executor = get_global_executor()

    # Create mock future
    future = Mock(spec=PopenFuture)
    future.tag = "existing-tag"
    executor._futures = [future]

    # Interrupt with non-existent tag
    executor.interrupt("nonexistent-tag")

    # No futures should be cancelled
    future.cancel.assert_not_called()
