# SPDX-License-Identifier: AGPL-3.0

import threading
from unittest.mock import Mock

from halmos.processes import PopenFuture, get_global_executor


class TestGlobalExecutor:
    def test_global_executor_singleton(self):
        """Test that get_global_executor returns the same instance."""
        executor1 = get_global_executor()
        executor2 = get_global_executor()
        
        assert (
            executor1 is executor2
        ), "get_global_executor should return the same instance"

    def test_global_executor_multithreaded(self):
        """Test that get_global_executor works correctly across threads."""
        results = []
        
        def get_executor():
            executor = get_global_executor()
            results.append(executor)
        
        threads = [threading.Thread(target=get_executor) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        
        # All threads should get the same executor instance
        assert len(set(id(executor) for executor in results)) == 1

    def test_popen_future_with_tag(self):
        """Test that PopenFuture accepts and stores tag parameter."""
        cmd = ["echo", "hello"]
        tag = "test-tag"
        
        future = PopenFuture(cmd, tag)
        
        assert future.cmd == cmd
        assert future.tag == tag

    def test_popen_future_with_minimal_args(self):
        """Test that PopenFuture works with minimal required parameters."""
        cmd = ["echo", "hello"]
        tag = "test-minimal"
        
        future = PopenFuture(cmd, tag)
        
        assert future.cmd == cmd
        assert future.tag == tag

    def test_popen_future_empty_tag_assertion(self):
        """Test that PopenFuture raises assertion error for empty tag."""
        cmd = ["echo", "hello"]
        
        try:
            PopenFuture(cmd, "")
            raise AssertionError("Expected AssertionError for empty tag")
        except AssertionError:
            pass  # Expected

    def test_interrupt_by_tag(self):
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

    def test_interrupt_with_empty_tag(self):
        """Test that interrupt() with empty tag raises assertion error."""
        executor = get_global_executor()
        
        # Create mock future
        future = Mock(spec=PopenFuture)
        future.tag = "some-tag"
        executor._futures = [future]
        
        # Interrupt with empty tag should raise assertion error
        try:
            executor.interrupt("")
            raise AssertionError("Expected AssertionError for empty tag")
        except AssertionError:
            pass  # Expected
        
        # No futures should be cancelled
        future.cancel.assert_not_called()

    def test_interrupt_nonexistent_tag(self):
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