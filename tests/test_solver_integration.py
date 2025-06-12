# SPDX-License-Identifier: AGPL-3.0

import contextlib
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from halmos.config import Config as HalmosConfig
from halmos.processes import PopenFuture, get_global_executor
from halmos.sevm import SMTQuery
from halmos.solve import PathContext, SolvingContext, solve_low_level


class TestSolverIntegration:
    
    def test_solve_low_level_creates_future_with_tag(self):
        """Test that solve_low_level creates PopenFuture with the correct tag."""
        
        # Create a mock config
        mock_args = Mock(spec=HalmosConfig)
        mock_args.solver_command = "echo"  # Use echo for simplicity
        mock_args.solver_timeout_assertion = 0  # No timeout
        mock_args.verbose = 0
        
        # Create a temporary directory for SMT files
        with tempfile.TemporaryDirectory() as temp_dir:
            solving_ctx = SolvingContext(dump_dir=Path(temp_dir))
            
            # Create a mock SMT query
            mock_query = Mock(spec=SMTQuery)
            mock_query.smtlib = "(assert true)"
            mock_query.assertions = []  # Empty for simplicity
            
            # Create a PathContext with a test tag
            test_tag = "test-function"
            path_ctx = PathContext(
                args=mock_args,
                path_id=123,
                solving_ctx=solving_ctx,
                query=mock_query,
                tag=test_tag
            )
            
            # Track the PopenFuture that gets created
            submitted_futures = []
            
            def mock_submit(future):
                submitted_futures.append(future)
                # Mock the result to avoid actually running
                future.result = Mock(return_value=("sat", "", 0))
                return future
            
            # Mock the global executor's submit method
            with patch.object(get_global_executor(), 'submit', side_effect=mock_submit):
                with contextlib.suppress(Exception):
                    # We expect this might fail due to mocking, that's OK
                    solve_low_level(path_ctx)
                
                # Verify that a future was submitted with the correct tag
                assert len(submitted_futures) == 1
                future = submitted_futures[0]
                assert future.tag == test_tag
                assert isinstance(future, PopenFuture)

    def test_path_context_tag_propagation(self):
        """Test that tags are properly propagated when refining PathContext."""
        
        # Create a temporary directory for SMT files
        with tempfile.TemporaryDirectory() as temp_dir:
            solving_ctx = SolvingContext(dump_dir=Path(temp_dir))
            
            # Create a mock SMT query and config
            mock_query = Mock(spec=SMTQuery) 
            mock_args = Mock(spec=HalmosConfig)
            
            original_tag = "original-tag"
            path_ctx = PathContext(
                args=mock_args,
                path_id=1,
                solving_ctx=solving_ctx,
                query=mock_query,
                tag=original_tag
            )
            
            # Test that refine() preserves the tag
            with patch('halmos.solve.refine', return_value=mock_query):
                refined_ctx = path_ctx.refine()
                
                assert refined_ctx.tag == original_tag
                assert refined_ctx.is_refined
                assert refined_ctx.path_id == path_ctx.path_id

    def test_global_executor_registration(self):
        """Test that executor is properly registered with ExecutorRegistry."""
        
        from halmos.processes import ExecutorRegistry
        
        # Get the global executor
        executor = get_global_executor()
        
        # Check that it's registered
        registry = ExecutorRegistry()
        assert executor in registry._executors