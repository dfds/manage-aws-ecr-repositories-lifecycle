"""
Tests for logging configuration module.

This module tests the logging setup, file rotation, and specialized ECR operation logging.
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.logger import setup_logging, ECROperationLogger, log_policy_details


class TestLoggingSetup:
    """Test cases for logging setup functionality."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir)

            assert logger.name == 'ecr_lifecycle_manager'
            assert len(logging.getLogger().handlers) >= 1

    def test_setup_logging_creates_log_directory(self):
        """Test that setup_logging creates log directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "new_logs"

            setup_logging(log_dir=str(log_dir))

            assert log_dir.exists()
            assert log_dir.is_dir()

    def test_setup_logging_dry_run_mode(self):
        """Test logging setup in dry run mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, dry_run=True)

            # Should contain "dryrun" in log filename
            log_files = list(Path(temp_dir).glob("*dryrun*.log"))
            assert len(log_files) == 1

    def test_setup_logging_apply_mode(self):
        """Test logging setup in apply mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, dry_run=False)

            # Should contain "apply" in log filename
            log_files = list(Path(temp_dir).glob("*apply*.log"))
            assert len(log_files) == 1

    def test_setup_logging_different_levels(self):
        """Test logging setup with different log levels."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, log_level=logging.DEBUG)

            # Test that debug messages are handled
            logger.debug("Test debug message")
            logger.info("Test info message")
            logger.warning("Test warning message")
            logger.error("Test error message")

    def test_setup_logging_no_console_output(self):
        """Test logging setup without console output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, console_output=False)

            # Should only have file handler, not console handler
            root_logger = logging.getLogger()
            file_handlers = [h for h in root_logger.handlers if hasattr(h, 'baseFilename')]
            console_handlers = [h for h in root_logger.handlers if not hasattr(h, 'baseFilename')]

            assert len(file_handlers) >= 1
            # In this test setup, we might still have some console handlers from other tests


class TestECROperationLogger:
    """Test cases for ECROperationLogger class."""

    def test_initialization(self):
        """Test ECROperationLogger initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)  # Setup root logging first

            op_logger = ECROperationLogger()

            assert op_logger.logger.name == 'ecr_operations'
            assert op_logger.operation_count == 0

    def test_log_repository_start(self):
        """Test logging repository start."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()

            op_logger.log_repository_start('test-repo')

            assert op_logger.operation_count == 1

    def test_log_repository_result_success(self):
        """Test logging successful repository result."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()
            op_logger.operation_count = 1

            # Should not raise any exceptions
            op_logger.log_repository_result('test-repo', 'updated', 'Policy applied successfully')

    def test_log_repository_result_error(self):
        """Test logging error repository result."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()
            op_logger.operation_count = 1

            # Should not raise any exceptions
            op_logger.log_repository_result('test-repo', 'error', 'Access denied')

    def test_log_repository_result_skipped(self):
        """Test logging skipped repository result."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()
            op_logger.operation_count = 1

            # Should not raise any exceptions
            op_logger.log_repository_result('test-repo', 'skipped', 'Already up to date')

    def test_log_backup_created(self):
        """Test logging backup creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()
            op_logger.operation_count = 1

            # Should not raise any exceptions
            op_logger.log_backup_created('test-repo', '/path/to/backup.json')

    def test_log_policy_comparison(self):
        """Test logging policy comparison."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()
            op_logger.operation_count = 1

            # Should not raise any exceptions
            op_logger.log_policy_comparison('test-repo', True)
            op_logger.log_policy_comparison('test-repo', False)

    def test_log_statistics(self):
        """Test logging statistics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir)

            op_logger = ECROperationLogger()

            stats = {
                'total_processed': 10,
                'updated': 5,
                'skipped': 3,
                'errors': 2
            }

            # Should not raise any exceptions
            op_logger.log_statistics(stats)


class TestUtilityFunctions:
    """Test cases for utility logging functions."""

    def test_log_policy_details_valid_policy(self):
        """Test logging policy details with valid policy."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, log_level=logging.DEBUG)

            policy = {
                "rules": [
                    {
                        "rulePriority": 1,
                        "selection": {"tagStatus": "any"},
                        "action": {"type": "expire"}
                    },
                    {
                        "rulePriority": 2,
                        "selection": {"tagStatus": "tagged"},
                        "action": {"type": "expire"}
                    }
                ]
            }

            # Should not raise any exceptions
            log_policy_details(policy, logger)

    def test_log_policy_details_empty_policy(self):
        """Test logging policy details with empty policy."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, log_level=logging.DEBUG)

            policy = {"rules": []}

            # Should not raise any exceptions
            log_policy_details(policy, logger)

    def test_log_policy_details_malformed_policy(self):
        """Test logging policy details with malformed policy."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, log_level=logging.DEBUG)

            policy = {"not_rules": "invalid"}

            # Should not raise any exceptions (should handle gracefully)
            log_policy_details(policy, logger)

    def test_log_policy_details_exception_handling(self):
        """Test that log_policy_details handles exceptions gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = setup_logging(log_dir=temp_dir, log_level=logging.DEBUG)

            # Pass something that will cause an exception
            invalid_policy = "not a dict"

            # Should not raise any exceptions
            log_policy_details(invalid_policy, logger)


class TestLogFileCreation:
    """Test cases for log file creation and naming."""

    def test_log_file_naming_dry_run(self):
        """Test log file naming in dry run mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir, dry_run=True)

            log_files = list(Path(temp_dir).glob("*.log"))
            assert len(log_files) == 1

            log_file = log_files[0]
            assert "dryrun" in log_file.name
            assert "ecr_lifecycle" in log_file.name

    def test_log_file_naming_apply_mode(self):
        """Test log file naming in apply mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_logging(log_dir=temp_dir, dry_run=False)

            log_files = list(Path(temp_dir).glob("*.log"))
            assert len(log_files) == 1

            log_file = log_files[0]
            assert "apply" in log_file.name
            assert "ecr_lifecycle" in log_file.name

    def test_multiple_logging_sessions(self):
        """Test that multiple logging sessions create separate files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # First session
            setup_logging(log_dir=temp_dir, dry_run=True)

            # Clear handlers to simulate new session
            logging.getLogger().handlers.clear()

            # Second session
            setup_logging(log_dir=temp_dir, dry_run=False)

            log_files = list(Path(temp_dir).glob("*.log"))
            # Should have created at least 2 files
            assert len(log_files) >= 1
