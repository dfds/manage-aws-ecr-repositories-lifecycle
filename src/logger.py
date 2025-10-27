"""
Logging Configuration Module

This module sets up comprehensive logging for the ECR lifecycle management system.
It provides timestamped logging to both console and files with proper rotation.
"""

import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: int = logging.INFO,
    log_dir: str = "logs",
    dry_run: bool = True,
    console_output: bool = True
) -> logging.Logger:
    """
    Set up comprehensive logging for the application.

    Args:
        log_level: Logging level (e.g., logging.INFO, logging.DEBUG)
        log_dir: Directory to store log files
        dry_run: Whether running in dry-run mode (affects log formatting)
        console_output: Whether to output logs to console

    Returns:
        Configured logger instance
    """
    # Ensure log directory exists
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)

    # Create timestamp for log files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_suffix = "dryrun" if dry_run else "apply"
    log_filename = f"ecr_lifecycle_{mode_suffix}_{timestamp}.log"
    log_file_path = log_path / log_filename

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any existing handlers
    root_logger.handlers.clear()

    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )

    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file_path,
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=10,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # Always log everything to file
    file_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(file_handler)

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # Create application-specific logger
    app_logger = logging.getLogger('ecr_lifecycle_manager')

    # Log initial setup information
    app_logger.info(f"Logging initialized - Level: {logging.getLevelName(log_level)}")
    app_logger.info(f"Log file: {log_file_path}")
    app_logger.info(f"Mode: {'DRY RUN' if dry_run else 'APPLY CHANGES'}")

    return app_logger


def setup_aws_logging(log_level: int = logging.WARNING) -> None:
    """
    Configure AWS SDK logging to reduce noise.

    Args:
        log_level: Logging level for AWS SDK logs
    """
    # Reduce AWS SDK logging noise
    aws_loggers = [
        'boto3',
        'botocore',
        'urllib3',
        's3transfer'
    ]

    for logger_name in aws_loggers:
        aws_logger = logging.getLogger(logger_name)
        aws_logger.setLevel(log_level)


class ECROperationLogger:
    """
    Specialized logger for ECR operations with structured logging.
    """

    def __init__(self, logger_name: str = 'ecr_operations'):
        """
        Initialize the ECR operation logger.

        Args:
            logger_name: Name for the logger instance
        """
        self.logger = logging.getLogger(logger_name)
        self.operation_count = 0

    def log_repository_start(self, repository_name: str) -> None:
        """Log the start of processing a repository."""
        self.operation_count += 1
        self.logger.info(f"[{self.operation_count:03d}] Starting repository: {repository_name}")

    def log_repository_result(self, repository_name: str, result: str, details: str = "") -> None:
        """Log the result of processing a repository."""
        status_msg = f"[{self.operation_count:03d}] Repository {repository_name}: {result.upper()}"
        if details:
            status_msg += f" - {details}"

        if result == 'error':
            self.logger.error(status_msg)
        elif result == 'skipped':
            self.logger.info(status_msg)
        else:
            self.logger.info(status_msg)

    def log_backup_created(self, repository_name: str, backup_path: str) -> None:
        """Log when a backup is created."""
        self.logger.info(f"[{self.operation_count:03d}] Backup created for {repository_name}: {backup_path}")

    def log_policy_comparison(self, repository_name: str, is_identical: bool) -> None:
        """Log policy comparison results."""
        if is_identical:
            self.logger.debug(f"[{self.operation_count:03d}] Policy for {repository_name} is identical to target")
        else:
            self.logger.debug(f"[{self.operation_count:03d}] Policy for {repository_name} differs from target")

    def log_statistics(self, stats: dict) -> None:
        """Log final operation statistics."""
        self.logger.info("="*50)
        self.logger.info("OPERATION STATISTICS")
        self.logger.info("="*50)

        for key, value in stats.items():
            formatted_key = key.replace('_', ' ').title()
            self.logger.info(f"{formatted_key}: {value}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Name for the logger

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_aws_session_info(session, logger: Optional[logging.Logger] = None) -> None:
    """
    Log AWS session information for debugging.

    Args:
        session: Boto3 session
        logger: Logger instance (creates new one if not provided)
    """
    if logger is None:
        logger = get_logger('aws_session')

    try:
        credentials = session.get_credentials()
        region = session.region_name

        logger.debug(f"AWS Region: {region}")
        logger.debug(f"AWS Access Key ID: {credentials.access_key[:8]}..." if credentials.access_key else "No access key")
        logger.debug(f"Using temporary credentials: {credentials.token is not None}" if credentials else "No credentials")

    except Exception as e:
        logger.warning(f"Could not retrieve AWS session information: {e}")


def log_policy_details(policy: dict, logger: Optional[logging.Logger] = None) -> None:
    """
    Log lifecycle policy details for debugging.

    Args:
        policy: Lifecycle policy dictionary
        logger: Logger instance (creates new one if not provided)
    """
    if logger is None:
        logger = get_logger('policy_details')

    try:
        rules = policy.get('rules', [])
        logger.debug(f"Lifecycle policy contains {len(rules)} rule(s)")

        for i, rule in enumerate(rules, 1):
            priority = rule.get('rulePriority', 'N/A')
            selection = rule.get('selection', {})
            action = rule.get('action', {})

            logger.debug(f"Rule {i}: Priority={priority}, "
                        f"TagStatus={selection.get('tagStatus', 'N/A')}, "
                        f"Action={action.get('type', 'N/A')}")

    except Exception as e:
        logger.warning(f"Could not log policy details: {e}")
