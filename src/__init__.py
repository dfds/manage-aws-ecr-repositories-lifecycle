"""
AWS ECR Repository Lifecycle Policy Management Package

This package provides tools to manage AWS ECR repository lifecycle policies.
"""

__version__ = "1.0.0"
__author__ = "DFDS Engineering"
__email__ = "engineering@dfds.com"

from .ecr_manager import ECRPolicyManager
from .logger import setup_logging, ECROperationLogger

__all__ = [
    "ECRPolicyManager",
    "setup_logging",
    "ECROperationLogger"
]
