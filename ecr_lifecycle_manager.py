#!/usr/bin/env python3
"""
AWS ECR Repository Lifecycle Policy Management Script

This script manages AWS ECR (Elastic Container Registry) repository lifecycle policies.
It can apply policies from a JSON file to all ECR repositories in the configured AWS account.

Features:
- Dry-run mode by default (use --apply to make actual changes)
- Backup existing policies before changes
- Comprehensive logging with timestamps
- Statistics reporting
- Skip repositories that already have the target policy
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from src.ecr_manager import ECRPolicyManager
from src.logger import setup_logging


def load_lifecycle_policy(policy_file: str) -> Dict:
    """
    Load the lifecycle policy from the JSON file.

    Args:
        policy_file: Path to the lifecycle policy JSON file

    Returns:
        Dictionary containing the lifecycle policy

    Raises:
        FileNotFoundError: If the policy file doesn't exist
        json.JSONDecodeError: If the policy file contains invalid JSON
    """
    try:
        with open(policy_file, 'r') as file:
            policy = json.load(file)
        logging.info(f"Successfully loaded lifecycle policy from {policy_file}")
        return policy
    except FileNotFoundError:
        logging.error(f"Policy file not found: {policy_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in policy file {policy_file}: {e}")
        raise


def main() -> None:
    """
    Main function to orchestrate the ECR lifecycle policy management.
    """
    parser = argparse.ArgumentParser(
        description="Manage AWS ECR repository lifecycle policies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run on all repositories (default - no changes made):
  python ecr_lifecycle_manager.py

  # Apply changes to all repositories:
  python ecr_lifecycle_manager.py --apply

  # Apply changes to specific repositories:
  python ecr_lifecycle_manager.py --repositories repo1,repo2,repo3 --apply

  # Use custom policy file:
  python ecr_lifecycle_manager.py --policy-file custom-lifecycle.json --apply

  # Specify AWS profile:
  python ecr_lifecycle_manager.py --profile production --apply

  # Target specific repositories with custom profile:
  python ecr_lifecycle_manager.py --repositories api-service,web-app --profile production --apply
        """
    )

    parser.add_argument(
        '--apply',
        action='store_true',
        help='Apply changes to repositories (default is dry-run mode)'
    )

    parser.add_argument(
        '--policy-file',
        default='lifecycle.json',
        help='Path to the lifecycle policy JSON file (default: lifecycle.json)'
    )

    parser.add_argument(
        '--profile',
        help='AWS profile to use (default: uses default profile or environment credentials)'
    )

    parser.add_argument(
        '--region',
        help='AWS region (default: uses profile/environment region)'
    )

    parser.add_argument(
        '--repositories',
        help='Comma-separated list of repository names to target (default: all repositories)'
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set the logging level (default: INFO)'
    )

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(
        log_level=getattr(logging, args.log_level),
        dry_run=not args.apply
    )

    try:
        # Load the lifecycle policy
        policy = load_lifecycle_policy(args.policy_file)

        # Initialize AWS session
        session_kwargs = {}
        if args.profile:
            session_kwargs['profile_name'] = args.profile
        if args.region:
            session_kwargs['region_name'] = args.region

        session = boto3.Session(**session_kwargs)

        # Log configuration
        region = session.region_name or 'default'
        profile = args.profile or 'default'
        mode = "DRY RUN" if not args.apply else "APPLY CHANGES"

        logger.info("="*60)
        logger.info(f"AWS ECR Lifecycle Policy Manager - {mode}")
        logger.info("="*60)
        logger.info(f"AWS Profile: {profile}")
        logger.info(f"AWS Region: {region}")
        logger.info(f"Policy File: {args.policy_file}")
        logger.info(f"Dry Run Mode: {not args.apply}")

        # Parse target repositories
        target_repositories = None
        if args.repositories:
            target_repositories = [repo.strip() for repo in args.repositories.split(',') if repo.strip()]
            logger.info(f"Target Repositories: {', '.join(target_repositories)}")
        else:
            logger.info("Target Repositories: ALL")

        logger.info("="*60)

        # Initialize ECR manager
        ecr_manager = ECRPolicyManager(session, dry_run=not args.apply)

        # Process repositories
        if target_repositories:
            stats = ecr_manager.apply_lifecycle_policy_to_repositories(policy, target_repositories)
        else:
            stats = ecr_manager.apply_lifecycle_policy_to_all_repositories(policy)

        # Display final statistics
        logger.info("="*60)
        logger.info("FINAL STATISTICS")
        logger.info("="*60)
        logger.info(f"Total repositories processed: {stats['total_processed']}")
        logger.info(f"Repositories updated: {stats['updated']}")
        logger.info(f"Repositories skipped (already up-to-date): {stats['skipped']}")
        logger.info(f"Repositories with errors: {stats['errors']}")

        if stats['errors'] > 0:
            logger.warning(f"Completed with {stats['errors']} error(s). Check logs for details.")
            sys.exit(1)
        else:
            logger.info("Completed successfully!")

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
