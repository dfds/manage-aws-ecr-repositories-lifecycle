"""
ECR Policy Manager Module

This module provides functionality to manage AWS ECR repository lifecycle policies.
It handles policy application, backup, and validation operations.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError


class ECRPolicyManager:
    """
    Manages AWS ECR repository lifecycle policies.

    This class provides methods to:
    - List ECR repositories
    - Get and set lifecycle policies
    - Backup existing policies
    - Compare policies to avoid unnecessary updates
    """

    def __init__(self, session: boto3.Session, dry_run: bool = True):
        """
        Initialize the ECR Policy Manager.

        Args:
            session: Boto3 session with configured credentials
            dry_run: If True, only log actions without making changes
        """
        self.session = session
        self.dry_run = dry_run
        self.ecr_client = session.client('ecr')
        self.logger = logging.getLogger(__name__)

        # Ensure backup directory exists
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)

    def list_repositories(self) -> List[str]:
        """
        List all ECR repositories in the AWS account.

        Returns:
            List of repository names

        Raises:
            ClientError: If AWS API call fails
        """
        repositories = []
        try:
            paginator = self.ecr_client.get_paginator('describe_repositories')

            for page in paginator.paginate():
                for repo in page['repositories']:
                    repositories.append(repo['repositoryName'])

            self.logger.info(f"Found {len(repositories)} ECR repositories")
            return repositories

        except ClientError as e:
            self.logger.error(f"Failed to list ECR repositories: {e}")
            raise

    def get_lifecycle_policy(self, repository_name: str) -> Optional[Dict]:
        """
        Get the current lifecycle policy for a repository.

        Args:
            repository_name: Name of the ECR repository

        Returns:
            Lifecycle policy as dictionary, or None if no policy exists

        Raises:
            ClientError: If AWS API call fails (except for LifecyclePolicyNotFoundException)
        """
        try:
            response = self.ecr_client.get_lifecycle_policy(
                repositoryName=repository_name
            )
            return json.loads(response['lifecyclePolicyText'])

        except ClientError as e:
            if e.response['Error']['Code'] == 'LifecyclePolicyNotFoundException':
                self.logger.debug(f"No lifecycle policy found for repository: {repository_name}")
                return None
            else:
                self.logger.error(f"Failed to get lifecycle policy for {repository_name}: {e}")
                raise

    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a string to be safe for use as a filename.

        Replaces special characters and filesystem-unsafe characters with underscores.

        Args:
            filename: The original filename string

        Returns:
            Sanitized filename string safe for filesystem use
        """
        # Replace any character that's not alphanumeric, dash, or dot with underscore
        # This covers slashes, spaces, and other special characters
        sanitized = re.sub(r'[^\w\-.]', '_', filename)

        # Remove multiple consecutive underscores and clean up
        sanitized = re.sub(r'_{2,}', '_', sanitized)
        sanitized = sanitized.strip('_')

        # Ensure it's not empty and not just dots
        if not sanitized or sanitized.replace('.', '').replace('_', '') == '':
            sanitized = 'unnamed_repository'

        return sanitized

    def backup_lifecycle_policy(self, repository_name: str, policy: Dict) -> str:
        """
        Backup an existing lifecycle policy to a file.

        Args:
            repository_name: Name of the ECR repository
            policy: Current lifecycle policy to backup

        Returns:
            Path to the backup file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize repository name for filename - replace special characters with underscores
        safe_repo_name = self._sanitize_filename(repository_name)
        backup_filename = f"backup_{safe_repo_name}_{timestamp}.json"
        backup_path = self.backup_dir / backup_filename

        try:
            with open(backup_path, 'w') as backup_file:
                json.dump(policy, backup_file, indent=2)

            # Log with clarification if repository name was sanitized
            if safe_repo_name != repository_name:
                self.logger.info(f"Backed up existing policy for '{repository_name}' to {backup_path} (filename sanitized: '{repository_name}' -> '{safe_repo_name}')")
            else:
                self.logger.info(f"Backed up existing policy for {repository_name} to {backup_path}")
            return str(backup_path)

        except Exception as e:
            self.logger.error(f"Failed to backup policy for {repository_name}: {e}")
            raise

    def policies_are_identical(self, policy1: Dict, policy2: Dict) -> bool:
        """
        Compare two lifecycle policies to determine if they are identical.

        Args:
            policy1: First policy to compare
            policy2: Second policy to compare

        Returns:
            True if policies are identical, False otherwise
        """
        try:
            # Normalize policies by converting to JSON strings and back
            # This ensures consistent formatting for comparison
            normalized_policy1 = json.loads(json.dumps(policy1, sort_keys=True))
            normalized_policy2 = json.loads(json.dumps(policy2, sort_keys=True))

            return normalized_policy1 == normalized_policy2

        except Exception as e:
            self.logger.error(f"Error comparing policies: {e}")
            return False

    def set_lifecycle_policy(self, repository_name: str, policy: Dict) -> bool:
        """
        Set the lifecycle policy for a repository.

        Args:
            repository_name: Name of the ECR repository
            policy: Lifecycle policy to apply

        Returns:
            True if policy was set successfully, False otherwise
        """
        try:
            policy_text = json.dumps(policy, separators=(',', ':'))

            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would set lifecycle policy for repository: {repository_name}")
                return True
            else:
                self.ecr_client.put_lifecycle_policy(
                    repositoryName=repository_name,
                    lifecyclePolicyText=policy_text
                )
                self.logger.info(f"Successfully set lifecycle policy for repository: {repository_name}")
                return True

        except ClientError as e:
            self.logger.error(f"Failed to set lifecycle policy for {repository_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error setting policy for {repository_name}: {e}")
            return False

    def apply_lifecycle_policy_to_repository(self, repository_name: str, new_policy: Dict) -> str:
        """
        Apply a lifecycle policy to a single repository.

        Args:
            repository_name: Name of the ECR repository
            new_policy: Lifecycle policy to apply

        Returns:
            Status string: 'updated', 'skipped', or 'error'
        """
        try:
            self.logger.debug(f"Processing repository: {repository_name}")

            # Get current policy
            current_policy = self.get_lifecycle_policy(repository_name)

            # Check if policies are identical
            if current_policy and self.policies_are_identical(current_policy, new_policy):
                self.logger.info(f"Repository {repository_name} already has the target policy - skipping")
                return 'skipped'

            # Backup existing policy if it exists
            if current_policy:
                self.backup_lifecycle_policy(repository_name, current_policy)
            else:
                self.logger.info(f"No existing policy to backup for repository: {repository_name}")

            # Apply new policy
            if self.set_lifecycle_policy(repository_name, new_policy):
                action = "[DRY RUN] Would update" if self.dry_run else "Updated"
                self.logger.info(f"{action} lifecycle policy for repository: {repository_name}")
                return 'updated'
            else:
                return 'error'

        except Exception as e:
            self.logger.error(f"Error processing repository {repository_name}: {e}", exc_info=True)
            return 'error'

    def apply_lifecycle_policy_to_repositories(self, policy: Dict, repository_names: List[str]) -> Dict[str, int]:
        """
        Apply a lifecycle policy to a specific list of ECR repositories.

        Args:
            policy: Lifecycle policy to apply to repositories
            repository_names: List of repository names to target

        Returns:
            Dictionary with statistics: total_processed, updated, skipped, errors
        """
        stats = {
            'total_processed': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0
        }

        try:
            # Validate that repositories exist
            all_repositories = self.list_repositories()
            missing_repos = [repo for repo in repository_names if repo not in all_repositories]

            if missing_repos:
                self.logger.warning(f"The following repositories do not exist: {', '.join(missing_repos)}")
                for missing_repo in missing_repos:
                    self.logger.error(f"Repository '{missing_repo}' not found in AWS account")
                    stats['errors'] += 1

            # Filter to only process existing repositories
            existing_repos = [repo for repo in repository_names if repo in all_repositories]
            stats['total_processed'] = len(repository_names)  # Count all requested repos

            if not existing_repos:
                self.logger.warning("No valid ECR repositories to process")
                return stats

            self.logger.info(f"Starting to process {len(existing_repos)} repositories")

            for repo_name in existing_repos:
                result = self.apply_lifecycle_policy_to_repository(repo_name, policy)
                stats[result] += 1

                # Log progress
                processed = stats['updated'] + stats['skipped'] + stats['errors']
                self.logger.info(f"Progress: {processed}/{len(repository_names)} repositories processed")

        except Exception as e:
            self.logger.error(f"Error processing repositories: {e}", exc_info=True)
            # Count remaining unprocessed repos as errors
            remaining = len(repository_names) - stats['updated'] - stats['skipped'] - stats['errors']
            stats['errors'] += remaining

        return stats

    def apply_lifecycle_policy_to_all_repositories(self, policy: Dict) -> Dict[str, int]:
        """
        Apply a lifecycle policy to all ECR repositories.

        Args:
            policy: Lifecycle policy to apply to all repositories

        Returns:
            Dictionary with statistics: total_processed, updated, skipped, errors
        """
        stats = {
            'total_processed': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0
        }

        try:
            repositories = self.list_repositories()
            stats['total_processed'] = len(repositories)

            if not repositories:
                self.logger.warning("No ECR repositories found")
                return stats

            self.logger.info(f"Starting to process {len(repositories)} repositories")

            for repo_name in repositories:
                result = self.apply_lifecycle_policy_to_repository(repo_name, policy)
                stats[result] += 1

                # Log progress
                processed = stats['updated'] + stats['skipped'] + stats['errors']
                self.logger.info(f"Progress: {processed}/{len(repositories)} repositories processed")

        except Exception as e:
            self.logger.error(f"Error processing repositories: {e}", exc_info=True)
            stats['errors'] = stats['total_processed'] - stats['updated'] - stats['skipped']

        return stats

    def validate_lifecycle_policy(self, policy: Dict) -> Tuple[bool, List[str]]:
        """
        Validate a lifecycle policy structure.

        Args:
            policy: Lifecycle policy to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check for required top-level structure
        if not isinstance(policy, dict):
            errors.append("Policy must be a dictionary")
            return False, errors

        if 'rules' not in policy:
            errors.append("Policy must contain 'rules' key")
            return False, errors

        rules = policy['rules']
        if not isinstance(rules, list):
            errors.append("'rules' must be a list")
            return False, errors

        if not rules:
            errors.append("'rules' list cannot be empty")
            return False, errors

        # Validate each rule
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i+1} must be a dictionary")
                continue

            # Check required fields
            required_fields = ['rulePriority', 'selection', 'action']
            for field in required_fields:
                if field not in rule:
                    errors.append(f"Rule {i+1} missing required field: {field}")

            # Validate selection
            if 'selection' in rule:
                selection = rule['selection']
                if not isinstance(selection, dict):
                    errors.append(f"Rule {i+1} 'selection' must be a dictionary")
                else:
                    required_selection_fields = ['tagStatus']
                    for field in required_selection_fields:
                        if field not in selection:
                            errors.append(f"Rule {i+1} selection missing required field: {field}")

            # Validate action
            if 'action' in rule:
                action = rule['action']
                if not isinstance(action, dict):
                    errors.append(f"Rule {i+1} 'action' must be a dictionary")
                elif 'type' not in action:
                    errors.append(f"Rule {i+1} action missing required field: type")

        return len(errors) == 0, errors
