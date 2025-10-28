"""
Tests for ECR Policy Manager module.

This module contains comprehensive tests for the ECRPolicyManager class,
including policy validation, backup functionality, and dry-run operations.
"""

import copy
import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.ecr_manager import ECRPolicyManager


class TestECRPolicyManager:
    """Test cases for ECRPolicyManager class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock boto3 session."""
        session = Mock()
        session.client.return_value = Mock()
        return session

    @pytest.fixture
    def ecr_manager(self, mock_session):
        """Create an ECRPolicyManager instance for testing."""
        return ECRPolicyManager(mock_session, dry_run=True)

    @pytest.fixture
    def sample_policy(self):
        """Sample lifecycle policy for testing."""
        return {
            "rules": [
                {
                    "rulePriority": 1,
                    "selection": {
                        "tagStatus": "any",
                        "countType": "imageCountMoreThan",
                        "countNumber": 10
                    },
                    "action": {
                        "type": "expire"
                    }
                }
            ]
        }

    def test_initialization(self, mock_session):
        """Test ECRPolicyManager initialization."""
        manager = ECRPolicyManager(mock_session, dry_run=True)

        assert manager.session == mock_session
        assert manager.dry_run is True
        assert manager.ecr_client == mock_session.client.return_value
        assert isinstance(manager.backup_dir, Path)

    def test_initialization_creates_backup_dir(self, mock_session, tmp_path):
        """Test that initialization creates backup directory."""
        with patch('pathlib.Path') as mock_path:
            mock_path.return_value = tmp_path / "backups"
            manager = ECRPolicyManager(mock_session, dry_run=True)
            # The backup directory should be created during initialization
            assert manager.backup_dir.exists() or mock_path.return_value.mkdir.called

    def test_list_repositories_success(self, ecr_manager):
        """Test successful repository listing."""
        # Mock the paginator
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'repositories': [
                    {'repositoryName': 'repo1'},
                    {'repositoryName': 'repo2'}
                ]
            },
            {
                'repositories': [
                    {'repositoryName': 'repo3'}
                ]
            }
        ]

        ecr_manager.ecr_client.get_paginator.return_value = mock_paginator

        repositories = ecr_manager.list_repositories()

        assert repositories == ['repo1', 'repo2', 'repo3']
        ecr_manager.ecr_client.get_paginator.assert_called_once_with('describe_repositories')

    def test_list_repositories_client_error(self, ecr_manager):
        """Test repository listing with client error."""
        ecr_manager.ecr_client.get_paginator.side_effect = ClientError(
            error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            operation_name='DescribeRepositories'
        )

        with pytest.raises(ClientError):
            ecr_manager.list_repositories()

    def test_get_lifecycle_policy_exists(self, ecr_manager, sample_policy):
        """Test getting existing lifecycle policy."""
        policy_text = json.dumps(sample_policy)
        ecr_manager.ecr_client.get_lifecycle_policy.return_value = {
            'lifecyclePolicyText': policy_text
        }

        result = ecr_manager.get_lifecycle_policy('test-repo')

        assert result == sample_policy
        ecr_manager.ecr_client.get_lifecycle_policy.assert_called_once_with(
            repositoryName='test-repo'
        )

    def test_get_lifecycle_policy_not_found(self, ecr_manager):
        """Test getting lifecycle policy when none exists."""
        ecr_manager.ecr_client.get_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'LifecyclePolicyNotFoundException', 'Message': 'Not found'}},
            operation_name='GetLifecyclePolicy'
        )

        result = ecr_manager.get_lifecycle_policy('test-repo')

        assert result is None

    def test_get_lifecycle_policy_other_error(self, ecr_manager):
        """Test getting lifecycle policy with other client error."""
        ecr_manager.ecr_client.get_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            operation_name='GetLifecyclePolicy'
        )

        with pytest.raises(ClientError):
            ecr_manager.get_lifecycle_policy('test-repo')

    def test_backup_lifecycle_policy(self, ecr_manager, sample_policy, tmp_path):
        """Test backing up a lifecycle policy."""
        # Set up temporary backup directory
        ecr_manager.backup_dir = tmp_path / "backups"
        ecr_manager.backup_dir.mkdir()

        with patch('src.ecr_manager.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "20241027_143000"

            backup_path = ecr_manager.backup_lifecycle_policy('test-repo', sample_policy)

            assert backup_path.endswith('backup_test-repo_20241027_143000.json')

            # Verify backup file was created and contains correct content
            backup_file = Path(backup_path)
            assert backup_file.exists()

            with open(backup_file, 'r') as f:
                backed_up_policy = json.load(f)

            assert backed_up_policy == sample_policy

    def test_policies_are_identical_true(self, ecr_manager, sample_policy):
        """Test policy comparison with identical policies."""
        policy1 = sample_policy.copy()
        policy2 = sample_policy.copy()

        result = ecr_manager.policies_are_identical(policy1, policy2)

        assert result is True

    def test_policies_are_identical_false(self, ecr_manager, sample_policy):
        """Test policy comparison with different policies."""
        policy1 = copy.deepcopy(sample_policy)
        policy2 = copy.deepcopy(sample_policy)
        policy2['rules'][0]['rulePriority'] = 2

        result = ecr_manager.policies_are_identical(policy1, policy2)

        assert result is False

    def test_policies_are_identical_different_order(self, ecr_manager):
        """Test policy comparison with same content, different order."""
        policy1 = {
            "rules": [
                {"rulePriority": 1, "selection": {"tagStatus": "any"}, "action": {"type": "expire"}},
                {"rulePriority": 2, "selection": {"tagStatus": "tagged"}, "action": {"type": "expire"}}
            ]
        }
        policy2 = {
            "rules": [
                {"rulePriority": 2, "selection": {"tagStatus": "tagged"}, "action": {"type": "expire"}},
                {"rulePriority": 1, "selection": {"tagStatus": "any"}, "action": {"type": "expire"}}
            ]
        }

        # Policies with different order should be considered different
        result = ecr_manager.policies_are_identical(policy1, policy2)

        assert result is False

    def test_set_lifecycle_policy_dry_run(self, ecr_manager, sample_policy):
        """Test setting lifecycle policy in dry-run mode."""
        result = ecr_manager.set_lifecycle_policy('test-repo', sample_policy)

        assert result is True
        # Should not call the actual AWS API in dry-run mode
        ecr_manager.ecr_client.put_lifecycle_policy.assert_not_called()

    def test_set_lifecycle_policy_apply_mode(self, mock_session, sample_policy):
        """Test setting lifecycle policy in apply mode."""
        manager = ECRPolicyManager(mock_session, dry_run=False)

        result = manager.set_lifecycle_policy('test-repo', sample_policy)

        assert result is True
        manager.ecr_client.put_lifecycle_policy.assert_called_once_with(
            repositoryName='test-repo',
            lifecyclePolicyText=json.dumps(sample_policy, separators=(',', ':'))
        )

    def test_set_lifecycle_policy_client_error(self, mock_session, sample_policy):
        """Test setting lifecycle policy with client error."""
        manager = ECRPolicyManager(mock_session, dry_run=False)
        manager.ecr_client.put_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            operation_name='PutLifecyclePolicy'
        )

        result = manager.set_lifecycle_policy('test-repo', sample_policy)

        assert result is False

    def test_validate_lifecycle_policy_valid(self, ecr_manager, sample_policy):
        """Test validation of a valid lifecycle policy."""
        is_valid, errors = ecr_manager.validate_lifecycle_policy(sample_policy)

        assert is_valid is True
        assert errors == []

    def test_validate_lifecycle_policy_invalid_structure(self, ecr_manager):
        """Test validation of invalid policy structure."""
        invalid_policy = "not a dict"

        is_valid, errors = ecr_manager.validate_lifecycle_policy(invalid_policy)

        assert is_valid is False
        assert "Policy must be a dictionary" in errors

    def test_validate_lifecycle_policy_missing_rules(self, ecr_manager):
        """Test validation of policy missing rules."""
        invalid_policy = {"notRules": []}

        is_valid, errors = ecr_manager.validate_lifecycle_policy(invalid_policy)

        assert is_valid is False
        assert "Policy must contain 'rules' key" in errors

    def test_validate_lifecycle_policy_empty_rules(self, ecr_manager):
        """Test validation of policy with empty rules."""
        invalid_policy = {"rules": []}

        is_valid, errors = ecr_manager.validate_lifecycle_policy(invalid_policy)

        assert is_valid is False
        assert "'rules' list cannot be empty" in errors

    def test_validate_lifecycle_policy_invalid_rule(self, ecr_manager):
        """Test validation of policy with invalid rule."""
        invalid_policy = {
            "rules": [
                {
                    "rulePriority": 1,
                    # Missing required fields: selection, action
                }
            ]
        }

        is_valid, errors = ecr_manager.validate_lifecycle_policy(invalid_policy)

        assert is_valid is False
        assert "Rule 1 missing required field: selection" in errors
        assert "Rule 1 missing required field: action" in errors

    def test_apply_lifecycle_policy_to_repository_new_policy(self, ecr_manager, sample_policy, tmp_path):
        """Test applying policy to repository with no existing policy."""
        ecr_manager.backup_dir = tmp_path / "backups"
        ecr_manager.backup_dir.mkdir()

        # Mock no existing policy
        ecr_manager.ecr_client.get_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'LifecyclePolicyNotFoundException', 'Message': 'Not found'}},
            operation_name='GetLifecyclePolicy'
        )

        result = ecr_manager.apply_lifecycle_policy_to_repository('test-repo', sample_policy)

        assert result == 'updated'

    def test_apply_lifecycle_policy_to_repository_same_policy(self, ecr_manager, sample_policy):
        """Test applying policy to repository with identical existing policy."""
        policy_text = json.dumps(sample_policy)
        ecr_manager.ecr_client.get_lifecycle_policy.return_value = {
            'lifecyclePolicyText': policy_text
        }

        result = ecr_manager.apply_lifecycle_policy_to_repository('test-repo', sample_policy)

        assert result == 'skipped'

    def test_apply_lifecycle_policy_to_all_repositories(self, ecr_manager, sample_policy):
        """Test applying policy to all repositories."""
        # Mock repository list
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'repositories': [{'repositoryName': 'repo1'}, {'repositoryName': 'repo2'}]}
        ]
        ecr_manager.ecr_client.get_paginator.return_value = mock_paginator

        # Mock no existing policies
        ecr_manager.ecr_client.get_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'LifecyclePolicyNotFoundException', 'Message': 'Not found'}},
            operation_name='GetLifecyclePolicy'
        )

        with patch.object(ecr_manager, 'backup_dir', Path('/tmp/test_backups')):
            stats = ecr_manager.apply_lifecycle_policy_to_all_repositories(sample_policy)

        assert stats['total_processed'] == 2
        assert stats['updated'] == 2
        assert stats['skipped'] == 0
        assert stats['errors'] == 0

    def test_apply_lifecycle_policy_to_repositories_valid_repos(self, ecr_manager, sample_policy):
        """Test applying policy to specific repositories that exist."""
        target_repos = ['repo1', 'repo3']

        # Mock repository list
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'repositories': [
                {'repositoryName': 'repo1'},
                {'repositoryName': 'repo2'},
                {'repositoryName': 'repo3'}
            ]}
        ]
        ecr_manager.ecr_client.get_paginator.return_value = mock_paginator

        # Mock no existing policies
        ecr_manager.ecr_client.get_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'LifecyclePolicyNotFoundException', 'Message': 'Not found'}},
            operation_name='GetLifecyclePolicy'
        )

        with patch.object(ecr_manager, 'backup_dir', Path('/tmp/test_backups')):
            stats = ecr_manager.apply_lifecycle_policy_to_repositories(sample_policy, target_repos)

        assert stats['total_processed'] == 2
        assert stats['updated'] == 2
        assert stats['skipped'] == 0
        assert stats['errors'] == 0

    def test_apply_lifecycle_policy_to_repositories_missing_repos(self, ecr_manager, sample_policy):
        """Test applying policy to repositories where some don't exist."""
        target_repos = ['repo1', 'nonexistent-repo', 'repo3']

        # Mock repository list (missing 'nonexistent-repo')
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'repositories': [
                {'repositoryName': 'repo1'},
                {'repositoryName': 'repo2'},
                {'repositoryName': 'repo3'}
            ]}
        ]
        ecr_manager.ecr_client.get_paginator.return_value = mock_paginator

        # Mock no existing policies
        ecr_manager.ecr_client.get_lifecycle_policy.side_effect = ClientError(
            error_response={'Error': {'Code': 'LifecyclePolicyNotFoundException', 'Message': 'Not found'}},
            operation_name='GetLifecyclePolicy'
        )

        with patch.object(ecr_manager, 'backup_dir', Path('/tmp/test_backups')):
            stats = ecr_manager.apply_lifecycle_policy_to_repositories(sample_policy, target_repos)

        assert stats['total_processed'] == 3  # All requested repos
        assert stats['updated'] == 2  # Only existing repos
        assert stats['skipped'] == 0
        assert stats['errors'] == 1  # Missing repo

    def test_apply_lifecycle_policy_to_repositories_empty_list(self, ecr_manager, sample_policy):
        """Test applying policy to empty repository list."""
        target_repos = []

        # Mock repository list
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'repositories': [{'repositoryName': 'repo1'}]}
        ]
        ecr_manager.ecr_client.get_paginator.return_value = mock_paginator

        stats = ecr_manager.apply_lifecycle_policy_to_repositories(sample_policy, target_repos)

        assert stats['total_processed'] == 0
        assert stats['updated'] == 0
        assert stats['skipped'] == 0
        assert stats['errors'] == 0

    def test_sanitize_filename_normal_name(self, ecr_manager):
        """Test filename sanitization with normal repository name."""
        result = ecr_manager._sanitize_filename('my-repo')
        assert result == 'my-repo'

    def test_sanitize_filename_with_special_chars(self, ecr_manager):
        """Test filename sanitization with special characters."""
        result = ecr_manager._sanitize_filename('my/repo:latest')
        assert result == 'my_repo_latest'

    def test_sanitize_filename_with_spaces_and_symbols(self, ecr_manager):
        """Test filename sanitization with spaces and various symbols."""
        result = ecr_manager._sanitize_filename('my repo@#$%^&*()+name')
        assert result == 'my_repo_name'

    def test_sanitize_filename_with_multiple_underscores(self, ecr_manager):
        """Test that multiple consecutive underscores are cleaned up."""
        result = ecr_manager._sanitize_filename('my///repo:::name')
        assert result == 'my_repo_name'

    def test_sanitize_filename_empty_or_invalid(self, ecr_manager):
        """Test filename sanitization with empty or invalid input."""
        result = ecr_manager._sanitize_filename('///.:::#@!')
        assert result == 'unnamed_repository'

        result = ecr_manager._sanitize_filename('')
        assert result == 'unnamed_repository'

    def test_backup_lifecycle_policy_with_special_chars(self, ecr_manager, sample_policy, tmp_path):
        """Test backing up a policy with special characters in repository name."""
        # Set up temporary backup directory
        ecr_manager.backup_dir = tmp_path / "backups"
        ecr_manager.backup_dir.mkdir()

        with patch('src.ecr_manager.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "20241027_143000"

            backup_path = ecr_manager.backup_lifecycle_policy('my/repo:latest', sample_policy)

            # Verify the filename is sanitized
            expected_filename = "backup_my_repo_latest_20241027_143000.json"
            assert backup_path.endswith(expected_filename)

            # Verify backup file was created and contains correct content
            backup_file = Path(backup_path)
            assert backup_file.exists()

            with open(backup_file, 'r') as f:
                backed_up_policy = json.load(f)

            assert backed_up_policy == sample_policy


class TestPolicyValidation:
    """Test cases specifically for policy validation functionality."""

    @pytest.fixture
    def ecr_manager(self):
        """Create an ECRPolicyManager instance for testing."""
        session = Mock()
        return ECRPolicyManager(session, dry_run=True)

    def test_validate_complex_policy(self, ecr_manager):
        """Test validation of a complex, valid policy."""
        complex_policy = {
            "rules": [
                {
                    "rulePriority": 1,
                    "selection": {
                        "tagStatus": "tagged",
                        "tagPrefixList": ["v1.", "v2."],
                        "countType": "imageCountMoreThan",
                        "countNumber": 5
                    },
                    "action": {
                        "type": "expire"
                    }
                },
                {
                    "rulePriority": 2,
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "sinceImagePushed",
                        "countUnit": "days",
                        "countNumber": 30
                    },
                    "action": {
                        "type": "expire"
                    }
                }
            ]
        }

        is_valid, errors = ecr_manager.validate_lifecycle_policy(complex_policy)

        assert is_valid is True
        assert errors == []

    def test_validate_policy_with_invalid_selection(self, ecr_manager):
        """Test validation of policy with invalid selection."""
        invalid_policy = {
            "rules": [
                {
                    "rulePriority": 1,
                    "selection": "not a dict",  # Should be a dictionary
                    "action": {
                        "type": "expire"
                    }
                }
            ]
        }

        is_valid, errors = ecr_manager.validate_lifecycle_policy(invalid_policy)

        assert is_valid is False
        assert "Rule 1 'selection' must be a dictionary" in errors

    def test_validate_policy_with_invalid_action(self, ecr_manager):
        """Test validation of policy with invalid action."""
        invalid_policy = {
            "rules": [
                {
                    "rulePriority": 1,
                    "selection": {
                        "tagStatus": "any"
                    },
                    "action": {
                        # Missing 'type' field
                    }
                }
            ]
        }

        is_valid, errors = ecr_manager.validate_lifecycle_policy(invalid_policy)

        assert is_valid is False
        assert "Rule 1 action missing required field: type" in errors
