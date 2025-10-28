# AWS ECR Repository Lifecycle Policy Management

A Python-based tool for managing AWS ECR (Elastic Container Registry) repository lifecycle policies across multiple repositories. This tool provides automated policy application, backup functionality, and comprehensive logging for large-scale ECR repository management.

## Features

- **Dry-Run Mode**: Test policy changes without making actual modifications (default behavior)
- **Backup System**: Automatically backs up existing policies before making changes
- **Smart Updates**: Skips repositories that already have the target policy to avoid unnecessary API calls
- **Comprehensive Logging**: Detailed logging with timestamps and rotation for tracking all operations
- **Statistics Reporting**: Summary of operations including repositories updated, skipped, and error counts
- **Policy Validation**: Validates lifecycle policy JSON structure before application
- **AWS Integration**: Full boto3 integration with support for profiles and regions

## Installation

### Prerequisites

- Python 3.8 or higher
- AWS CLI configured with appropriate credentials
- IAM permissions for ECR operations

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dfds/manage-aws-ecr-repositories-lifecycle.git
   cd manage-aws-ecr-repositories-lifecycle
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv replife
   source replife/bin/activate  # On Windows: replife\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install development dependencies (optional):**
   ```bash
   pip install -e ".[dev]"
   ```

## Configuration

### AWS Credentials

Ensure your AWS credentials are configured. The tool supports:

- AWS CLI profiles (`--profile` option)
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- IAM roles (when running on EC2 instances)
- Default AWS credential chain

### Required IAM Permissions

The AWS user/role must have the following ECR permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:DescribeRepositories",
                "ecr:GetLifecyclePolicy",
                "ecr:PutLifecyclePolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

### Lifecycle Policy Configuration

Create or modify the `lifecycle.json` file to define your desired lifecycle policy:

```json
{
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
```

## Usage

### Basic Usage

**Dry run on all repositories (recommended first step):**
```bash
python ecr_lifecycle_manager.py
```

**Apply changes to all repositories:**
```bash
python ecr_lifecycle_manager.py --apply
```

**Target specific repositories:**
```bash
# Dry run on specific repositories
python ecr_lifecycle_manager.py --repositories repo1,repo2,repo3

# Apply changes to specific repositories
python ecr_lifecycle_manager.py --repositories api-service,web-app,database --apply
```

### Advanced Usage

**Use a custom policy file:**
```bash
python ecr_lifecycle_manager.py --policy-file custom-lifecycle.json --apply
```

**Specify AWS profile and region:**
```bash
python ecr_lifecycle_manager.py --profile production --region us-east-1 --apply
```

**Enable debug logging:**
```bash
python ecr_lifecycle_manager.py --log-level DEBUG
```

**Combined examples:**
```bash
# Target specific repos with custom profile and policy
python ecr_lifecycle_manager.py --repositories api-service,web-app --profile production --policy-file prod-lifecycle.json --apply

# Dry run on specific repos with debug logging
python ecr_lifecycle_manager.py --repositories test-repo1,test-repo2 --log-level DEBUG
```

### Command Line Options

```text
usage: ecr_lifecycle_manager.py [-h] [--apply] [--policy-file POLICY_FILE]
                                [--repositories REPOSITORIES] [--profile PROFILE]
                                [--region REGION] [--log-level {DEBUG,INFO,WARNING,ERROR}]

Manage AWS ECR repository lifecycle policies

optional arguments:
  -h, --help            show this help message and exit
  --apply               Apply changes to repositories (default is dry-run mode)
  --policy-file POLICY_FILE
                        Path to the lifecycle policy JSON file (default: lifecycle.json)
  --repositories REPOSITORIES
                        Comma-separated list of repository names to target (default: all repositories)
  --profile PROFILE     AWS profile to use (default: uses default profile or environment credentials)
  --region REGION       AWS region (default: uses profile/environment region)
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Set the logging level (default: INFO)
```

## Repository Targeting

### All Repositories (Default)

When no `--repositories` argument is provided, the script processes all ECR repositories in your AWS account:

```bash
python ecr_lifecycle_manager.py --apply
```

### Specific Repositories

Use the `--repositories` argument to target specific repositories by providing a comma-separated list:

```bash
# Target specific repositories
python ecr_lifecycle_manager.py --repositories repo1,repo2,repo3 --apply

# Spaces around commas are automatically trimmed
python ecr_lifecycle_manager.py --repositories "api-service, web-app, database" --apply
```

### Error Handling for Missing Repositories

The tool validates repository names against your AWS account:

- **Missing repositories**: Logged as errors but don't stop processing of valid repositories
- **Statistics**: Include counts of missing repositories in error statistics
- **Validation**: All repository names are checked before processing begins

Example output when targeting missing repositories:
```text
WARNING: The following repositories do not exist: nonexistent-repo
ERROR: Repository 'nonexistent-repo' not found in AWS account
INFO: Starting to process 2 repositories (out of 3 requested)
```

## Project Structure

```
manage-aws-ecr-repositories-lifecycle/
├── ecr_lifecycle_manager.py    # Main script
├── lifecycle.json              # Default lifecycle policy
├── requirements.txt            # Python dependencies
├── pyproject.toml             # Project configuration
├── setup.cfg                  # Tool configuration
├── README.md                  # This file
├── src/
│   ├── __init__.py           # Package initialization
│   ├── ecr_manager.py        # ECR policy management logic
│   └── logger.py             # Logging configuration
├── tests/
│   ├── __init__.py           # Test package initialization
│   ├── test_ecr_manager.py   # ECR manager tests
│   └── test_logger.py        # Logger tests
├── logs/                     # Generated log files (gitignored)
└── backups/                  # Policy backups (gitignored)
```

## Logging

The tool generates comprehensive logs in the `logs/` directory:

- **File naming**: `ecr_lifecycle_{mode}_{timestamp}.log`
- **Rotation**: Automatic rotation when files exceed 50MB (keeps 10 backups)
- **Content**: Timestamps, operation details, errors, and statistics

Example log entries:
```
2024-10-27 14:30:15 | INFO     | Starting repository: my-app-repo
2024-10-27 14:30:16 | INFO     | Backed up existing policy for my-app-repo to backups/backup_my-app-repo_20241027_143016.json
2024-10-27 14:30:17 | INFO     | [DRY RUN] Would update lifecycle policy for repository: my-app-repo
```

## Backup System

Before applying any policy changes, the tool automatically:

1. Creates timestamped backups of existing policies in the `backups/` directory
2. Names backups as: `backup_{repository_name}_{timestamp}.json`
3. **Sanitizes repository names** for safe filenames (special characters become underscores)
4. Logs backup creation for audit purposes

### Filename Sanitization

Repository names containing special characters are automatically sanitized for backup filenames:

- **Special characters** (`/`, `:`, `@`, `#`, etc.) → replaced with underscores
- **Spaces** → replaced with underscores
- **Multiple consecutive underscores** → collapsed to single underscore
- **Invalid names** (empty or only special chars) → becomes `unnamed_repository`

**Examples:**
```text
my/repo:latest          → backup_my_repo_latest_20241027_143000.json
my repo@service         → backup_my_repo_service_20241027_143000.json
normal-repo             → backup_normal-repo_20241027_143000.json (no change needed)
```

## Migration Context

This tool is designed for organizations migrating from manual ECR lifecycle policy management to automated, consistent policy application across all repositories. It ensures:

- **Zero downtime**: Dry-run mode allows safe testing
- **Audit trail**: Complete logging and backup system
- **Consistency**: Same policy applied across all repositories
- **Safety**: Validation and error handling prevent corruption

## Development

### Code Quality

The project follows strict code quality standards:

- **Style**: Black formatting with 100-character line limit
- **Linting**: Flake8 with custom configuration
- **Type Hints**: Full type annotations for Python 3.8+
- **Documentation**: Comprehensive docstrings for all public functions
- **Testing**: pytest with coverage reporting

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=html
```

### Code Formatting

```bash
# Format code
black .

# Check style
flake8

# Type checking
mypy src/
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure boto3 is installed: `pip install boto3`
2. **Permission Denied**: Verify IAM permissions for ECR operations
3. **Region Issues**: Explicitly set region with `--region` if autodetection fails
4. **Profile Not Found**: Verify AWS profile exists: `aws configure list-profiles`

### Debug Mode

Enable debug logging for detailed troubleshooting:
```bash
python ecr_lifecycle_manager.py --log-level DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following the code quality standards
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the GitHub repository
- Contact the DFDS Engineering team
