# AWS ECR Repository Lifecycle policy rules Management

## Project Overview

This repository manages AWS ECR (Elastic Container Registry) repository lifecycle policies.

## Core Architecture

### Policy Evolution Pattern
- `lifecycle.json`: Future repository lifecycle policies.

### Key Files
- **README.md**: Minimal documentation - expand with migration context when updating
- **.gitignore**: Python-focused ignore patterns suggest potential automation tooling

## Development Workflow

### Policy Updates
1. When modifying lifecycle policies, update `lifecycle.json` first
2. Test policies in development ECR repositories before production deployment
3. Validate JSON syntax - policies must be valid IAM policy documents
4. The policy file should never be updated with code. Only manual edits are allowed.

### File Naming Convention
- JSON files should be properly formatted with consistent indentation

## Integration Context

### AWS Resource Patterns
- Lifecycle policies are designed for ECR repository repository lifecycle policies

## Automation Considerations

The `.gitignore` includes Python tooling patterns, suggesting:
- Potential for repository lifecycle policies automation
- JSON validation and formatting tools
- AWS CLI or SDK integration for policy application
- Log file should also be ignored

When adding automation:
- Use boto3 SDK with Python for AWS interactions
- Implement repository lifecycle policies validation before deployment

## Code requirements
- All code must be written in Python 3.8 or higher.
- Follow flake8 style guidelines for Python code.
- Use the black formatter for consistent code formatting.
- Include type hints for all functions and methods.
- Include docstrings for all public modules, functions, and classes.
- Include test cases where applicable.

## Code logic
- Ensure code is modular and reusable.
- Handle exceptions and errors gracefully.
- Loop through all relevant AWS ECR repositories to apply policies.
- Take a backup of existing policies before making changes. Log these backups to a file with the date and time of the change as well as the repository name.
- If a repository already has the new policy, skip updating it to avoid unnecessary API calls.
- Log every action taken, including repositories updated, skipped, and any errors encountered. The log files should be stored in a `logs/` directory with timestamps in the contents and in the filenames for easy tracking.
- By default, the script should run in a "dry run" mode, where it only logs the actions it would take without making any changes. An optional command-line argument can be provided to enable actual updates.
- At the end of the run, it should display statistics summarizing the number of repositories processed, updated, skipped, and any errors encountered.
