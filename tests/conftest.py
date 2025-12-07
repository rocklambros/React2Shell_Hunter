"""Pytest fixtures for React2Shell Hunter tests."""
import os
import pytest
import yaml


@pytest.fixture
def project_root():
    """Return project root directory."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def terraform_dir(project_root):
    """Return terraform directory path."""
    return os.path.join(project_root, 'terraform')


@pytest.fixture
def config_dir(project_root):
    """Return config directory path."""
    return os.path.join(project_root, 'config')


@pytest.fixture
def ioc_config(config_dir):
    """Load IOC configuration."""
    with open(os.path.join(config_dir, 'iocs.yaml'), 'r') as f:
        return yaml.safe_load(f)
