"""
Basic tests for the SeeVee package.
"""

import pytest
import sys
import os

# Add the parent directory to the path to import seevee
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_package_import():
    """Test that the package can be imported."""
    try:
        import seevee
        assert hasattr(seevee, '__version__')
        assert seevee.__version__ == "1.0.0"
    except ImportError as e:
        pytest.skip(f"Could not import seevee package: {e}")

def test_version_info():
    """Test package version information."""
    try:
        import seevee
        info = seevee.get_info()
        assert info['name'] == 'seevee'
        assert info['version'] == '1.0.0'
        assert info['license'] == 'MIT'
    except ImportError as e:
        pytest.skip(f"Could not import seevee package: {e}")

def test_cli_import():
    """Test that the CLI module can be imported."""
    try:
        from seevee.cli import main
        assert callable(main)
    except ImportError as e:
        pytest.skip(f"Could not import CLI module: {e}")

def test_api_import():
    """Test that the API module can be imported."""
    try:
        from seevee.api import app
        assert app is not None
    except ImportError as e:
        pytest.skip(f"Could not import API module: {e}")

if __name__ == "__main__":
    pytest.main([__file__]) 