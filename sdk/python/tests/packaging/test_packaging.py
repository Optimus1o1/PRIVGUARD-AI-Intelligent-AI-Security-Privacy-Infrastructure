"""Packaging metadata and distribution tests."""

from pathlib import Path

import privguard_sdk


def test_package_version_and_imports():
    assert privguard_sdk.__version__ == "0.1.0"
    assert hasattr(privguard_sdk, "PrivGuardClient")
    assert hasattr(privguard_sdk, "AsyncPrivGuardClient")
    assert hasattr(privguard_sdk, "verify_export_package")


def test_py_typed_marker_present():
    pkg_dir = Path(privguard_sdk.__file__).parent
    py_typed_file = pkg_dir / "py.typed"
    assert py_typed_file.exists(), "py.typed marker must be present in package root"


def test_pyproject_toml_configuration():
    sdk_root = Path(__file__).parent.parent.parent
    pyproject_file = sdk_root / "pyproject.toml"
    assert pyproject_file.exists()

    content = pyproject_file.read_text(encoding="utf-8")
    assert 'name = "privguard-sdk"' in content
    assert 'version = "0.1.0"' in content
    assert "hatchling.build" in content
