"""Custom build backend that builds libaegis with Zig before building the Python package."""

import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import build_meta as _orig


def _check_zig_available():
    """Check if Zig is installed and available."""
    if shutil.which("zig") is None:
        raise RuntimeError(
            "\n" + "=" * 70 + "\n"
            "ERROR: Zig compiler not found!\n"
            "\n"
            "Building pyaegis requires the Zig compiler to build the libaegis\n"
            "static library. Please install Zig before building this package.\n"
            "\n"
            "Installation instructions:\n"
            "  - Visit: https://ziglang.org/download/\n"
            "  - Or use a package manager:\n"
            "    * macOS:   brew install zig\n"
            "    * Linux:   See https://github.com/ziglang/zig/wiki/Install-Zig-from-a-Package-Manager\n"
            "    * Windows: choco install zig  or  scoop install zig\n"
            "\n"
            "After installing Zig, please try building again.\n" + "=" * 70 + "\n"
        )


def _build_libaegis():
    """Build libaegis static library with Zig."""
    # Check Zig availability first
    _check_zig_available()

    libaegis_dir = Path(__file__).parent / "libaegis"
    if not libaegis_dir.exists():
        raise FileNotFoundError(
            f"libaegis directory not found at {libaegis_dir}. "
            "Cannot build static library."
        )

    print("Building libaegis static library with Zig...")
    try:
        subprocess.run(
            ["zig", "build", "-Drelease"],
            cwd=libaegis_dir,
            check=True,
            capture_output=False,
        )
        print("Successfully built libaegis static library")
    except subprocess.CalledProcessError as e:
        print(
            f"\nError: Zig build failed with exit code {e.returncode}\n"
            f"Command: {' '.join(e.cmd)}\n",
            file=sys.stderr,
        )
        raise


# Expose all the standard build backend hooks
def get_requires_for_build_wheel(config_settings=None):
    """Return build requirements and ensure libaegis is built first."""
    _build_libaegis()
    return _orig.get_requires_for_build_wheel(config_settings)


def get_requires_for_build_sdist(config_settings=None):
    """Return build requirements for sdist and ensure libaegis is built first."""
    _build_libaegis()
    return _orig.get_requires_for_build_sdist(config_settings)


_orig_prepare_metadata_for_build_wheel = _orig.prepare_metadata_for_build_wheel
_orig_build_sdist = _orig.build_sdist


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    """Prepare metadata and ensure libaegis is built (some frontends call this early)."""
    _build_libaegis()
    return _orig_prepare_metadata_for_build_wheel(metadata_directory, config_settings)


def build_sdist(sdist_directory, config_settings=None):
    """Build sdist, building libaegis first so the sdist can include built artifacts if needed."""
    _build_libaegis()
    return _orig_build_sdist(sdist_directory, config_settings)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """Build wheel with libaegis built first."""
    _build_libaegis()
    return _orig.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    """Build editable install with libaegis built first."""
    _build_libaegis()
    return _orig.build_editable(wheel_directory, config_settings, metadata_directory)
