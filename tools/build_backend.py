"""Custom build backend that builds libaegis with Zig before building the Python package."""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import build_meta

__all__ = [
    "build_sdist",
    "build_wheel",
    "build_editable",
    "get_requires_for_build_sdist",
    "get_requires_for_build_wheel",
    "prepare_metadata_for_build_wheel",
]

_MACOS_TARGET = "11.0"
_prepared = False


def _prepare():
    """Prepare the build environment and build libaegis."""
    global _prepared
    if _prepared:
        return
    _prepared = True

    # Set macOS deployment target
    if sys.platform == "darwin" and "MACOSX_DEPLOYMENT_TARGET" not in os.environ:
        os.environ["MACOSX_DEPLOYMENT_TARGET"] = _MACOS_TARGET

    # Check Zig is available
    if shutil.which("zig") is None:
        raise RuntimeError(
            "Zig compiler not found. Install from https://ziglang.org/download/"
        )

    # Build libaegis
    libaegis_dir = Path(__file__).parent.parent / "libaegis"
    cmd = ["zig", "build", "-Drelease"]
    if sys.platform == "darwin":
        arch = {"arm64": "aarch64", "x86_64": "x86_64"}.get(platform.machine())
        if arch:
            cmd.append(f"-Dtarget={arch}-macos.{_MACOS_TARGET}")
    subprocess.run(cmd, cwd=libaegis_dir, check=True)


build_sdist = build_meta.build_sdist
get_requires_for_build_sdist = build_meta.get_requires_for_build_sdist
get_requires_for_build_wheel = build_meta.get_requires_for_build_wheel
prepare_metadata_for_build_wheel = build_meta.prepare_metadata_for_build_wheel


# Wheel build hooks - need libaegis built first
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _prepare()
    return build_meta.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _prepare()
    return build_meta.build_editable(
        wheel_directory, config_settings, metadata_directory
    )
