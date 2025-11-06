"""Hatch build hook for building dynamic libaegis library using Zig."""

import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class BuildHook(BuildHookInterface):
    """Build dynamic library with Zig and include in wheel."""

    def initialize(self, version: str, build_data: dict) -> None:
        """Build library with Zig and add it to the wheel."""
        if self.target_name != "wheel":
            return

        if not shutil.which("zig"):
            raise RuntimeError("Zig compiler not found in PATH")

        libaegis_dir = Path(self.root) / "libaegis"
        original_build_zig = libaegis_dir / "build.zig"
        if not original_build_zig.exists():
            raise RuntimeError(f"libaegis source not found at {libaegis_dir}")

        # Prepare a temporary build directory (avoid touching original files)
        build_dir = Path.cwd() / "libaegis-build"
        build_dir.mkdir(exist_ok=True)
        build_zig = build_dir / "build.zig"
        build_zig.write_text(
            original_build_zig.read_text(encoding="utf-8").replace(
                ".linkage = .static,", ".linkage = .dynamic,"
            ),
            encoding="utf-8",
        )
        for res in "build.zig.zon", "src":
            (build_dir / res).symlink_to(libaegis_dir / res)
        self.app.display_info("[aegis] Building libaegis dynamic library with Zig...")
        try:
            subprocess.run(
                ["zig", "build", "-Drelease"],
                check=True,
                cwd=str(build_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            output = e.stdout.decode(errors="replace") if e.stdout else ""
            raise RuntimeError(f"Zig build failed:\n{output}") from e

        lib_dir = build_dir / "zig-out" / "lib"

        dynamic_lib = None
        for lib_file in lib_dir.iterdir():
            if lib_file.name.startswith("libaegis") and lib_file.suffix in (
                ".so",
                ".dylib",
                ".dll",
            ):
                dynamic_lib = lib_file
                break

        if not dynamic_lib or not dynamic_lib.exists():
            raise RuntimeError(f"Built dynamic library not found in {lib_dir}")

        if "force_include" not in build_data:
            build_data["force_include"] = {}
        dest_rel = str(Path("build") / dynamic_lib.name)
        build_data["force_include"][str(dynamic_lib)] = dest_rel
        self.app.display_info(f"[aegis] Added dynamic library to wheel: {dest_rel}")
