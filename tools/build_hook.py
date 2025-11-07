"""Hatch build hook for building dynamic libaegis library using Zig."""

import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class BuildHook(BuildHookInterface):
    """Build dynamic library with Zig and include in wheel."""

    PLUGIN_NAME = "pyaegis_build_hook"

    def initialize(self, version: str, build_data: dict) -> None:
        """Build library with Zig and add it to the wheel."""
        super().initialize(version, build_data)
        if self.target_name != "wheel":
            return

        if not shutil.which("zig"):
            raise RuntimeError("Zig compiler not found in PATH")

        libaegis_dir = Path(self.root) / "libaegis"
        self.app.display_info(f"[aegis] Using libaegis source at: {libaegis_dir}")
        original_build_zig = libaegis_dir / "build.zig"
        if not original_build_zig.exists():
            raise RuntimeError(f"libaegis source not found at {libaegis_dir}")

        try:
            build_dir = Path("libaegis-build")
            build_dir.mkdir(exist_ok=True)
            build_zig = build_dir / "build.zig"
            build_zig.write_text(
                original_build_zig.read_text(encoding="utf-8").replace(
                    ".linkage = .static,", ".linkage = .dynamic,"
                ),
                encoding="utf-8",
            )
            for res in ("build.zig.zon", "src"):
                (build_dir / res).symlink_to(libaegis_dir / res)
            self.app.display_info(
                "[aegis] Building libaegis dynamic library with Zig..."
            )
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

            # Copy the built dynamic library into the Python package tree so that it
            # is naturally included as package data. Hatch will pick up anything
            # under the listed packages ("pyaegis"), so a direct copy is simpler
            # than relying on force_include. We still leave the original artifact
            # in place in case other hooks/tools want to inspect it.
            package_build_dir = Path(self.root) / "pyaegis" / "build"
            package_build_dir.mkdir(parents=True, exist_ok=True)
            self.app.display_info(
                f"[aegis] Staging dynamic library to package... {package_build_dir} {Path.cwd()}"
            )
            dest_path = package_build_dir / dynamic_lib.name
            try:
                shutil.copy2(dynamic_lib, dest_path)
            except Exception as e:  # pragma: no cover - defensive
                raise RuntimeError(
                    f"Failed to copy dynamic library to package: {e}"
                ) from e
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

        # Retain force_include as a fallback for environments where an older
        # Hatch might not automatically include non-.py files, or if wheels are
        # built with custom exclusion rules.
        if "force_include" not in build_data:
            build_data["force_include"] = {}
        build_data["force_include"][str(dest_path)] = str(
            Path("pyaegis") / "build" / dynamic_lib.name
        )
        self.app.display_info(f"[aegis] Dynamic library staged at: {dest_path}")
