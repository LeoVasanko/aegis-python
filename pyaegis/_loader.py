"""Loader for libaegis CFFI extension module."""

from pyaegis._aegis import ffi, lib

__all__ = ["ffi", "lib"]

lib.aegis_init()
