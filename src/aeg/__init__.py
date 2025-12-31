import importlib

from ._ciphers import CIPHERS, CipherName
from ._typing import Cipher

__all__ = ["cipher", "CIPHERS", "Cipher", "CipherName"]


def cipher(alg: CipherName) -> Cipher:
    """Acquire a cipher module by name."""
    name = alg.lower().replace("-", "")
    if name == "aegis128":
        name = "aegis128l"  # AEGIS-128 is dead, the user meant AEGIS-128L
    if name in CIPHERS.values():
        return importlib.import_module(f".{name}", __package__)  # type: ignore[return-value]
    raise ValueError(f"Unknown algorithm {alg!r}. Valid options: {', '.join(CIPHERS)}")
