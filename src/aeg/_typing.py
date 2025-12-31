from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .util import Buffer

__all__ = ["Cipher"]


class _Mac(Protocol):
    def reset(self) -> None: ...
    def clone(self) -> "_Mac": ...
    def update(self, data: "Buffer") -> None: ...
    def final(self, into: "Buffer | None" = None) -> bytearray | memoryview: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def verify(self, mac: "Buffer") -> None: ...


class _Encryptor(Protocol):
    def update(
        self, message: "Buffer", into: "Buffer | None" = None
    ) -> bytearray | memoryview: ...
    def final(self, into: "Buffer | None" = None) -> bytearray | memoryview: ...


class _Decryptor(Protocol):
    def update(
        self, ct: "Buffer", into: "Buffer | None" = None
    ) -> bytearray | memoryview: ...
    def final(self, mac: "Buffer") -> None: ...


class Cipher(Protocol):
    NAME: str
    KEYBYTES: int
    NONCEBYTES: int
    MACBYTES: int
    MACBYTES_LONG: int
    ALIGNMENT: int
    RATE: int

    Mac: type[_Mac]
    Encryptor: type[_Encryptor]
    Decryptor: type[_Decryptor]

    @staticmethod
    def random_key() -> bytearray: ...
    @staticmethod
    def random_nonce() -> bytearray: ...
    @staticmethod
    def encrypt_detached(
        key: "Buffer",
        nonce: "Buffer",
        message: "Buffer",
        ad: "Buffer | None" = None,
        *,
        maclen: int = ...,
        ct_into: "Buffer | None" = None,
        mac_into: "Buffer | None" = None,
    ) -> tuple[bytearray | memoryview, bytearray | memoryview]: ...
    @staticmethod
    def decrypt_detached(
        key: "Buffer",
        nonce: "Buffer",
        ct: "Buffer",
        mac: "Buffer",
        ad: "Buffer | None" = None,
        *,
        into: "Buffer | None" = None,
    ) -> bytearray | memoryview: ...
    @staticmethod
    def encrypt(
        key: "Buffer",
        nonce: "Buffer",
        message: "Buffer",
        ad: "Buffer | None" = None,
        *,
        maclen: int = ...,
        into: "Buffer | None" = None,
    ) -> bytearray | memoryview: ...
    @staticmethod
    def decrypt(
        key: "Buffer",
        nonce: "Buffer",
        ct: "Buffer",
        ad: "Buffer | None" = None,
        *,
        maclen: int = ...,
        into: "Buffer | None" = None,
    ) -> bytearray | memoryview: ...
    @staticmethod
    def stream(
        key: "Buffer",
        nonce: "Buffer | None",
        length: int | None = None,
        *,
        into: "Buffer | None" = None,
    ) -> "bytearray | Buffer": ...
    @staticmethod
    def encrypt_unauthenticated(
        key: "Buffer",
        nonce: "Buffer",
        message: "Buffer",
        *,
        into: "Buffer | None" = None,
    ) -> bytearray | memoryview: ...
    @staticmethod
    def decrypt_unauthenticated(
        key: "Buffer",
        nonce: "Buffer",
        ct: "Buffer",
        *,
        into: "Buffer | None" = None,
    ) -> bytearray | memoryview: ...
    @staticmethod
    def mac(
        key: "Buffer",
        nonce: "Buffer",
        data: "Buffer",
        maclen: int = ...,
        into: "Buffer | None" = None,
    ) -> bytearray | memoryview: ...
