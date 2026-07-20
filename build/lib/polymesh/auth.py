"""Credential storage helpers for the PolyMesh loopback profile.

The loopback runtime token is deliberately treated as a transport credential,
not an agent identity.  This module consequently has a very small surface:
it validates canonical base64url tokens and reads/writes them from an
owner-only file.  It never places a token in a URL or a protocol record.
"""

from __future__ import annotations

import base64
import os
import secrets
import stat
from pathlib import Path
from typing import Final

try:  # Keep this module importable while the package is being bootstrapped.
    from .errors import TokenError
except ImportError:  # pragma: no cover - used only by incomplete source trees
    class TokenError(ValueError):
        """A runtime token or token-file security check failed."""


RUNTIME_TOKEN_BYTES: Final = 32
RUNTIME_TOKEN_LENGTH: Final = 43
_BASE64URL_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_decode_exact(value: str, byte_length: int) -> bytes:
    """Decode a canonical unpadded base64url value of an exact byte length.

    ``urlsafe_b64decode`` is intentionally permissive.  Wire and credential
    values need the stricter behaviour here: no padding, no whitespace, a
    known alphabet, and a round-trip encoding identical to the input.
    """

    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("base64url value must be unpadded")
    if any(character not in _BASE64URL_ALPHABET for character in value):
        raise ValueError("base64url value contains an invalid character")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # binascii.Error differs between Python builds.
        raise ValueError("base64url value is invalid") from exc
    if len(raw) != byte_length:
        raise ValueError(f"base64url value must encode exactly {byte_length} bytes")
    if _b64url_encode(raw) != value:
        raise ValueError("base64url value is not canonical")
    return raw


def validate_runtime_token(value: str) -> str:
    """Return a canonical runtime token or raise ``TokenError``.

    A direct token is never whitespace-tolerant.  The narrowly scoped final
    newline exception belongs to :meth:`TokenStore.read`, where it is useful
    for files created by conventional credential tooling.
    """

    if not isinstance(value, str):
        raise TokenError("Runtime token must be text")
    try:
        raw = base64url_decode_exact(value, RUNTIME_TOKEN_BYTES)
    except ValueError as exc:
        raise TokenError(
            "Runtime token must be exactly 32 random bytes encoded as canonical base64url"
        ) from exc
    if len(value) != RUNTIME_TOKEN_LENGTH or _b64url_encode(raw) != value:
        raise TokenError(
            "Runtime token must be exactly 32 random bytes encoded as canonical base64url"
        )
    return value


def generate_runtime_token() -> str:
    """Create a fresh canonical 32-byte loopback runtime token."""

    return _b64url_encode(secrets.token_bytes(RUNTIME_TOKEN_BYTES))


def _is_posix() -> bool:
    return os.name == "posix"


def _unsafe_mode(mode: int) -> bool:
    return bool(stat.S_IMODE(mode) & 0o077)


class TokenStore:
    """Safely read or atomically create a loopback runtime-token file.

    On platforms where Python cannot provide the POSIX ownership/mode checks
    required by the v0.1 profile, this class fails closed instead of claiming
    that a world-readable credential is protected.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        chosen = self.default_path() if path is None else Path(path).expanduser()
        if not chosen.is_absolute():
            raise ValueError("Runtime token path must be absolute")
        if chosen.name in {"", ".", ".."}:
            raise ValueError("Runtime token path is invalid")
        self.path = chosen

    @classmethod
    def default_path(cls) -> Path:
        return Path.home() / ".polymesh" / "token"

    def read(self) -> str:
        """Read one owner-only token file and return canonical token text."""

        self._require_secure_platform()
        self._assert_secure_directory(create=False)
        file_stat = self._lstat_file(required=True)
        assert file_stat is not None
        self._assert_secure_file_stat(file_stat)

        # Open after lstat using O_NOFOLLOW where available.  The latter is
        # important because a file replacement between checks must not turn
        # into a read through an attacker-controlled symlink.
        flags = os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise TokenError("Runtime token file could not be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            self._assert_secure_file_stat(opened)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(RUNTIME_TOKEN_LENGTH + 2)
                # A valid file is at most token + one LF.  Reading one extra
                # byte avoids silently accepting a trailing secret/comment.
                if handle.read(1):
                    raise TokenError("Runtime token file contains extra data")
        finally:
            os.close(descriptor)

        if data.endswith(b"\n"):
            data = data[:-1]
        if not data or any(byte in b" \t\r\n\v\f" for byte in data):
            raise TokenError("Runtime token file does not contain one canonical token")
        try:
            token = data.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise TokenError("Runtime token file does not contain ASCII base64url text") from exc
        return validate_runtime_token(token)

    def write_new(self) -> str:
        """Generate, atomically persist, and return a fresh runtime token."""

        self._require_secure_platform()
        directory = self._assert_secure_directory(create=True)
        existing = self._lstat_file(required=False)
        if existing is not None:
            self._assert_secure_file_stat(existing)

        token = generate_runtime_token()
        payload = token.encode("ascii")
        temporary = directory / f".{self.path.name}.{secrets.token_urlsafe(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            # os.open honours umask, which can only make this stricter; fchmod
            # makes the intended mode explicit for unusual umask settings.
            os.fchmod(descriptor, 0o600)
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None

            # Recheck a pre-existing target before replace.  os.replace itself
            # does not follow a final symlink, but rejecting one makes the
            # security policy visible and avoids replacing a surprise target.
            current = self._lstat_file(required=False)
            if current is not None:
                self._assert_secure_file_stat(current)
            os.replace(temporary, self.path)
            # Validate the replacement as a regular owner-only file before
            # syncing the parent directory entry.
            replacement = self._lstat_file(required=True)
            assert replacement is not None
            self._assert_secure_file_stat(replacement)
            self._fsync_directory(directory)
            return token
        except TokenError:
            raise
        except OSError as exc:
            raise TokenError("Runtime token file could not be written safely") from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _require_secure_platform(self) -> None:
        if not _is_posix():
            raise TokenError(
                "Runtime token storage requires an equivalent owner-only ACL implementation on this platform"
            )
        # A pre-open ``lstat`` alone cannot protect the final path from a
        # symlink replacement race.  Every supported POSIX target for this
        # profile must expose O_NOFOLLOW; otherwise fail closed rather than
        # reading a credential through an attacker-controlled link.
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if not isinstance(no_follow, int) or no_follow == 0:
            raise TokenError("Runtime token storage requires no-follow file-open support")

    def _assert_secure_directory(self, *, create: bool) -> Path:
        directory = self.path.parent
        if create and not directory.exists():
            # The default is a single ~/.polymesh directory.  Do not make an
            # arbitrary chain of unknown parents and accidentally bless it.
            try:
                os.mkdir(directory, 0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise TokenError("Runtime token directory could not be created safely") from exc
        try:
            metadata = os.lstat(directory)
        except OSError as exc:
            raise TokenError("Runtime token directory is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise TokenError("Runtime token directory must be a real directory")
        if metadata.st_uid != os.geteuid():
            raise TokenError("Runtime token directory must be owned by the current user")
        if _unsafe_mode(metadata.st_mode):
            raise TokenError("Runtime token directory must not be accessible by group or other users")
        return directory

    def _lstat_file(self, *, required: bool) -> os.stat_result | None:
        try:
            return os.lstat(self.path)
        except FileNotFoundError:
            if required:
                raise TokenError("Runtime token file does not exist")
            return None
        except OSError as exc:
            raise TokenError("Runtime token file is unavailable") from exc

    def _assert_secure_file_stat(self, metadata: os.stat_result) -> None:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TokenError("Runtime token file must be a regular non-symlink file")
        if metadata.st_uid != os.geteuid():
            raise TokenError("Runtime token file must be owned by the current user")
        if _unsafe_mode(metadata.st_mode):
            raise TokenError("Runtime token file must not be accessible by group or other users")

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short token-file write")
            offset += written

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


__all__ = [
    "RUNTIME_TOKEN_BYTES",
    "RUNTIME_TOKEN_LENGTH",
    "TokenStore",
    "base64url_decode_exact",
    "generate_runtime_token",
    "validate_runtime_token",
]
