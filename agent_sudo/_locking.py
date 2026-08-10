"""Internal advisory file locking for the file-backed stores.

Provides a single, fail-closed exclusive lock used to serialize the
read-modify-write sequences in :mod:`agent_sudo.delegations` and the
hash-chained append in :mod:`agent_sudo.audit`.

Design notes:

* Uses the standard-library native advisory lock for the active platform:
  ``fcntl.flock`` on macOS/Linux and ``msvcrt.locking`` on Windows.
* The lock is **advisory** -- all writers in this codebase cooperate by going
  through this helper. It is associated with the open file description, so two
  separate ``open`` calls (even in the same process) contend, which is what we
  rely on for the lock-timeout behaviour.
* **Fail closed:** if the lock cannot be acquired within ``timeout`` seconds we
  raise :class:`LockTimeout`. Callers must treat that as a denial, never as a
  silent fallback.
* **Auto-release:** the kernel releases the file lock when the holding fd is
  closed or the process exits, so a crashed holder cannot wedge the store.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
    import msvcrt
else:  # pragma: no cover - exercised on POSIX CI
    import fcntl


DEFAULT_LOCK_TIMEOUT = 5.0
_POLL_INTERVAL = 0.01


# ``msvcrt.locking`` applies locks per process, so a second thread in the same
# process can otherwise enter a protected file-backed transaction. Keep a
# process-local mutex for each Windows lock file, while ``msvcrt`` serializes
# separate processes.
_WINDOWS_LOCKS: dict[str, threading.Lock] = {}
_WINDOWS_LOCKS_GUARD = threading.Lock()


class LockTimeout(Exception):
    """Raised when the advisory lock cannot be acquired within the deadline."""


def _lock_unavailable(exc: OSError) -> bool:
    """Return whether ``exc`` represents an already-held advisory lock."""
    if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
        return True
    return getattr(exc, "winerror", None) == 33  # ERROR_LOCK_VIOLATION


def _windows_thread_lock(lock_path: Path) -> threading.Lock:
    """Return the process-local mutex associated with a Windows lock file."""
    key = os.path.normcase(str(lock_path.resolve()))
    with _WINDOWS_LOCKS_GUARD:
        return _WINDOWS_LOCKS.setdefault(key, threading.Lock())


def _acquire_windows_thread_lock(
    lock: threading.Lock, lock_path: Path, deadline: float, timeout: float
) -> None:
    """Acquire the per-process portion of a Windows file lock before deadline."""
    remaining = max(0.0, deadline - time.monotonic())
    acquired = (
        lock.acquire(blocking=False)
        if remaining == 0
        else lock.acquire(timeout=remaining)
    )
    if not acquired:
        raise LockTimeout(f"could not acquire lock {lock_path} within {timeout}s")


def _prepare_windows_lock_file(fd: int) -> None:
    """Ensure byte zero exists before asking ``msvcrt`` to lock it."""
    if os.fstat(fd).st_size == 0:
        os.write(fd, b"\0")
        os.fsync(fd)
    os.lseek(fd, 0, os.SEEK_SET)


def _try_platform_lock(fd: int) -> None:
    """Attempt a non-blocking exclusive lock using the active platform API."""
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        _prepare_windows_lock_file(fd)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_platform_lock(fd: int) -> None:
    """Release a lock acquired by :func:`_try_platform_lock`."""
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def file_lock(lock_path: Path, timeout: float = DEFAULT_LOCK_TIMEOUT) -> Iterator[None]:
    """Hold an exclusive advisory lock on ``lock_path`` for the with-block.

    Raises :class:`LockTimeout` if the lock is not acquired within ``timeout``
    seconds. The dedicated ``.lock`` file is created if absent; its contents are
    never read or written -- only the lock state matters.
    """
    lock_path = Path(lock_path)
    deadline = time.monotonic() + max(0.0, timeout)
    thread_lock: threading.Lock | None = None
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        thread_lock = _windows_thread_lock(lock_path)
        _acquire_windows_thread_lock(thread_lock, lock_path, deadline, timeout)

    fd: int | None = None
    locked = False
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        while True:
            try:
                _try_platform_lock(fd)
                locked = True
                break
            except OSError as exc:
                if not _lock_unavailable(exc):
                    raise
                if time.monotonic() >= deadline:
                    raise LockTimeout(
                        f"could not acquire lock {lock_path} within {timeout}s"
                    ) from exc
                time.sleep(_POLL_INTERVAL)
        yield
    finally:
        try:
            if locked and fd is not None:
                _release_platform_lock(fd)
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                if thread_lock is not None:
                    thread_lock.release()


def fsync_dir(directory: Path) -> None:
    """Best-effort ``fsync`` of a directory so a rename is durable.

    Directory fsync is not portable to every filesystem; failures are ignored
    because the preceding file fsync already provides the safety we need.
    """
    try:
        dir_fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)
