from __future__ import annotations

import errno
import unittest

from agent_sudo._locking import _LOCK_BUSY_ERRNOS, _is_lock_busy


class LockBusyClassificationTests(unittest.TestCase):
    """PR #90 review fix: replace magic numbers (13, 33) in the lock-retry
    filter with named errno/winerror sets via _is_lock_busy()."""

    def test_posix_busy_errnos_are_retryable(self) -> None:
        for code in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES, errno.EDEADLK):
            self.assertTrue(
                _is_lock_busy(OSError(code, "busy")), errno.errorcode.get(code, code)
            )

    def test_windows_lock_winerrors_are_retryable(self) -> None:
        # ERROR_SHARING_VIOLATION (32) / ERROR_LOCK_VIOLATION (33) surface as a
        # winerror rather than an errno on Windows msvcrt locks.
        for winerr in (32, 33):
            exc = OSError()
            exc.winerror = winerr
            self.assertTrue(_is_lock_busy(exc), winerr)

    def test_unrelated_errno_is_not_retryable(self) -> None:
        # A genuine error (e.g. ENOENT) must propagate, not be retried.
        self.assertFalse(_is_lock_busy(OSError(errno.ENOENT, "missing")))

    def test_eacces_dedup_documented_constant(self) -> None:
        # EACCES (13) is covered via the named set, not a magic literal.
        self.assertIn(errno.EACCES, _LOCK_BUSY_ERRNOS)


if __name__ == "__main__":
    unittest.main()
