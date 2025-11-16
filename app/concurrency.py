"""Per-account concurrency & locking utilities.

Guarantees:
- At most one active job per Gmail account at a time (any module).
- Implemented via simple file-based locks under /data/locks.
- Cooperative: workers will wait for the lock unless cancelled or a timeout is hit.
"""

import os
import time
from pathlib import Path
from typing import Callable, Optional


DATA_DIR = os.getenv("DATA_DIR", "/data")
LOCK_DIR = Path(DATA_DIR) / "locks"
LOCK_DIR.mkdir(parents=True, exist_ok=True)


def _lock_path_for(from_email: str, module: str) -> Path:
    """Return lock file path for a given Gmail + logical lock name.

    NOTE: We deliberately allow callers to choose a *shared* lock name,
    e.g. "gmail", so that different modules (Module 1 / Module 2)
    cannot overlap for the same account.
    """
    safe_email = (from_email or "").replace("@", "_at_").replace(".", "_")
    safe_module = (module or "generic").replace(os.sep, "_")
    return LOCK_DIR / f"{safe_email}.{safe_module}.lock"


def acquire_account_lock(
    from_email: str,
    module: str,
    log: Optional[Callable[[str], None]] = None,
    check_stop: Optional[Callable[[], bool]] = None,
    wait_interval: int = 5,
    max_wait_seconds: Optional[int] = None,
):
    """Try to acquire an exclusive lock for a Gmail account.

    Args:
        from_email: Gmail address this job is using.
        module: Logical lock name. If you pass the same value (e.g. "gmail")
            from multiple modules, they will share a single account-wide lock.
        log: Optional logger function.
        check_stop: Optional callable that returns True if the job has been
            externally asked to stop (e.g. via a .flag file).
        wait_interval: Seconds between lock acquisition retries.
        max_wait_seconds: Optional upper bound on how long to wait for the lock.
            If exceeded, acquisition fails and (False, None) is returned.

    Returns:
        (ok, lock_path):
            ok == True  -> the caller owns the lock and must later release it.
            ok == False -> the lock was not acquired (timeout / stop requested).
    """
    path = _lock_path_for(from_email, module)
    start_ts = time.time()
    notified = False

    while True:
        # First, honour any explicit stop signal.
        if check_stop and check_stop():
            if log:
                log("Stop requested while waiting for account lock; aborting.")
            return False, None

        # Try to create the lock file atomically.
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            if log:
                log(f"Acquired account lock for {from_email} [{module}].")
            return True, str(path)
        except FileExistsError:
            # Someone else holds the lock.
            pass

        # Enforce optional timeout.
        if max_wait_seconds is not None:
            elapsed = time.time() - start_ts
            if elapsed >= max_wait_seconds:
                if log:
                    log(
                        f"Timeout ({int(elapsed)}s) waiting for account lock for {from_email} [{module}]; aborting."
                    )
                return False, None

        if not notified and log:
            log(f"Another {module} job is active for this account. Waiting for it to finish...")
            notified = True

        time.sleep(wait_interval)


def release_account_lock(lock_path, log: Optional[Callable[[str], None]] = None) -> None:
    """Release a previously acquired account lock.

    It is safe to call this with lock_path=None.
    """
    if not lock_path:
        return
    try:
        Path(lock_path).unlink(missing_ok=True)
        if log:
            log("Released account lock.")
    except Exception:
        # Best-effort only.
        pass
