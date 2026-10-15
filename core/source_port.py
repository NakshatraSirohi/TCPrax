"""
Source-Port Allocator

Thread-safe allocation of ephemeral source ports for SYN probes.

The SYN scanner runs many concurrent workers, each of which may probe a
port several times (retries). Two probes that are in flight at the same
time must not use the same source port, otherwise a late reply to one
probe could be matched against the other. A single shared allocator
hands out distinct ports and reclaims them when a probe finishes.

The allocation range defaults to the scanner's existing source-port
range (50000-51000), which is the range covered by the Linux
RST-suppression firewall rule described in the README. The range is not
expanded here, so that rule keeps working unchanged.

Exhaustion is handled cleanly: when every port in the range is in use,
`acquire()` raises SourcePortExhausted rather than blocking, and callers
fall back to an unreserved port so a worker is never stalled or killed.
"""

import random
import threading
from contextlib import contextmanager
from typing import Collection, Iterator


class SourcePortExhausted(Exception):
    """Raised when no source port in the range is currently free."""


class SourcePortAllocator:
    """
    Thread-safe pool of source ports over an inclusive range.

    A port handed out by `acquire()` is marked in-use and is not handed
    out again until `release()` returns it to the pool. All mutation is
    guarded by a single lock, so the allocator is safe to share across
    worker threads.
    """

    def __init__(self, start: int, end: int):
        if start > end:
            raise ValueError("start must be <= end")

        self._start = start
        self._end = end
        # Free ports are kept in a set for O(1) membership/removal.
        self._free = set(range(start, end + 1))
        self._in_use = set()
        self._lock = threading.Lock()

    @property
    def capacity(self) -> int:
        """Total number of ports the allocator manages."""
        return self._end - self._start + 1

    def available(self) -> int:
        """Number of ports currently free (point-in-time snapshot)."""
        with self._lock:
            return len(self._free)

    def acquire(self, exclude: Collection[int] = ()) -> int:
        """
        Reserves and returns a free source port.

        Parameters:
            exclude: Ports to avoid even if free (e.g. ports already
                     used for earlier attempts on the same target port,
                     so a retry always uses a different source port).

        Returns:
            A reserved port number.

        Raises:
            SourcePortExhausted if no eligible port is free.
        """
        with self._lock:
            candidates = self._free - set(exclude) if exclude else self._free
            if not candidates:
                raise SourcePortExhausted(
                    f"no free source port in {self._start}-{self._end}")

            # random.choice needs a sequence; sample one without building
            # a full sorted copy on the hot path.
            port = random.choice(tuple(candidates))
            self._free.discard(port)
            self._in_use.add(port)
            return port

    def release(self, port: int) -> None:
        """
        Returns a previously acquired port to the free pool.

        Releasing a port that is not in use, or is outside the range, is
        ignored so that cleanup paths never raise.
        """
        with self._lock:
            if port in self._in_use:
                self._in_use.discard(port)
                self._free.add(port)

    @contextmanager
    def lease(self, exclude: Collection[int] = ()) -> Iterator[int]:
        """
        Context manager that acquires a port and always releases it.

        Usage:
            with allocator.lease() as port:
                ...
        """
        port = self.acquire(exclude)
        try:
            yield port
        finally:
            self.release(port)
