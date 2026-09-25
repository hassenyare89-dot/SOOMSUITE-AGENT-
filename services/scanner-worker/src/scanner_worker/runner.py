"""Sandboxed subprocess execution for scanners.

* argv lists only (never a shell), fixed binaries, minimal environment
* private temp dir per run, output size caps, wall-clock timeout
* heartbeats so Temporal can cancel; SIGKILL of the whole process group on cancel/timeout
The container itself runs as non-root, read-only rootfs, no capabilities, seccomp default,
and egress restricted to public addresses (see infra/kubernetes/scanner-worker).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

SAFE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}


@dataclass
class ProcessResult:
    returncode: int
    stdout_tail: str
    timed_out: bool


async def run(argv: list[str], *, cwd: str, timeout: float,
              heartbeat: Callable[[str], Awaitable[None] | None] | None = None,
              max_output: int = 1_000_000) -> ProcessResult:
    proc = await asyncio.create_subprocess_exec(
        *argv, cwd=cwd, env={**SAFE_ENV, "HOME": cwd},  # per-run private HOME stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, start_new_session=True)
    buf = bytearray()

    async def pump() -> None:
        if proc.stdout is None:
            return
        while chunk := await proc.stdout.read(65536):
            if len(buf) < max_output:
                buf.extend(chunk[: max_output - len(buf)])

    async def beat() -> None:
        while True:
            await asyncio.sleep(15)
            if heartbeat:
                result = heartbeat(f"running {argv[0]}")
                if asyncio.iscoroutine(result):
                    await result

    pump_task, beat_task = asyncio.create_task(pump()), asyncio.create_task(beat())
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        timed_out = True
    except asyncio.CancelledError:
        _kill(proc)
        raise
    finally:
        beat_task.cancel()
        if proc.returncode is None:
            _kill(proc)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=5)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(pump_task, timeout=5)
    return ProcessResult(proc.returncode if proc.returncode is not None else -9,
                         bytes(buf[-4000:]).decode(errors="replace"), timed_out)


def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
