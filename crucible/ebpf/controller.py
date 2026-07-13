from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

BCC_AVAILABLE = False
try:
    if sys.platform.startswith("linux"):
        from bcc import BPF

        BCC_AVAILABLE = True
    else:
        BPF = Any
except ImportError:
    BPF = Any  # type: ignore


@dataclass
class EbpfEvent:
    """Parsed event from the eBPF monitoring probe."""

    pid: int
    comm: str
    event_type: str  # EXECVE, OPENAT, CONNECT
    details: str
    timestamp: float


class EbpfController:
    """Controls loading, attachment, and event loops for the eBPF sidecar agent monitor."""

    def __init__(
        self,
        target_pid: int | None = None,
        c_program_path: str | None = None,
    ) -> None:
        self.target_pid = target_pid
        self.c_program_path = c_program_path or os.path.join(
            os.path.dirname(__file__), "programs", "monitor.c"
        )
        self.monitoring = False

    def is_linux_active(self) -> bool:
        """Return True if running on Linux and BCC library is loaded."""
        return sys.platform.startswith("linux") and BCC_AVAILABLE

    def start_monitoring(
        self,
        event_callback: Callable[[EbpfEvent], None],
        max_events: int | None = None,
        duration: float | None = None,
    ) -> None:
        """Start the event loop and monitor system calls.

        If BCC is available and on Linux, uses the real kernel probe.
        Otherwise, falls back to a high-fidelity event simulator for testing/cross-platform support.
        """
        self.monitoring = True
        event_count = 0
        start_time = time.time()

        if self.is_linux_active():
            # Real eBPF execution via BCC
            bpf_prog = BPF(src_file=self.c_program_path)
            execve_fn = bpf_prog.get_syscall_fnname("execve")
            openat_fn = bpf_prog.get_syscall_fnname("openat")

            bpf_prog.attach_kprobe(event=execve_fn, fn_name="trace_execve")
            bpf_prog.attach_kprobe(event=openat_fn, fn_name="trace_openat")

            def handle_perf_event(cpu: int, data: Any, size: int) -> None:
                nonlocal event_count
                event = bpf_prog["events"].event(data)

                # Filter by target PID if specified
                if self.target_pid is not None and event.pid != self.target_pid:
                    return

                event_type_str = "UNKNOWN"
                if event.type == 1:
                    event_type_str = "EXECVE"
                elif event.type == 2:
                    event_type_str = "OPENAT"

                parsed = EbpfEvent(
                    pid=event.pid,
                    comm=event.comm.decode("utf-8", errors="ignore"),
                    event_type=event_type_str,
                    details=event.details.decode("utf-8", errors="ignore"),
                    timestamp=time.time(),
                )
                event_callback(parsed)
                event_count += 1

            bpf_prog["events"].open_perf_buffer(handle_perf_event)

            while self.monitoring:
                if max_events is not None and event_count >= max_events:
                    break
                if duration is not None and (time.time() - start_time) >= duration:
                    break
                # Poll perf buffer
                bpf_prog.perf_buffer_poll(timeout=100)

        else:
            # High-fidelity Simulator Mode
            # Yields a set of typical agent actions (suspicious file read, command execution)
            simulated_events = [
                EbpfEvent(
                    pid=self.target_pid or 1234,
                    comm="python",
                    event_type="OPENAT",
                    details="/etc/passwd",
                    timestamp=time.time(),
                ),
                EbpfEvent(
                    pid=self.target_pid or 1234,
                    comm="python",
                    event_type="EXECVE",
                    details="/usr/bin/curl",
                    timestamp=time.time(),
                ),
                EbpfEvent(
                    pid=self.target_pid or 1234,
                    comm="python",
                    event_type="OPENAT",
                    details="/home/user/.ssh/id_rsa",
                    timestamp=time.time(),
                ),
            ]

            for event in simulated_events:
                if not self.monitoring:
                    break
                if max_events is not None and event_count >= max_events:
                    break
                if duration is not None and (time.time() - start_time) >= duration:
                    break

                # Brief sleep to simulate real-time arrival
                time.sleep(0.01)
                event_callback(event)
                event_count += 1

        self.monitoring = False

    def stop_monitoring(self) -> None:
        """Stop the event monitoring loop."""
        self.monitoring = False
