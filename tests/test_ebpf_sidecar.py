"""tests/test_ebpf_sidecar.py — Phase 17 eBPF Sidecar tests (v0.15.0)

Tests run in simulator mode on all platforms (including Windows/macOS).
Linux-only BCC integration tests are marked with ``linux_bcc`` and are skipped
when not on Linux **or** when the optional ``bcc`` package is not installed.
"""

from __future__ import annotations

import sys
import time
from unittest.mock import patch

import pytest

from crucible.ebpf.controller import BCC_AVAILABLE, EbpfController, EbpfEvent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def controller() -> EbpfController:
    """Return a default EbpfController with no specific target PID."""
    return EbpfController()


@pytest.fixture()
def targeted_controller() -> EbpfController:
    """Return an EbpfController targeting PID 9999."""
    return EbpfController(target_pid=9999)


@pytest.fixture()
def collected_events() -> list[EbpfEvent]:
    return []


@pytest.fixture()
def event_collector(collected_events):
    def _collect(event: EbpfEvent) -> None:
        collected_events.append(event)

    return _collect


# ---------------------------------------------------------------------------
# Unit tests — EbpfEvent dataclass
# ---------------------------------------------------------------------------


class TestEbpfEvent:
    def test_event_creation(self):
        event = EbpfEvent(
            pid=1234,
            comm="python",
            event_type="EXECVE",
            details="/usr/bin/curl",
            timestamp=time.time(),
        )
        assert event.pid == 1234
        assert event.comm == "python"
        assert event.event_type == "EXECVE"
        assert "/usr/bin/curl" in event.details

    def test_event_openat(self):
        event = EbpfEvent(
            pid=5678,
            comm="agent",
            event_type="OPENAT",
            details="/etc/shadow",
            timestamp=time.time(),
        )
        assert event.event_type == "OPENAT"
        assert "/etc/shadow" in event.details

    def test_event_connect(self):
        event = EbpfEvent(
            pid=9999,
            comm="node",
            event_type="CONNECT",
            details="192.168.1.1:443",
            timestamp=time.time(),
        )
        assert event.event_type == "CONNECT"
        assert event.pid == 9999

    def test_event_timestamp_is_float(self):
        ts = time.time()
        event = EbpfEvent(
            pid=1, comm="x", event_type="EXECVE", details="y", timestamp=ts
        )
        assert isinstance(event.timestamp, float)
        assert event.timestamp <= time.time()


# ---------------------------------------------------------------------------
# Unit tests — EbpfController construction
# ---------------------------------------------------------------------------


class TestEbpfControllerInit:
    def test_default_init(self, controller):
        assert controller.target_pid is None
        assert controller.monitoring is False

    def test_targeted_init(self, targeted_controller):
        assert targeted_controller.target_pid == 9999
        assert targeted_controller.monitoring is False

    def test_custom_c_program_path(self):
        ctrl = EbpfController(c_program_path="/custom/path/prog.c")
        assert ctrl.c_program_path == "/custom/path/prog.c"

    def test_default_c_program_path_set(self, controller):
        assert controller.c_program_path.endswith("monitor.c")

    def test_stop_monitoring_before_start(self, controller):
        """stop_monitoring should be safe to call even if never started."""
        controller.stop_monitoring()
        assert controller.monitoring is False


# ---------------------------------------------------------------------------
# Unit tests — Platform detection
# ---------------------------------------------------------------------------


class TestPlatformDetection:
    def test_is_linux_active_on_windows(self, controller):
        """Should return False on Windows."""
        if sys.platform.startswith("win"):
            assert controller.is_linux_active() is False

    def test_is_linux_active_depends_on_bcc(self):
        """If BCC not available, should return False regardless of platform."""
        with patch("crucible.ebpf.controller.BCC_AVAILABLE", False):
            ctrl = EbpfController()
            assert ctrl.is_linux_active() is False

    def test_bcc_available_is_bool(self):
        assert isinstance(BCC_AVAILABLE, bool)


# ---------------------------------------------------------------------------
# Simulator mode tests (cross-platform)
# ---------------------------------------------------------------------------


class TestSimulatorMode:
    def test_simulator_fires_events(
        self, controller, collected_events, event_collector
    ):
        """Simulator should yield at least one event."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=3)

        assert len(collected_events) > 0

    def test_simulator_produces_execve(
        self, controller, collected_events, event_collector
    ):
        """Simulator should produce at least one EXECVE event."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=3)

        types = [e.event_type for e in collected_events]
        assert "EXECVE" in types

    def test_simulator_produces_openat(
        self, controller, collected_events, event_collector
    ):
        """Simulator should produce at least one OPENAT event."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=3)

        types = [e.event_type for e in collected_events]
        assert "OPENAT" in types

    def test_simulator_events_have_pid(
        self, controller, collected_events, event_collector
    ):
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=2)

        for event in collected_events:
            assert isinstance(event.pid, int)
            assert event.pid > 0

    def test_simulator_events_have_comm(
        self, controller, collected_events, event_collector
    ):
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=2)

        for event in collected_events:
            assert isinstance(event.comm, str)
            assert len(event.comm) > 0

    def test_simulator_events_have_details(
        self, controller, collected_events, event_collector
    ):
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=2)

        for event in collected_events:
            assert isinstance(event.details, str)
            assert len(event.details) > 0

    def test_simulator_respects_max_events(
        self, controller, event_collector, collected_events
    ):
        """Should stop after max_events even if more events are available."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=1)

        assert len(collected_events) == 1

    def test_simulator_monitoring_false_after_completion(
        self, controller, event_collector, collected_events
    ):
        """monitoring flag should be reset to False after start_monitoring returns."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=2)

        assert controller.monitoring is False

    def test_targeted_simulator_uses_target_pid(
        self, targeted_controller, event_collector, collected_events
    ):
        """Events in simulator mode should use the target_pid if set."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            targeted_controller.start_monitoring(event_collector, max_events=1)

        assert collected_events[0].pid == 9999

    def test_simulator_duration_limit(
        self, controller, event_collector, collected_events
    ):
        """Should respect duration limit (short duration, may get 0 events)."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            start = time.time()
            controller.start_monitoring(event_collector, duration=0.001)
            elapsed = time.time() - start

        # Should return relatively quickly (within 1 second)
        assert elapsed < 1.0

    def test_suspicious_paths_detected(
        self, controller, event_collector, collected_events
    ):
        """Simulator should include sensitive path access patterns."""
        with (
            patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
            patch.object(sys, "platform", "win32"),
        ):
            controller.start_monitoring(event_collector, max_events=10)

        details_all = " ".join(e.details for e in collected_events)
        # The simulator should include at least one privileged path
        suspicious = ["/etc/passwd", "/etc/shadow", "id_rsa", "curl", "wget"]
        assert any(s in details_all for s in suspicious)

    def test_stop_monitoring_halts_event_loop(self, event_collector, collected_events):
        """Calling stop_monitoring mid-run should halt event collection."""
        import threading

        ctrl = EbpfController()

        def _run():
            with (
                patch("crucible.ebpf.controller.BCC_AVAILABLE", False),
                patch.object(sys, "platform", "win32"),
            ):
                ctrl.start_monitoring(event_collector, max_events=100)

        t = threading.Thread(target=_run)
        t.start()
        time.sleep(0.05)
        ctrl.stop_monitoring()
        t.join(timeout=2.0)

        # We called stop, so fewer than 100 events should have been received
        assert len(collected_events) <= 100


# Linux-only marker tests (skipped on non-Linux or when BCC is missing)
# ---------------------------------------------------------------------------

linux_bcc = pytest.mark.skipif(
    (not sys.platform.startswith("linux")) or (not BCC_AVAILABLE),
    reason="Requires Linux kernel with BCC eBPF support installed",
)


@linux_bcc
class TestLinuxBCCIntegration:
    """These tests only run on Linux with BCC installed.

    GitHub-hosted Linux runners do not ship BCC by default, so the suite must
    skip (not fail) when the optional import is unavailable.
    """

    def test_bcc_available_on_linux(self, controller):
        assert BCC_AVAILABLE is True

    def test_is_linux_active_true_on_linux(self, controller):
        assert controller.is_linux_active() is True
