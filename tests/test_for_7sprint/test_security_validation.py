from __future__ import annotations

import statistics
import time
from unittest.mock import patch

from src.core.crypto.authentication import AuthenticationService
from src.core.events import EventBus, PanicModeActivated
from src.core.key_manager import KeyManager
from src.core.security import ActivityMonitor, MemoryGuard, PanicMode
from src.core.security.side_channel_protection import constant_time_compare, constant_time_compare_str
from src.core.state_manager import StateManager


def _mean_compare_ns(compare_fn, left, right, iterations: int = 20_000) -> float:
    started = time.perf_counter_ns()
    for _ in range(iterations):
        compare_fn(left, right)
    elapsed = time.perf_counter_ns() - started
    return elapsed / float(iterations)


def test_timing_attack_constant_time_behavior():
    # Compare timing of equal vs unequal inputs with the same length.
    equal_samples = []
    mismatch_samples = []
    for _ in range(8):
        equal_samples.append(_mean_compare_ns(constant_time_compare, b"A" * 32, b"A" * 32))
        mismatch_samples.append(_mean_compare_ns(constant_time_compare, b"A" * 32, b"A" * 31 + b"B"))

    equal_median = statistics.median(equal_samples)
    mismatch_median = statistics.median(mismatch_samples)
    relative_delta = abs(equal_median - mismatch_median) / max(equal_median, mismatch_median)
    assert relative_delta < 0.35

    # Same invariant for security-critical string comparisons.
    s_equal_samples = []
    s_mismatch_samples = []
    for _ in range(8):
        s_equal_samples.append(
            _mean_compare_ns(constant_time_compare_str, "vault-session-token", "vault-session-token")
        )
        s_mismatch_samples.append(
            _mean_compare_ns(constant_time_compare_str, "vault-session-token", "vault-session-t0ken")
        )
    s_equal = statistics.median(s_equal_samples)
    s_mismatch = statistics.median(s_mismatch_samples)
    s_delta = abs(s_equal - s_mismatch) / max(s_equal, s_mismatch)
    assert s_delta < 0.35


def test_memory_protection_wipe_removes_plaintext():
    marker = b"TOP_SECRET_MEMORY_MARKER_2026"
    guard = MemoryGuard(enable_locking=False, enable_auto_wipe=True, multi_pass_wipe_for_critical=True)
    secure = guard.allocate(marker, critical=True)

    assert secure.to_bytes() == marker

    # Hold a reference to the backing allocation to emulate a "memory dump" probe.
    backing = secure._backing
    assert backing is not None
    assert marker in bytes(backing)

    guard.wipe(secure, critical=True)
    dumped_after_wipe = bytes(backing)
    assert marker not in dumped_after_wipe
    assert dumped_after_wipe.count(0) > 0


def test_auto_lock_reliability_24h_simulation():
    monitor = ActivityMonitor(enabled=True, auto_lock_timeout_sec=300, sensitivity="medium", device_type="desktop")
    effective_timeout = monitor.get_effective_timeout_sec()
    assert effective_timeout == 300

    lock_events = 0
    # Simulate 24h, 1-minute ticks. Pattern: 10m active, then 20m inactive.
    for minute in range(24 * 60):
        now = float(minute * 60)
        in_active_window = (minute % 30) < 10
        if in_active_window:
            with patch("src.core.security.activity_monitor.time.time", return_value=now):
                monitor.mark_activity("keyboard")

        with patch("src.core.security.activity_monitor.time.time", return_value=now):
            if monitor.is_inactive():
                lock_events += 1
                monitor.mark_activity("auto_lock_reset")

    # Each 30-minute cycle has a 20-minute inactive window => 4 lock events (every 5 minutes),
    # and there are 48 cycles in 24 hours.
    assert lock_events == 192


def test_panic_mode_stress_and_recovery(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")
    state = StateManager()
    bus = EventBus()
    panic = PanicMode(enabled=True, lock_on_activate=True, clear_clipboard_on_activate=True)
    auth = AuthenticationService(km, state, event_bus=bus, panic_mode=panic)

    panic_events: list[PanicModeActivated] = []
    bus.subscribe(PanicModeActivated, lambda e: panic_events.append(e))

    for idx in range(25):
        auth.login("StrongPass123!")
        marker = {"clipboard_cleared": False}
        activated = auth.activate_panic_mode(
            clear_clipboard_callback=lambda: marker.__setitem__("clipboard_cleared", True),
            reason=f"stress-{idx}",
        )
        assert activated is True
        assert marker["clipboard_cleared"] is True
        assert auth.is_unlocked() is False

        # Clean recovery should allow normal unlock again.
        auth.login("StrongPass123!")
        assert auth.is_unlocked() is True
        auth.logout()

    assert len(panic_events) == 25
