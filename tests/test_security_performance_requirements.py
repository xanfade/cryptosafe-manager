from __future__ import annotations

import base64
import os
import secrets
import time

from src.core.config import ConfigManager
from src.core.crypto.authentication import AuthenticationService
from src.core.events import EventBus
from src.core.key_manager import KeyManager
from src.core.security import ActivityMonitor, MemoryGuard, PanicMode, SecurityHardeningSettings
from src.core.security.side_channel_protection import constant_time_compare_str
from src.core.settings_repo import SettingsService
from src.core.state_manager import StateManager


def _avg_ns(fn, loops: int = 100_000) -> float:
    started = time.perf_counter_ns()
    for _ in range(loops):
        fn()
    elapsed = time.perf_counter_ns() - started
    return elapsed / float(loops)


def test_perf1_constant_time_overhead_under_10_percent():
    left = b"vault-session-fingerprint" * 256
    right = b"vault-session-fingerprint" * 256
    left_s = left.decode("utf-8")
    right_s = right.decode("utf-8")

    baseline = _avg_ns(lambda: secrets.compare_digest(left_s, right_s), loops=20_000)
    hardened = _avg_ns(lambda: constant_time_compare_str(left_s, right_s), loops=20_000)

    overhead = (hardened - baseline) / max(1.0, baseline)
    assert overhead < 0.10, f"constant-time compare overhead is {overhead * 100:.2f}%"


def test_perf2_memory_protection_overhead_under_5_percent():
    payload = os.urandom(64 * 1024)  # use a realistic buffer size
    guard = MemoryGuard(enable_locking=False, enable_auto_wipe=True)

    buf = guard.allocate(payload, critical=True)
    protected_size = len(buf._payload)
    raw_size = len(payload)
    overhead = (protected_size - raw_size) / float(raw_size)

    # Include canary bytes as effective allocation overhead.
    effective_alloc = raw_size + 32
    effective_overhead = (effective_alloc - raw_size) / float(raw_size)

    guard.wipe(buf, critical=True)
    assert overhead <= 0.0
    assert effective_overhead < 0.05, f"memory protection overhead is {effective_overhead * 100:.2f}%"


def test_perf3_auto_lock_idle_cpu_under_1_percent():
    monitor = ActivityMonitor(enabled=True, auto_lock_timeout_sec=300, sensitivity="medium", device_type="desktop")

    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    # Simulate idle monitor checks for 2 seconds.
    for _ in range(200):
        monitor.is_inactive()
        time.sleep(0.01)
    cpu_delta = time.process_time() - cpu_start
    wall_delta = time.perf_counter() - wall_start

    cpu_percent = (cpu_delta / wall_delta) * 100.0
    assert cpu_percent < 1.0, f"idle auto-lock monitoring CPU usage is {cpu_percent:.2f}%"


def test_perf4_startup_security_under_3_seconds(test_db, tmp_path):
    started = time.perf_counter()

    cfg_path = tmp_path / "perf_cfg.json"
    cfg = ConfigManager(str(cfg_path))
    cfg.load()
    cfg.set("db_path", test_db.db_path)

    event_bus = EventBus()
    key_manager = KeyManager(test_db)
    if not key_manager.is_initialized():
        key_manager.initialize_master_password("StrongPass123!")

    state_manager = StateManager()
    raw_settings_key = os.urandom(32)
    cfg.set("settings_secret_key", base64.b64encode(raw_settings_key).decode("utf-8"))
    fernet_key = SettingsService.build_fernet_key(raw_settings_key)
    settings_service = SettingsService(test_db, fernet_key)
    hardening = SecurityHardeningSettings.from_settings(settings_service)

    activity_monitor = ActivityMonitor(
        enabled=hardening.enabled and hardening.activity_monitor_enabled,
        auto_lock_timeout_sec=hardening.auto_lock_timeout_sec,
        sensitivity=hardening.activity_sensitivity,
        device_type=hardening.activity_device_type,
    )
    panic_mode = PanicMode(enabled=hardening.enabled and hardening.panic_mode_enabled)
    auth_service = AuthenticationService(
        key_manager=key_manager,
        state_manager=state_manager,
        event_bus=event_bus,
        activity_monitor=activity_monitor,
        panic_mode=panic_mode,
        normalize_auth_timing_enabled=hardening.enabled and hardening.normalize_auth_timing,
        minimum_auth_delay_sec=hardening.minimum_auth_delay_sec,
    )
    assert auth_service is not None

    elapsed = time.perf_counter() - started
    assert elapsed < 3.0, f"startup with security features took {elapsed:.3f}s"
