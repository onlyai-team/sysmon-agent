"""System metric instruments: CPU, memory, disk, network, sessions."""

from __future__ import annotations

import logging
import time
from typing import Iterable, List, Optional

import psutil
from opentelemetry.metrics import CallbackOptions, Observation

LOG = logging.getLogger("sysmon.metrics")

# Pseudo filesystems that only add noise to disk usage series.
_SKIP_FSTYPES = {
    "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs",
    "devpts", "devtmpfs", "efivarfs", "fuse.gvfsd-fuse", "fuse.portal", "fusectl",
    "hugetlbfs", "iso9660", "mqueue", "nsfs", "overlay", "proc", "pstore",
    "ramfs", "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
}
_SKIP_MOUNT_PREFIXES = ("/snap/", "/var/lib/docker/", "/run/", "/sys/", "/proc/", "/dev/")


def _observe(value, attributes=None) -> Observation:
    return Observation(value, attributes or {})


class SystemMetrics:
    """Registers observable instruments; every value is read at collection time."""

    def __init__(self, meter, session_tracker=None):
        self.meter = meter
        self.session_tracker = session_tracker
        self._boot_time = psutil.boot_time()
        psutil.cpu_percent(interval=None)  # prime the delta counters
        psutil.cpu_times_percent(interval=None)
        self._instruments: List[object] = []

    # ------------------------------------------------------------- registration

    def register(self) -> None:
        m = self.meter
        add = self._instruments.append

        add(m.create_observable_gauge(
            "system.cpu.utilization", callbacks=[self._cpu_utilization],
            unit="1", description="CPU utilisation, 0..1, averaged over all cores"))
        add(m.create_observable_gauge(
            "system.cpu.time.utilization", callbacks=[self._cpu_time_states],
            unit="1", description="Fraction of CPU time per state"))
        add(m.create_observable_gauge(
            "system.cpu.logical.count", callbacks=[self._cpu_count],
            unit="{cpu}", description="Number of logical CPUs"))
        add(m.create_observable_gauge(
            "system.cpu.load_average", callbacks=[self._load_average],
            unit="1", description="Run-queue load average"))

        add(m.create_observable_gauge(
            "system.memory.usage", callbacks=[self._memory_usage],
            unit="By", description="Physical memory by state"))
        add(m.create_observable_gauge(
            "system.memory.utilization", callbacks=[self._memory_utilization],
            unit="1", description="Fraction of physical memory in use"))
        add(m.create_observable_gauge(
            "system.paging.usage", callbacks=[self._swap_usage],
            unit="By", description="Swap / page file by state"))
        add(m.create_observable_gauge(
            "system.paging.utilization", callbacks=[self._swap_utilization],
            unit="1", description="Fraction of swap / page file in use"))

        add(m.create_observable_gauge(
            "system.filesystem.usage", callbacks=[self._filesystem_usage],
            unit="By", description="Filesystem space by state, per mount point"))
        add(m.create_observable_gauge(
            "system.filesystem.utilization", callbacks=[self._filesystem_utilization],
            unit="1", description="Fraction of filesystem space in use"))
        add(m.create_observable_counter(
            "system.disk.io", callbacks=[self._disk_io_bytes],
            unit="By", description="Bytes read from / written to disk since boot"))
        add(m.create_observable_counter(
            "system.disk.operations", callbacks=[self._disk_io_ops],
            unit="{operation}", description="Disk read/write operations since boot"))

        add(m.create_observable_counter(
            "system.network.io", callbacks=[self._net_bytes],
            unit="By", description="Bytes received / transmitted since boot"))
        add(m.create_observable_counter(
            "system.network.packets", callbacks=[self._net_packets],
            unit="{packet}", description="Packets received / transmitted since boot"))
        add(m.create_observable_counter(
            "system.network.errors", callbacks=[self._net_errors],
            unit="{error}", description="Network errors since boot"))
        add(m.create_observable_counter(
            "system.network.dropped", callbacks=[self._net_dropped],
            unit="{packet}", description="Dropped packets since boot"))
        add(m.create_observable_gauge(
            "system.network.connections", callbacks=[self._net_connections],
            unit="{connection}", description="TCP connections by state"))

        add(m.create_observable_gauge(
            "system.processes.count", callbacks=[self._process_count],
            unit="{process}", description="Number of processes"))
        add(m.create_observable_gauge(
            "system.uptime", callbacks=[self._uptime],
            unit="s", description="Seconds since boot"))

        if self.session_tracker is not None:
            add(m.create_observable_gauge(
                "system.sessions.active", callbacks=[self._active_sessions],
                unit="{session}", description="Active login sessions by kind"))

        LOG.info("Registered %d metric instruments", len(self._instruments))

    # ------------------------------------------------------------------- CPU

    def _cpu_utilization(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(psutil.cpu_percent(interval=None) / 100.0)

    def _cpu_time_states(self, options: CallbackOptions) -> Iterable[Observation]:
        times = psutil.cpu_times_percent(interval=None)
        for state in ("user", "system", "idle", "iowait", "steal", "nice", "irq", "softirq"):
            value = getattr(times, state, None)
            if value is not None:
                yield _observe(value / 100.0, {"state": state})

    def _cpu_count(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(psutil.cpu_count(logical=True) or 0)

    def _load_average(self, options: CallbackOptions) -> Iterable[Observation]:
        try:
            one, five, fifteen = psutil.getloadavg()
        except (AttributeError, OSError):
            return
        yield _observe(one, {"period": "1m"})
        yield _observe(five, {"period": "5m"})
        yield _observe(fifteen, {"period": "15m"})

    # ---------------------------------------------------------------- memory

    def _memory_usage(self, options: CallbackOptions) -> Iterable[Observation]:
        mem = psutil.virtual_memory()
        yield _observe(mem.used, {"state": "used"})
        yield _observe(mem.available, {"state": "available"})
        yield _observe(mem.total, {"state": "total"})
        for state in ("free", "cached", "buffers"):
            value = getattr(mem, state, None)
            if value is not None:
                yield _observe(value, {"state": state})

    def _memory_utilization(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(psutil.virtual_memory().percent / 100.0)

    def _swap_usage(self, options: CallbackOptions) -> Iterable[Observation]:
        swap = psutil.swap_memory()
        yield _observe(swap.used, {"state": "used"})
        yield _observe(swap.free, {"state": "free"})
        yield _observe(swap.total, {"state": "total"})

    def _swap_utilization(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(psutil.swap_memory().percent / 100.0)

    # ------------------------------------------------------------------ disk

    def _partitions(self):
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception as exc:
            LOG.debug("disk_partitions failed: %s", exc)
            return
        for part in partitions:
            if part.fstype.lower() in _SKIP_FSTYPES:
                continue
            if any(part.mountpoint.startswith(p) for p in _SKIP_MOUNT_PREFIXES):
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            yield part, usage

    def _filesystem_usage(self, options: CallbackOptions) -> Iterable[Observation]:
        for part, usage in self._partitions():
            base = {"device": part.device, "mountpoint": part.mountpoint,
                    "type": part.fstype}
            for state in ("used", "free", "total"):
                attrs = dict(base)
                attrs["state"] = state
                yield _observe(getattr(usage, state), attrs)

    def _filesystem_utilization(self, options: CallbackOptions) -> Iterable[Observation]:
        for part, usage in self._partitions():
            yield _observe(usage.percent / 100.0, {
                "device": part.device, "mountpoint": part.mountpoint, "type": part.fstype})

    def _disk_counters(self):
        try:
            return psutil.disk_io_counters(perdisk=True) or {}
        except Exception as exc:
            LOG.debug("disk_io_counters failed: %s", exc)
            return {}

    def _disk_io_bytes(self, options: CallbackOptions) -> Iterable[Observation]:
        for device, counters in self._disk_counters().items():
            yield _observe(counters.read_bytes, {"device": device, "direction": "read"})
            yield _observe(counters.write_bytes, {"device": device, "direction": "write"})

    def _disk_io_ops(self, options: CallbackOptions) -> Iterable[Observation]:
        for device, counters in self._disk_counters().items():
            yield _observe(counters.read_count, {"device": device, "direction": "read"})
            yield _observe(counters.write_count, {"device": device, "direction": "write"})

    # --------------------------------------------------------------- network

    def _net_counters(self):
        try:
            return psutil.net_io_counters(pernic=True) or {}
        except Exception as exc:
            LOG.debug("net_io_counters failed: %s", exc)
            return {}

    def _net_bytes(self, options: CallbackOptions) -> Iterable[Observation]:
        for nic, counters in self._net_counters().items():
            yield _observe(counters.bytes_recv, {"device": nic, "direction": "receive"})
            yield _observe(counters.bytes_sent, {"device": nic, "direction": "transmit"})

    def _net_packets(self, options: CallbackOptions) -> Iterable[Observation]:
        for nic, counters in self._net_counters().items():
            yield _observe(counters.packets_recv, {"device": nic, "direction": "receive"})
            yield _observe(counters.packets_sent, {"device": nic, "direction": "transmit"})

    def _net_errors(self, options: CallbackOptions) -> Iterable[Observation]:
        for nic, counters in self._net_counters().items():
            yield _observe(counters.errin, {"device": nic, "direction": "receive"})
            yield _observe(counters.errout, {"device": nic, "direction": "transmit"})

    def _net_dropped(self, options: CallbackOptions) -> Iterable[Observation]:
        for nic, counters in self._net_counters().items():
            yield _observe(counters.dropin, {"device": nic, "direction": "receive"})
            yield _observe(counters.dropout, {"device": nic, "direction": "transmit"})

    def _net_connections(self, options: CallbackOptions) -> Iterable[Observation]:
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError, OSError) as exc:
            LOG.debug("net_connections denied: %s", exc)
            return
        counts = {}
        for conn in connections:
            counts[conn.status] = counts.get(conn.status, 0) + 1
        for status, count in counts.items():
            yield _observe(count, {"state": str(status).lower()})

    # ----------------------------------------------------------------- misc

    def _process_count(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(len(psutil.pids()))

    def _uptime(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(time.time() - self._boot_time)

    def _active_sessions(self, options: CallbackOptions) -> Iterable[Observation]:
        counts = self.session_tracker.active_counts()
        if not counts:
            yield _observe(0, {"session.kind": "none"})
            return
        for kind, count in counts.items():
            yield _observe(count, {"session.kind": kind})


def snapshot() -> dict:
    """A one-shot human-readable summary, used by 'sysmon-agent status'."""
    mem = psutil.virtual_memory()
    disks = []
    for part in psutil.disk_partitions(all=False):
        if part.fstype.lower() in _SKIP_FSTYPES:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append((part.mountpoint, usage.percent))
    net = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "memory_percent": mem.percent,
        "memory_total": mem.total,
        "disks": disks,
        "net_recv": net.bytes_recv,
        "net_sent": net.bytes_sent,
        "uptime_seconds": time.time() - psutil.boot_time(),
        "processes": len(psutil.pids()),
    }
