"""System metric instruments.

Names and attributes follow the OpenTelemetry host metrics semantic
conventions, the same set the collector's hostmetrics receiver emits, so
standard dashboards work without remapping.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Dict, Iterable, List, Optional

import psutil
from opentelemetry.metrics import CallbackOptions, Observation

from .paths import IS_LINUX, IS_WINDOWS

LOG = logging.getLogger("sysmon.metrics")

# Pseudo filesystems that only add noise to disk usage series.
_SKIP_FSTYPES = {
    "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs",
    "devpts", "devtmpfs", "efivarfs", "fuse.gvfsd-fuse", "fuse.portal", "fusectl",
    "hugetlbfs", "iso9660", "mqueue", "nsfs", "overlay", "proc", "pstore",
    "ramfs", "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
}
_SKIP_MOUNT_PREFIXES = ("/snap/", "/var/lib/docker/", "/run/", "/sys/", "/proc/", "/dev/")

# psutil's cpu_times fields -> the semantic convention's 'state' values.
_CPU_STATES = {
    "user": "user",
    "system": "system",
    "idle": "idle",
    "nice": "nice",
    "iowait": "wait",
    "irq": "interrupt",
    "interrupt": "interrupt",
    "softirq": "softirq",
    "steal": "steal",
    "dpc": "dpc",
}

_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _observe(value, attributes=None) -> Observation:
    return Observation(value, attributes or {})


class SystemMetrics:
    """Registers observable instruments; every value is read at collection time."""

    def __init__(self, meter, session_tracker=None, per_cpu: bool = True):
        self.meter = meter
        self.session_tracker = session_tracker
        self.per_cpu = per_cpu
        self._boot_time = psutil.boot_time()
        # Prime the delta counters so the first export is not a spike.
        psutil.cpu_times_percent(interval=None)
        psutil.cpu_times_percent(interval=None, percpu=True)
        self._instruments: List[object] = []

    # ------------------------------------------------------------- registration

    def register(self) -> None:
        m = self.meter
        add = self._instruments.append

        # -- cpu ------------------------------------------------------------
        add(m.create_observable_counter(
            "system.cpu.time", callbacks=[self._cpu_time],
            unit="s", description="Seconds each CPU spent in each state"))
        add(m.create_observable_gauge(
            "system.cpu.utilization", callbacks=[self._cpu_utilization],
            unit="1", description="Fraction of CPU time in each state, 0..1"))
        add(m.create_observable_gauge(
            "system.cpu.logical.count", callbacks=[self._cpu_count],
            unit="{cpu}", description="Number of logical CPUs"))
        for index, period in enumerate(("1m", "5m", "15m")):
            add(m.create_observable_gauge(
                "system.cpu.load_average.%s" % period,
                callbacks=[self._load_average(index)],
                unit="{thread}", description="Run-queue load average over %s" % period))

        # -- memory ---------------------------------------------------------
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
        add(m.create_observable_counter(
            "system.paging.operations", callbacks=[self._paging_operations],
            unit="{operation}", description="Pages swapped in and out since boot"))

        # -- disk -----------------------------------------------------------
        add(m.create_observable_gauge(
            "system.filesystem.usage", callbacks=[self._filesystem_usage],
            unit="By", description="Filesystem space by state, per mount point"))
        add(m.create_observable_gauge(
            "system.filesystem.utilization", callbacks=[self._filesystem_utilization],
            unit="1", description="Fraction of filesystem space in use"))
        add(m.create_observable_gauge(
            "system.filesystem.inodes.usage", callbacks=[self._filesystem_inodes],
            unit="{inode}", description="Filesystem inodes by state"))
        add(m.create_observable_counter(
            "system.disk.io", callbacks=[self._disk_io_bytes],
            unit="By", description="Bytes read from / written to disk since boot"))
        add(m.create_observable_counter(
            "system.disk.operations", callbacks=[self._disk_io_ops],
            unit="{operation}", description="Disk read/write operations since boot"))
        add(m.create_observable_counter(
            "system.disk.operation_time", callbacks=[self._disk_operation_time],
            unit="s", description="Time spent in disk reads and writes"))
        add(m.create_observable_counter(
            "system.disk.io_time", callbacks=[self._disk_io_time],
            unit="s", description="Time the disk spent activated"))
        add(m.create_observable_counter(
            "system.disk.merged", callbacks=[self._disk_merged],
            unit="{operation}", description="Disk operations merged into others"))

        # -- network --------------------------------------------------------
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

        # -- processes and host ---------------------------------------------
        add(m.create_observable_gauge(
            "system.processes.count", callbacks=[self._process_count],
            unit="{process}", description="Processes by status"))
        add(m.create_observable_counter(
            "system.processes.created", callbacks=[self._processes_created],
            unit="{process}", description="Processes created since boot"))
        add(m.create_observable_gauge(
            "system.uptime", callbacks=[self._uptime],
            unit="s", description="Seconds since boot"))

        if self.session_tracker is not None:
            add(m.create_observable_gauge(
                "system.sessions.active", callbacks=[self._active_sessions],
                unit="{session}", description="Active login sessions by kind"))

        LOG.info("Registered %d metric instruments (per-cpu: %s)",
                 len(self._instruments), self.per_cpu)

    # ------------------------------------------------------------------- CPU

    @staticmethod
    def _states(times) -> Iterable:
        for field, state in _CPU_STATES.items():
            value = getattr(times, field, None)
            if value is not None:
                yield state, value

    def _cpu_time(self, options: CallbackOptions) -> Iterable[Observation]:
        if self.per_cpu:
            for index, times in enumerate(psutil.cpu_times(percpu=True)):
                for state, value in self._states(times):
                    yield _observe(value, {"cpu": "cpu%d" % index, "state": state})
        else:
            for state, value in self._states(psutil.cpu_times()):
                yield _observe(value, {"state": state})

    def _cpu_utilization(self, options: CallbackOptions) -> Iterable[Observation]:
        if self.per_cpu:
            for index, times in enumerate(psutil.cpu_times_percent(percpu=True)):
                for state, value in self._states(times):
                    yield _observe(value / 100.0,
                                   {"cpu": "cpu%d" % index, "state": state})
        else:
            for state, value in self._states(psutil.cpu_times_percent()):
                yield _observe(value / 100.0, {"state": state})

    def _cpu_count(self, options: CallbackOptions) -> Iterable[Observation]:
        yield _observe(psutil.cpu_count(logical=True) or 0)

    def _load_average(self, index: int):
        def callback(options: CallbackOptions) -> Iterable[Observation]:
            try:
                yield _observe(psutil.getloadavg()[index])
            except (AttributeError, OSError) as exc:
                LOG.debug("getloadavg unavailable: %s", exc)

        return callback

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

    def _paging_operations(self, options: CallbackOptions) -> Iterable[Observation]:
        # psutil reports bytes; the convention counts pages, and psutil derives
        # those bytes from the kernel's page counters in the first place.
        swap = psutil.swap_memory()
        swapped_in = getattr(swap, "sin", 0) or 0
        swapped_out = getattr(swap, "sout", 0) or 0
        if IS_WINDOWS or (swapped_in == 0 and swapped_out == 0 and not IS_LINUX):
            return
        yield _observe(swapped_in // _PAGE_SIZE,
                       {"direction": "page_in", "type": "major"})
        yield _observe(swapped_out // _PAGE_SIZE,
                       {"direction": "page_out", "type": "major"})

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

    @staticmethod
    def _mount_attributes(part) -> Dict[str, str]:
        return {"device": part.device, "mountpoint": part.mountpoint,
                "type": part.fstype, "mode": "rw" if "rw" in part.opts else "ro"}

    def _filesystem_usage(self, options: CallbackOptions) -> Iterable[Observation]:
        for part, usage in self._partitions():
            base = self._mount_attributes(part)
            for state in ("used", "free", "total"):
                attrs = dict(base)
                attrs["state"] = state
                yield _observe(getattr(usage, state), attrs)

    def _filesystem_utilization(self, options: CallbackOptions) -> Iterable[Observation]:
        for part, usage in self._partitions():
            yield _observe(usage.percent / 100.0, self._mount_attributes(part))

    def _filesystem_inodes(self, options: CallbackOptions) -> Iterable[Observation]:
        if not hasattr(os, "statvfs"):
            return  # Windows has no inode concept
        for part, _ in self._partitions():
            try:
                stats = os.statvfs(part.mountpoint)
            except OSError:
                continue
            if not stats.f_files:
                continue
            base = self._mount_attributes(part)
            used = dict(base, state="used")
            free = dict(base, state="free")
            yield _observe(stats.f_files - stats.f_ffree, used)
            yield _observe(stats.f_ffree, free)

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

    def _disk_operation_time(self, options: CallbackOptions) -> Iterable[Observation]:
        for device, counters in self._disk_counters().items():
            for field, direction in (("read_time", "read"), ("write_time", "write")):
                value = getattr(counters, field, None)
                if value is not None:
                    yield _observe(value / 1000.0,
                                   {"device": device, "direction": direction})

    def _disk_io_time(self, options: CallbackOptions) -> Iterable[Observation]:
        for device, counters in self._disk_counters().items():
            busy = getattr(counters, "busy_time", None)
            if busy is not None:
                yield _observe(busy / 1000.0, {"device": device})

    def _disk_merged(self, options: CallbackOptions) -> Iterable[Observation]:
        for device, counters in self._disk_counters().items():
            for field, direction in (("read_merged_count", "read"),
                                     ("write_merged_count", "write")):
                value = getattr(counters, field, None)
                if value is not None:
                    yield _observe(value, {"device": device, "direction": direction})

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
        counts: Dict[str, int] = {}
        for conn in connections:
            counts[conn.status] = counts.get(conn.status, 0) + 1
        for status, count in counts.items():
            yield _observe(count, {"protocol": "tcp", "state": str(status).lower()})

    # ----------------------------------------------------------------- misc

    def _process_count(self, options: CallbackOptions) -> Iterable[Observation]:
        counts: Dict[str, int] = {}
        try:
            for proc in psutil.process_iter(["status"]):
                status = proc.info.get("status") or "unknown"
                counts[status] = counts.get(status, 0) + 1
        except Exception as exc:
            LOG.debug("process_iter failed: %s", exc)
            yield _observe(len(psutil.pids()), {"status": "unknown"})
            return
        for status, count in counts.items():
            yield _observe(count, {"status": status})

    def _processes_created(self, options: CallbackOptions) -> Iterable[Observation]:
        if not IS_LINUX:
            return
        try:
            with open("/proc/stat", "r") as handle:
                for line in handle:
                    if line.startswith("processes "):
                        yield _observe(int(line.split()[1]))
                        return
        except (OSError, ValueError, IndexError) as exc:
            LOG.debug("/proc/stat unreadable: %s", exc)

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
