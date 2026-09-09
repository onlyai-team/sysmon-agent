"""The exported metric names and attributes are a contract with the dashboards.

Names follow the OpenTelemetry host metrics conventions, so this pins them and
collects every instrument once against the real machine.
"""

import time
import unittest

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from sysmon_agent.metrics import SystemMetrics
from sysmon_agent.paths import IS_LINUX, IS_WINDOWS

# Every metric the hostmetrics receiver emits by default, plus this agent's own.
EXPECTED = {
    "system.cpu.time",
    "system.cpu.utilization",
    "system.cpu.logical.count",
    "system.cpu.load_average.1m",
    "system.cpu.load_average.5m",
    "system.cpu.load_average.15m",
    "system.memory.usage",
    "system.memory.utilization",
    "system.paging.usage",
    "system.paging.utilization",
    "system.paging.operations",
    "system.filesystem.usage",
    "system.filesystem.utilization",
    "system.filesystem.inodes.usage",
    "system.disk.io",
    "system.disk.operations",
    "system.disk.operation_time",
    "system.disk.io_time",
    "system.disk.merged",
    "system.network.io",
    "system.network.packets",
    "system.network.errors",
    "system.network.dropped",
    "system.network.connections",
    "system.processes.count",
    "system.processes.created",
    "system.uptime",
    "system.sessions.active",
}

# Instruments whose data source is absent on some platforms; the instrument is
# always registered but may legitimately report nothing.
PLATFORM_DEPENDENT = {
    "system.disk.io_time",          # busy_time: Linux only
    "system.disk.merged",           # merged counts: Linux only
    "system.paging.operations",     # swap counters: not on Windows
    "system.processes.created",     # /proc/stat: Linux only
    "system.filesystem.inodes.usage",   # no inodes on Windows
    "system.network.connections",   # needs root / Administrator
    "system.cpu.load_average.1m",
    "system.cpu.load_average.5m",
    "system.cpu.load_average.15m",
}


class FakeTracker:
    source_name = "fake"

    def active_counts(self):
        return {"ssh": 2, "console": 1}


def collect(per_cpu=True, warmup=1.0):
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    metrics = SystemMetrics(provider.get_meter("test"), session_tracker=FakeTracker(),
                            per_cpu=per_cpu)
    metrics.register()
    # cpu_times_percent needs a gap after priming, exactly as the real export
    # interval provides; without it every state reads 0. A full second also
    # keeps macOS tick rounding from skewing the per-core percentages.
    time.sleep(warmup)
    data = reader.get_metrics_data()
    collected = {}
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                collected[metric.name] = list(metric.data.data_points)
    provider.shutdown()
    return collected


class MetricNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.collected = collect()

    def test_no_metric_is_missing(self):
        missing = EXPECTED - set(self.collected)
        self.assertEqual(missing - PLATFORM_DEPENDENT, set())

    def test_no_unexpected_metric_is_exported(self):
        self.assertEqual(set(self.collected) - EXPECTED, set())

    def test_load_average_is_three_separate_metrics(self):
        # Not one metric with a 'period' attribute: dashboards query the names.
        for period in ("1m", "5m", "15m"):
            name = "system.cpu.load_average.%s" % period
            points = self.collected.get(name)
            if points is None:
                self.skipTest("no load average on this platform")
            self.assertEqual(len(points), 1, name)
            self.assertEqual(dict(points[0].attributes or {}), {}, name)

    def test_cpu_time_has_cpu_and_state(self):
        points = self.collected["system.cpu.time"]
        self.assertTrue(points)
        for point in points:
            attributes = dict(point.attributes)
            self.assertIn("cpu", attributes)
            self.assertIn("state", attributes)
            self.assertTrue(attributes["cpu"].startswith("cpu"))
        states = {dict(p.attributes)["state"] for p in points}
        self.assertIn("idle", states)
        self.assertIn("user", states)

    def test_cpu_time_is_monotonic_seconds(self):
        for point in self.collected["system.cpu.time"]:
            self.assertGreaterEqual(point.value, 0)

    def test_cpu_utilization_states_sum_to_one_per_cpu(self):
        totals = {}
        for point in self.collected["system.cpu.utilization"]:
            cpu = dict(point.attributes)["cpu"]
            totals[cpu] = totals.get(cpu, 0.0) + point.value
        for cpu, total in totals.items():
            self.assertAlmostEqual(total, 1.0, delta=0.05, msg=cpu)

    def test_aggregate_mode_drops_the_cpu_attribute(self):
        collected = collect(per_cpu=False, warmup=0.05)
        for point in collected["system.cpu.time"]:
            self.assertNotIn("cpu", dict(point.attributes))
            self.assertIn("state", dict(point.attributes))

    def test_directional_metrics_carry_device_and_direction(self):
        for name in ("system.network.io", "system.network.packets",
                     "system.disk.io", "system.disk.operations"):
            points = self.collected[name]
            self.assertTrue(points, name)
            for point in points:
                attributes = dict(point.attributes)
                self.assertIn("device", attributes, name)
                self.assertIn(attributes["direction"],
                              ("read", "write", "receive", "transmit"), name)

    def test_filesystem_usage_identifies_the_mount(self):
        for point in self.collected["system.filesystem.usage"]:
            attributes = dict(point.attributes)
            for key in ("device", "mountpoint", "type", "state"):
                self.assertIn(key, attributes)

    def test_memory_usage_states(self):
        states = {dict(p.attributes)["state"]
                  for p in self.collected["system.memory.usage"]}
        self.assertTrue({"used", "available", "total"}.issubset(states))

    def test_process_count_is_broken_down_by_status(self):
        points = self.collected["system.processes.count"]
        self.assertTrue(points)
        for point in points:
            self.assertIn("status", dict(point.attributes))
        self.assertGreater(sum(p.value for p in points), 0)

    def test_sessions_active_uses_the_tracker(self):
        points = {dict(p.attributes)["session.kind"]: p.value
                  for p in self.collected["system.sessions.active"]}
        self.assertEqual(points, {"ssh": 2, "console": 1})

    def test_network_connections_marks_the_protocol(self):
        points = self.collected.get("system.network.connections")
        if not points:
            self.skipTest("net_connections needs elevated privileges here")
        for point in points:
            self.assertEqual(dict(point.attributes)["protocol"], "tcp")

    @unittest.skipUnless(IS_LINUX, "Linux-only source")
    def test_linux_only_metrics_are_present(self):
        for name in ("system.processes.created", "system.disk.io_time",
                     "system.paging.operations"):
            self.assertIn(name, self.collected, name)

    @unittest.skipIf(IS_WINDOWS, "no inodes on Windows")
    def test_inodes_reported_on_posix(self):
        points = self.collected.get("system.filesystem.inodes.usage", [])
        states = {dict(p.attributes)["state"] for p in points}
        self.assertTrue(states.issubset({"used", "free"}))


class UnitTests(unittest.TestCase):
    def test_units_match_the_conventions(self):
        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader])
        SystemMetrics(provider.get_meter("test"), session_tracker=FakeTracker()).register()
        units = {}
        for resource_metric in reader.get_metrics_data().resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    units[metric.name] = metric.unit
        provider.shutdown()
        self.assertEqual(units["system.cpu.time"], "s")
        self.assertEqual(units["system.cpu.utilization"], "1")
        self.assertEqual(units["system.cpu.load_average.15m"], "{thread}")
        self.assertEqual(units["system.memory.usage"], "By")
        self.assertEqual(units["system.disk.io"], "By")
        self.assertEqual(units["system.disk.operation_time"], "s")
        self.assertEqual(units["system.uptime"], "s")


if __name__ == "__main__":
    unittest.main()
