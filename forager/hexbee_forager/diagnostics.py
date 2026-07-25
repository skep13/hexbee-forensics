"""Diagnostics collectors — the same agent, pointed at machine health.

`hexbee-forager collect --mode diagnostics` reuses every piece of Forager
plumbing (Hive discovery, batching, offline spooling, watch mode) and swaps
the forensic collectors for health ones. There is no second agent to deploy
and no extra memory cost: the collectors are the same shape, reading from
`/sys`, `/proc`, `smartctl`, and the platform's own tooling.

Two event types come out:

    diagnostic_snapshot   the readings themselves (severity 0)
    diagnostic_alert      a reading that crossed a threshold (severity 2)

Alerts carry a `rule` key so they thread through Hive correlation and ATT&CK
tagging exactly like forensic findings.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
from pathlib import Path

from .collectors import HAVE_PSUTIL, IS_WINDOWS, _event, _run

if HAVE_PSUTIL:
    import psutil  # type: ignore

IS_MACOS = platform.system() == "Darwin"

# Thresholds. Deliberately conservative — a field kit that cries wolf gets
# ignored.
DISK_WARN_PCT = 90
MEM_WARN_PCT = 90
SWAP_WARN_PCT = 50
TEMP_WARN_C = 80.0
LOAD_WARN_PER_CPU = 2.0


def _alert(rule: str, summary: str, **detail) -> dict:
    return _event("diagnostic_alert", {"rule": rule, "summary": summary, **detail})


# -- CPU / memory / load --------------------------------------------------

def collect_resources() -> list[dict]:
    events: list[dict] = []
    payload: dict = {"kind": "resources"}

    if HAVE_PSUTIL:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        payload |= {
            "cpu_percent": psutil.cpu_percent(interval=0.4),
            "cpu_count": psutil.cpu_count(),
            "memory_total": vm.total, "memory_available": vm.available,
            "memory_percent": vm.percent,
            "swap_total": sm.total, "swap_used": sm.used,
            "swap_percent": sm.percent,
        }
    else:
        payload |= _meminfo_native()
    try:
        load = os.getloadavg()
        payload["load_avg"] = [round(x, 2) for x in load]
    except (OSError, AttributeError):
        load = None

    events.append(_event("diagnostic_snapshot", payload))

    if payload.get("memory_percent", 0) >= MEM_WARN_PCT:
        events.append(_alert("memory_pressure",
                             f"Memory {payload['memory_percent']}% used",
                             memory_percent=payload["memory_percent"]))
    if payload.get("swap_percent", 0) >= SWAP_WARN_PCT:
        events.append(_alert("swap_pressure",
                             f"Swap {payload['swap_percent']}% used — the host "
                             f"is paging",
                             swap_percent=payload["swap_percent"]))
    cpus = payload.get("cpu_count") or 1
    if load and load[0] / cpus >= LOAD_WARN_PER_CPU:
        events.append(_alert("load_high",
                             f"Load average {load[0]:.2f} across {cpus} CPU(s)",
                             load_1m=round(load[0], 2), cpus=cpus))
    return events


def _meminfo_native() -> dict:
    """psutil-free memory figures."""
    if IS_MACOS:
        return _meminfo_macos()
    if IS_WINDOWS:
        out = _run(["wmic", "OS", "get",
                    "FreePhysicalMemory,TotalVisibleMemorySize", "/format:list"])
        free = re.search(r"FreePhysicalMemory=(\d+)", out)
        total = re.search(r"TotalVisibleMemorySize=(\d+)", out)
        if free and total:
            total_b, free_b = int(total.group(1)) * 1024, int(free.group(1)) * 1024
            return {"memory_total": total_b, "memory_available": free_b,
                    "memory_percent": round(100 * (1 - free_b / total_b), 1)}
        return {}
    try:
        values = {}
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                num = rest.strip().split()
                if num and num[0].isdigit():
                    values[key] = int(num[0]) * 1024
    except OSError:
        return {}
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    swap_total = values.get("SwapTotal", 0)
    swap_free = values.get("SwapFree", 0)
    out = {"memory_total": total, "memory_available": available}
    if total:
        out["memory_percent"] = round(100 * (1 - available / total), 1)
    if swap_total:
        out["swap_total"] = swap_total
        out["swap_used"] = swap_total - swap_free
        out["swap_percent"] = round(100 * (swap_total - swap_free) / swap_total, 1)
    return out


def _meminfo_macos() -> dict:
    """Memory figures from sysctl and vm_stat.

    macOS has no /proc. 'Free' memory is also close to meaningless here —
    the kernel deliberately uses everything for cache — so pressure is
    computed the way macOS itself thinks about it: wired plus compressed
    plus active, against the total.
    """
    total = 0
    out = _run(["sysctl", "-n", "hw.memsize"])
    if out.strip().isdigit():
        total = int(out.strip())
    if not total:
        return {}

    stats: dict[str, int] = {}
    page_size = 4096
    vm = _run(["vm_stat"])
    header = re.search(r"page size of (\d+) bytes", vm)
    if header:
        page_size = int(header.group(1))
    for line in vm.splitlines():
        m = re.match(r'"?([A-Za-z][A-Za-z ,\-]+)"?:\s+(\d+)', line.strip())
        if m:
            stats[m.group(1).strip().lower()] = int(m.group(2)) * page_size

    wired = stats.get("pages wired down", 0)
    compressed = stats.get("pages occupied by compressor", 0)
    active = stats.get("pages active", 0)
    inactive = stats.get("pages inactive", 0)
    free = stats.get("pages free", 0) + stats.get("pages speculative", 0)

    used = wired + compressed + active
    info = {
        "memory_total": total,
        # Inactive pages are reclaimable on demand, so they count as available.
        "memory_available": free + inactive,
        "memory_percent": round(100 * used / total, 1) if total else 0.0,
        "memory_wired": wired,
        "memory_compressed": compressed,
    }

    swap = _run(["sysctl", "-n", "vm.swapusage"])
    m = re.search(r"total = ([\d.]+)M.*used = ([\d.]+)M", swap)
    if m:
        swap_total = float(m.group(1)) * 1024 * 1024
        swap_used = float(m.group(2)) * 1024 * 1024
        info["swap_total"] = int(swap_total)
        info["swap_used"] = int(swap_used)
        if swap_total:
            info["swap_percent"] = round(100 * swap_used / swap_total, 1)
    return info


# -- temperature ----------------------------------------------------------

def collect_thermal() -> list[dict]:
    """CPU/SoC temperatures. On a Pi this is the single most useful reading —
    thermal throttling is the usual cause of 'the Hive got slow'."""
    readings: list[dict] = []

    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")) \
            if Path("/sys/class/thermal").is_dir() else []:
        try:
            millidegrees = int((zone / "temp").read_text().strip())
            label = (zone / "type").read_text().strip()
        except (OSError, ValueError):
            continue
        readings.append({"sensor": label, "celsius": round(millidegrees / 1000, 1)})

    if not readings and HAVE_PSUTIL and hasattr(psutil, "sensors_temperatures"):
        try:
            for name, entries in (psutil.sensors_temperatures() or {}).items():
                for entry in entries:
                    if entry.current:
                        readings.append({"sensor": entry.label or name,
                                         "celsius": round(entry.current, 1)})
        except Exception:
            pass

    if not readings and IS_MACOS:
        # Apple Silicon exposes thermals only through powermetrics, which
        # needs root. Report the pressure level instead — it needs no
        # privileges and is the number that actually matters.
        level = _run(["pmset", "-g", "therm"])
        m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", level)
        if m:
            limit = int(m.group(1))
            events = [_event("diagnostic_snapshot",
                             {"kind": "thermal", "platform": "macos",
                              "cpu_speed_limit_percent": limit,
                              "note": "per-sensor temperatures need root on "
                                      "macOS; speed limit is the useful proxy"})]
            if limit < 100:
                events.append(_alert(
                    "temperature_high",
                    f"CPU is thermally limited to {limit}% of full speed",
                    cpu_speed_limit_percent=limit))
            return events
        return []

    if not readings:
        return []

    events = [_event("diagnostic_snapshot",
                     {"kind": "thermal", "sensors": readings,
                      "max_celsius": max(r["celsius"] for r in readings)})]
    for r in readings:
        if r["celsius"] >= TEMP_WARN_C:
            events.append(_alert("temperature_high",
                                 f"{r['sensor']} at {r['celsius']} C",
                                 sensor=r["sensor"], celsius=r["celsius"]))
    return events


# -- disks ----------------------------------------------------------------

def collect_disks() -> list[dict]:
    events, usages = [], []
    mounts = _mount_points()
    for mount in mounts:
        try:
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        pct = round(100 * usage.used / usage.total, 1) if usage.total else 0.0
        usages.append({"mount": mount, "total": usage.total,
                       "free": usage.free, "used_percent": pct})
        if pct >= DISK_WARN_PCT:
            events.append(_alert("disk_full",
                                 f"{mount} is {pct}% full "
                                 f"({usage.free // (1024 ** 2)} MB free)",
                                 mount=mount, used_percent=pct, free=usage.free))
    events.insert(0, _event("diagnostic_snapshot",
                            {"kind": "disks", "filesystems": usages}))
    return events


def _mount_points() -> list[str]:
    if IS_WINDOWS:
        if HAVE_PSUTIL:
            try:
                return [p.mountpoint for p in psutil.disk_partitions(all=False)]
            except Exception:
                pass
        return [f"{chr(letter)}:\\" for letter in range(ord("A"), ord("Z") + 1)
                if os.path.exists(f"{chr(letter)}:\\")]
    if HAVE_PSUTIL:
        try:
            return [p.mountpoint for p in psutil.disk_partitions(all=False)]
        except Exception:
            pass
    mounts = ["/"]
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) > 2 and parts[0].startswith("/dev/"):
                    mounts.append(parts[1])
    except OSError:
        pass
    return sorted(set(mounts))


def collect_smart() -> list[dict]:
    """Disk health via smartmontools. Silent when smartctl is absent — it is
    not installed by default and this must never fail a collection run."""
    if not shutil.which("smartctl"):
        return []
    devices = _smart_devices()
    events = []
    for dev in devices[:8]:
        out = _run(["smartctl", "-H", "-A", dev], timeout=30)
        if not out:
            continue
        healthy = bool(re.search(r"(PASSED|OK)", out))
        attrs = {}
        for name in ("Reallocated_Sector_Ct", "Current_Pending_Sector",
                     "Offline_Uncorrectable", "Power_On_Hours",
                     "Temperature_Celsius", "Percentage Used",
                     "Media_Wearout_Indicator"):
            m = re.search(rf"{re.escape(name)}\s+.*?(\d+)\s*$", out, re.M)
            if m:
                attrs[name.lower()] = int(m.group(1))
        events.append(_event("diagnostic_snapshot",
                             {"kind": "smart", "device": dev,
                              "health_ok": healthy, "attributes": attrs}))
        if not healthy:
            events.append(_alert("smart_failure",
                                 f"SMART health check FAILED on {dev}",
                                 device=dev))
        for attr in ("reallocated_sector_ct", "current_pending_sector",
                     "offline_uncorrectable"):
            if attrs.get(attr, 0) > 0:
                events.append(_alert("smart_degraded",
                                     f"{dev}: {attr} = {attrs[attr]}",
                                     device=dev, attribute=attr,
                                     value=attrs[attr]))
    return events


def _smart_devices() -> list[str]:
    out = _run(["smartctl", "--scan"], timeout=15)
    devices = [line.split()[0] for line in out.splitlines() if line.startswith("/dev/")]
    if devices:
        return devices
    if IS_MACOS:
        # Apple's internal NVMe does not answer SMART through smartctl; only
        # attached external disks will appear.
        return [f"/dev/disk{n}" for n in range(4)
                if Path(f"/dev/disk{n}").exists()]
    return [f"/dev/{d}" for d in ("sda", "sdb", "nvme0")
            if Path(f"/dev/{d}").exists()]


# -- services -------------------------------------------------------------

def collect_services() -> list[dict]:
    """Services that should be running but are not."""
    events = []
    if IS_MACOS:
        # launchctl's last-exit-status column: non-zero means it died.
        failed = []
        for line in _run(["launchctl", "list"]).splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[1] not in ("0", "-"):
                failed.append({"label": parts[2], "exit_status": parts[1]})
        events.append(_event("diagnostic_snapshot",
                             {"kind": "services", "platform": "macos",
                              "failed_units": [f["label"] for f in failed[:40]],
                              "count": len(failed)}))
        for item in failed[:20]:
            events.append(_alert("service_failed",
                                 f"launchd job {item['label']} last exited "
                                 f"with status {item['exit_status']}",
                                 unit=item["label"],
                                 exit_status=item["exit_status"]))
        return events
    if IS_WINDOWS:
        out = _run(["sc", "query", "type=", "service", "state=", "inactive"])
        stopped = re.findall(r"SERVICE_NAME:\s*(\S+)", out)[:40]
        events.append(_event("diagnostic_snapshot",
                             {"kind": "services", "platform": "windows",
                              "stopped": stopped, "count": len(stopped)}))
        return events
    out = _run(["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"])
    failed = [line.split()[0] for line in out.splitlines() if line.strip()]
    events.append(_event("diagnostic_snapshot",
                         {"kind": "services", "platform": "linux",
                          "failed_units": failed, "count": len(failed)}))
    for unit in failed[:20]:
        events.append(_alert("service_failed", f"systemd unit {unit} has failed",
                             unit=unit))
    return events


# -- top consumers --------------------------------------------------------

def collect_top_consumers(limit: int = 10) -> list[dict]:
    rows = []
    if HAVE_PSUTIL:
        procs = []
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                procs.append((proc, proc.cpu_percent(None),
                              proc.memory_info().rss))
            except Exception:
                continue
        for proc, cpu, rss in sorted(procs, key=lambda t: t[2], reverse=True)[:limit]:
            rows.append({"pid": proc.info.get("pid"), "name": proc.info.get("name"),
                         "user": proc.info.get("username"),
                         "cpu_percent": cpu, "rss": rss})
    elif IS_WINDOWS:
        out = _run(["tasklist", "/fo", "csv", "/nh"])
        for line in out.splitlines()[:200]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 5:
                kb = parts[4].replace(",", "").replace(" K", "")
                rows.append({"name": parts[0], "pid": _safe_int(parts[1]),
                             "rss": _safe_int(kb) * 1024 if kb.isdigit() else None})
        rows = sorted(rows, key=lambda r: r.get("rss") or 0, reverse=True)[:limit]
    else:
        out = _run(["ps", "-eo", "pid,pcpu,rss,comm", "--sort=-rss", "--no-headers"])
        for line in out.splitlines()[:limit]:
            parts = line.split(None, 3)
            if len(parts) == 4:
                rows.append({"pid": _safe_int(parts[0]),
                             "cpu_percent": float(parts[1]) if parts[1] else None,
                             "rss": _safe_int(parts[2]) * 1024 if parts[2].isdigit() else None,
                             "name": parts[3]})
    return [_event("diagnostic_snapshot",
                   {"kind": "top_consumers", "processes": rows})]


def _safe_int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def collect_uptime() -> list[dict]:
    import time

    payload = {"kind": "uptime", "platform": platform.system()}
    if HAVE_PSUTIL:
        payload["uptime_seconds"] = int(time.time() - psutil.boot_time())
    elif Path("/proc/uptime").exists():
        try:
            payload["uptime_seconds"] = int(float(
                Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError, IndexError):
            pass
    elif IS_MACOS:
        m = re.search(r"sec = (\d+)", _run(["sysctl", "-n", "kern.boottime"]))
        if m:
            payload["uptime_seconds"] = int(time.time()) - int(m.group(1))
    return [_event("diagnostic_snapshot", payload)]


# Registry mirroring ALL_COLLECTORS: (name, function, volatile?)
# Volatile ones are re-sampled by `watch --mode diagnostics`.
DIAGNOSTIC_COLLECTORS = [
    ("resources", collect_resources, True),
    ("thermal", collect_thermal, True),
    ("disks", collect_disks, True),
    ("services", collect_services, True),
    ("top_consumers", collect_top_consumers, True),
    ("smart", collect_smart, False),
    ("uptime", collect_uptime, False),
]
