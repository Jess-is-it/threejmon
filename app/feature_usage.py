import threading
import time

_LOCK = threading.Lock()
_TOTAL_CPU_SECONDS = {}
_LAST_TOTALS = {}
_LAST_SAMPLE_AT = time.monotonic()
_REGISTERED = {
    "WAN Ping",
    "Accounts Ping",
    "Under Surveillance",
    "Usage",
    "Offline",
    "Optical Monitoring",
    "Telegram",
    "Dashboard/API",
}


class track_feature_cpu:
    def __init__(self, feature: str):
        self.feature = (feature or "").strip() or "Unknown"
        self.start = 0.0

    def __enter__(self):
        self.start = time.thread_time()
        register_feature(self.feature)
        return self

    def __exit__(self, exc_type, exc, tb):
        end = time.thread_time()
        delta = max(float(end - self.start), 0.0)
        if delta > 0:
            add_feature_cpu(self.feature, delta)
        return False


def register_feature(feature: str):
    name = (feature or "").strip()
    if not name:
        return
    with _LOCK:
        _REGISTERED.add(name)
        _TOTAL_CPU_SECONDS.setdefault(name, 0.0)
        _LAST_TOTALS.setdefault(name, 0.0)


def add_feature_cpu(feature: str, cpu_seconds: float):
    name = (feature or "").strip()
    if not name:
        return
    seconds = float(cpu_seconds or 0.0)
    if seconds <= 0:
        return
    with _LOCK:
        _REGISTERED.add(name)
        _TOTAL_CPU_SECONDS[name] = float(_TOTAL_CPU_SECONDS.get(name, 0.0) or 0.0) + seconds


def sample_feature_cpu_percent(cpu_count: int):
    global _LAST_SAMPLE_AT
    cores = max(int(cpu_count or 1), 1)
    now = time.monotonic()
    with _LOCK:
        elapsed = max(float(now - _LAST_SAMPLE_AT), 0.25)
        _LAST_SAMPLE_AT = now
        rows = []
        for feature in sorted(_REGISTERED):
            total = float(_TOTAL_CPU_SECONDS.get(feature, 0.0) or 0.0)
            prev = float(_LAST_TOTALS.get(feature, 0.0) or 0.0)
            delta = max(total - prev, 0.0)
            _LAST_TOTALS[feature] = total
            cpu_pct = max(0.0, 100.0 * delta / (elapsed * cores))
            rows.append(
                {
                    "name": feature,
                    "cpu_pct": round(cpu_pct, 1),
                    "source": "ThreeJ runtime",
                }
            )
    rows.sort(key=lambda item: (item.get("cpu_pct") or 0.0, item.get("name") or ""), reverse=True)
    return rows
