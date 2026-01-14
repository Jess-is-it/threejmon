
def parse_bool(form, key):
    value = form.get(key)
    return value in ("on", "true", "1", True)


def parse_int(form, key, default):
    value = form.get(key, "")
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_float(form, key, default):
    value = form.get(key, "")
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_lines(text):
    if text is None:
        return []
    lines = []
    for line in str(text).splitlines():
        cleaned = line.strip()
        if cleaned:
            lines.append(cleaned)
    return lines


def parse_int_list(text):
    values = []
    for item in parse_lines(text):
        try:
            values.append(int(item))
        except (TypeError, ValueError):
            continue
    return values


def parse_targets(text):
    targets = []
    for line in parse_lines(text):
        parts = [part.strip() for part in line.split("|")]
        if not parts:
            continue
        ip = parts[0]
        if not ip:
            continue
        label = parts[1] if len(parts) > 1 and parts[1] else ip
        down_message = parts[2] if len(parts) > 2 and parts[2] else f"{label} ({ip}) is DOWN"
        up_message = parts[3] if len(parts) > 3 and parts[3] else f"{label} ({ip}) is UP"
        targets.append(
            {
                "ip": ip,
                "label": label,
                "down_message": down_message,
                "up_message": up_message,
            }
        )
    return targets
