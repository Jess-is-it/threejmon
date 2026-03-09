
def parse_bool(form, key):
    if hasattr(form, "getlist"):
        values = form.getlist(key)
        if values:
            return any(str(value).lower() in ("on", "true", "1", "yes") for value in values)
    value = form.get(key)
    return str(value).lower() in ("on", "true", "1", "yes")


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

