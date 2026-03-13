import re


def _normalize_unit(unit: str) -> str:
    value = str(unit or "").strip().lower()
    return "hour" if value == "hour" else "day"


def _normalize_int(value, default_value: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default_value)


def offline_rule_minutes(value, unit: str) -> int:
    normalized_value = max(_normalize_int(value, 1), 0)
    normalized_unit = _normalize_unit(unit)
    return normalized_value * (60 if normalized_unit == "hour" else 1440)


def offline_rule_compact_label(value, unit: str) -> str:
    normalized_value = max(_normalize_int(value, 1), 0)
    normalized_unit = _normalize_unit(unit)
    suffix = "H" if normalized_unit == "hour" else "D"
    return f"{normalized_value}{suffix}"


def _sanitize_rule_id(raw_value: str, fallback_index: int) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(raw_value or "").strip()).strip("-").lower()
    return value or f"offline-rule-{fallback_index}"


def normalize_offline_tracking_rules(raw_rules, fallback_value=1, fallback_unit="day"):
    rules = []
    seen_ids = set()
    fallback_value = max(_normalize_int(fallback_value, 1), 0)
    fallback_unit = _normalize_unit(fallback_unit)

    source_rules = raw_rules if isinstance(raw_rules, list) else []
    for idx, raw_rule in enumerate(source_rules, start=1):
        if not isinstance(raw_rule, dict):
            continue
        value = max(_normalize_int(raw_rule.get("value"), fallback_value), 0)
        unit = _normalize_unit(raw_rule.get("unit") or fallback_unit)
        enabled = bool(raw_rule.get("enabled", True))
        position = _normalize_int(raw_rule.get("position"), idx)
        rule_id = _sanitize_rule_id(raw_rule.get("id"), idx)
        base_id = rule_id
        suffix = 2
        while rule_id in seen_ids:
            rule_id = f"{base_id}-{suffix}"
            suffix += 1
        seen_ids.add(rule_id)
        minutes = offline_rule_minutes(value, unit)
        compact = offline_rule_compact_label(value, unit)
        rules.append(
            {
                "id": rule_id,
                "value": value,
                "unit": unit,
                "enabled": enabled,
                "position": position,
                "minutes": minutes,
                "label": compact,
                "tab_label": f"Offline {compact}",
            }
        )

    if not rules:
        compact = offline_rule_compact_label(fallback_value, fallback_unit)
        rules = [
            {
                "id": "offline-rule-1",
                "value": fallback_value,
                "unit": fallback_unit,
                "enabled": True,
                "position": 1,
                "minutes": offline_rule_minutes(fallback_value, fallback_unit),
                "label": compact,
                "tab_label": f"Offline {compact}",
            }
        ]

    rules.sort(key=lambda item: (int(item.get("position", 0) or 0), int(item.get("minutes", 0) or 0), str(item.get("id") or "")))
    if not any(bool(item.get("enabled")) for item in rules):
        rules[0]["enabled"] = True

    for idx, rule in enumerate(rules, start=1):
        rule["position"] = idx
    return rules


def enabled_offline_tracking_rules(raw_rules, fallback_value=1, fallback_unit="day"):
    rules = normalize_offline_tracking_rules(raw_rules, fallback_value=fallback_value, fallback_unit=fallback_unit)
    enabled_rules = [dict(rule) for rule in rules if bool(rule.get("enabled"))]
    return enabled_rules if enabled_rules else [dict(rules[0])]


def offline_rules_summary_text(raw_rules, fallback_value=1, fallback_unit="day"):
    rules = enabled_offline_tracking_rules(raw_rules, fallback_value=fallback_value, fallback_unit=fallback_unit)
    return ", ".join(str(rule.get("label") or "").strip() for rule in rules if str(rule.get("label") or "").strip())
