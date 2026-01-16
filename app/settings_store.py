import copy
import json

from .db import fetch_all_settings, fetch_all_state, get_json, set_json


def deep_merge(defaults, overrides):
    if overrides is None:
        return copy.deepcopy(defaults)
    result = copy.deepcopy(defaults)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get_settings(key, defaults):
    saved = get_json("settings", key, None)
    return deep_merge(defaults, saved or {})


def save_settings(key, settings):
    set_json("settings", key, settings)


def get_state(key, default):
    return get_json("state", key, default)


def save_state(key, state):
    set_json("state", key, state)


def export_settings():
    raw_settings = fetch_all_settings()
    settings_payload = {}
    for key, value in raw_settings.items():
        try:
            settings_payload[key] = json.loads(value)
        except json.JSONDecodeError:
            settings_payload[key] = value
    return {"settings": settings_payload}


def import_settings(data):
    if not isinstance(data, dict):
        raise ValueError("settings payload must be an object")
    if "settings" in data or "state" in data:
        settings_data = data.get("settings", {})
        state_data = data.get("state", {})
        if isinstance(settings_data, dict):
            for key, value in settings_data.items():
                if not isinstance(key, str):
                    continue
                set_json("settings", key, value)
        if isinstance(state_data, dict):
            for key, value in state_data.items():
                if not isinstance(key, str):
                    continue
                set_json("state", key, value)
        return
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        set_json("settings", key, value)
