import copy
import json

from .db import fetch_all_settings, get_json, set_json


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
    raw = fetch_all_settings()
    payload = {}
    for key, value in raw.items():
        try:
            payload[key] = json.loads(value)
        except json.JSONDecodeError:
            payload[key] = value
    return payload


def import_settings(data):
    if not isinstance(data, dict):
        raise ValueError("settings payload must be an object")
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        set_json("settings", key, value)
