import copy
import json
import base64
from pathlib import Path

from .db import export_auth_config, fetch_all_settings, get_json, replace_auth_config, set_json, utc_now_iso

DATA_DIR = Path("/data")
_BRANDING_ASSET_KEYS = ("company_logo", "browser_logo")


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


def _coerce_json_payload(raw_map):
    payload = {}
    for key, value in (raw_map or {}).items():
        try:
            payload[key] = json.loads(value)
        except json.JSONDecodeError:
            payload[key] = value
    return payload


def _resolve_branding_asset_path(asset_key, entry):
    entry = entry if isinstance(entry, dict) else {}
    raw_path = str(entry.get("path", "") or "").strip()
    if raw_path:
        path = Path(raw_path)
        if path.exists() and path.is_file():
            return path
    public_dir = DATA_DIR / "public"
    candidates = sorted(public_dir.glob(f"{asset_key}.*"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _export_branding_assets(settings_payload):
    assets_payload = {}
    system_settings = settings_payload.get("system") if isinstance(settings_payload.get("system"), dict) else {}
    branding = system_settings.get("branding") if isinstance(system_settings.get("branding"), dict) else {}
    for asset_key in _BRANDING_ASSET_KEYS:
        asset_path = _resolve_branding_asset_path(asset_key, branding.get(asset_key))
        if asset_path is None:
            continue
        try:
            raw_bytes = asset_path.read_bytes()
        except Exception:
            continue
        assets_payload[asset_key] = {
            "filename": asset_path.name,
            "content_type": str((branding.get(asset_key) or {}).get("content_type", "") or "").strip(),
            "updated_at": str((branding.get(asset_key) or {}).get("updated_at", "") or "").strip(),
            "data_base64": base64.b64encode(raw_bytes).decode("ascii"),
        }
    return assets_payload


def _restore_branding_asset(asset_key, payload):
    if not isinstance(payload, dict):
        return None
    encoded = str(payload.get("data_base64", "") or "").strip()
    if not encoded:
        return None
    try:
        raw_bytes = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid {asset_key} asset data: {exc}") from exc
    filename = str(payload.get("filename", "") or "").strip()
    suffix = Path(filename).suffix.lower()
    if not suffix:
        suffix = ".bin"
    public_dir = DATA_DIR / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    for old in public_dir.glob(f"{asset_key}.*"):
        try:
            old.unlink()
        except OSError:
            pass
    dest = public_dir / f"{asset_key}{suffix}"
    dest.write_bytes(raw_bytes)
    return {
        "path": str(dest),
        "content_type": str(payload.get("content_type", "") or "").strip(),
        "updated_at": str(payload.get("updated_at", "") or "").strip() or utc_now_iso(),
    }


def export_settings():
    raw_settings = fetch_all_settings()
    settings_payload = _coerce_json_payload(raw_settings)
    payload = {
        "format": "threejnotif.settings.backup",
        "version": 2,
        "exported_at": utc_now_iso(),
        "settings": settings_payload,
        "auth": export_auth_config(),
    }
    assets_payload = _export_branding_assets(settings_payload)
    if assets_payload:
        payload["assets"] = assets_payload
    return payload


def import_settings(data):
    if not isinstance(data, dict):
        raise ValueError("settings payload must be an object")
    if "settings" in data or "state" in data or "auth" in data or "assets" in data:
        settings_data = data.get("settings", {})
        state_data = data.get("state", {})
        auth_data = data.get("auth")
        assets_data = data.get("assets")
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
        if isinstance(auth_data, dict):
            replace_auth_config(auth_data)
        if isinstance(assets_data, dict):
            system_settings = get_json("settings", "system", {}) or {}
            if not isinstance(system_settings, dict):
                system_settings = {}
            branding = system_settings.get("branding") if isinstance(system_settings.get("branding"), dict) else {}
            updated = False
            for asset_key in _BRANDING_ASSET_KEYS:
                asset_meta = _restore_branding_asset(asset_key, assets_data.get(asset_key))
                if asset_meta is None:
                    continue
                branding[asset_key] = asset_meta
                updated = True
            if updated:
                system_settings["branding"] = branding
                set_json("settings", "system", system_settings)
        return
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        set_json("settings", key, value)
