from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress

from .mikrotik import RouterOSClient
from .settings_defaults import ISP_PING_DEFAULTS, MIKROTIK_LOGS_DEFAULTS, WAN_PING_DEFAULTS
from .settings_store import get_settings, get_state, save_state


MIKROTIK_LOG_ACTION_NAME = "threejmon"
MIKROTIK_LOG_TOPICS = ("info", "warning", "error", "critical")


def _routeros_sentence_to_dict(sentence):
    data = {}
    for token in sentence or []:
        if not token or token == "!re":
            continue
        if token.startswith("="):
            token = token[1:]
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        data[key] = value
    return data


def _routeros_rows(client, words):
    replies = client.talk(words)
    trap = _routeros_trap_message(replies)
    if trap:
        raise RuntimeError(trap)
    return [_routeros_sentence_to_dict(sentence) for sentence in replies if sentence and sentence[0] == "!re"]


def _routeros_trap_message(replies):
    for sentence in replies or []:
        if not sentence or sentence[0] != "!trap":
            continue
        data = _routeros_sentence_to_dict(sentence)
        return (data.get("message") or "RouterOS trap").strip()
    return ""


def _run_routeros(client, words):
    replies = client.talk(words)
    trap = _routeros_trap_message(replies)
    if trap:
        raise RuntimeError(trap)
    return replies


def _router_ipv4_aliases(client):
    aliases = set()
    try:
        rows = _routeros_rows(client, ["/ip/address/print"])
    except Exception:
        return []
    for row in rows:
        raw = (row.get("address") or "").strip()
        if not raw:
            continue
        try:
            iface = ipaddress.ip_interface(raw)
        except Exception:
            continue
        if iface.version == 4:
            aliases.add(str(iface.ip))
    return sorted(aliases)


def get_mikrotik_log_setup_routers():
    routers = []
    seen = set()

    def add_router(raw, kind):
        if not isinstance(raw, dict):
            return
        host = (raw.get("host") or "").strip()
        if not host:
            return
        router_id = (raw.get("id") or host).strip()
        key = (kind, router_id, host)
        if key in seen:
            return
        seen.add(key)
        routers.append(
            {
                "id": router_id,
                "name": (raw.get("label") or raw.get("name") or raw.get("id") or host).strip(),
                "host": host,
                "port": int(raw.get("port") or 8728),
                "username": raw.get("username") or "",
                "password": raw.get("password") or "",
                "use_tls": bool(raw.get("use_tls")),
                "kind": kind,
            }
        )

    try:
        pulse = get_settings("isp_ping", ISP_PING_DEFAULTS)
        for core in ((((pulse.get("pulsewatch") or {}).get("mikrotik") or {}).get("cores")) or []):
            add_router(core, "core")
    except Exception:
        pass

    try:
        wan = get_settings("wan_ping", WAN_PING_DEFAULTS)
        for router in (wan.get("pppoe_routers") or []):
            add_router(router, "pppoe")
    except Exception:
        pass

    return routers


def build_mikrotik_log_setup_commands(remote_host, remote_port, topics=None):
    remote_host = (remote_host or "SERVER_IP").strip() or "SERVER_IP"
    safe_remote_host = remote_host.replace("\\", "\\\\").replace('"', '\\"')
    try:
        remote_port = int(remote_port or 5514)
    except Exception:
        remote_port = 5514
    topics = tuple(topics or MIKROTIK_LOG_TOPICS)
    commands = [
        f':local threejAction "{MIKROTIK_LOG_ACTION_NAME}"',
        f':local threejRemote "{safe_remote_host}"',
        f":local threejPort {remote_port}",
        ':if ([:len [/system logging action find where name=$threejAction]] = 0) do={/system logging action add name=$threejAction target=remote remote=$threejRemote remote-port=$threejPort} else={/system logging action set [find where name=$threejAction] target=remote remote=$threejRemote remote-port=$threejPort}',
    ]
    for topic in topics:
        topic = str(topic or "").strip()
        if not topic:
            continue
        commands.append(
            f':if ([:len [/system logging find where topics="{topic}" action=$threejAction]] = 0) do={{/system logging add topics="{topic}" action=$threejAction}}'
        )
    return commands


def apply_mikrotik_log_setup(router, remote_host, remote_port, timeout_seconds=8, topics=None):
    router = dict(router or {})
    label = (router.get("name") or router.get("id") or router.get("host") or "Router").strip()
    result = {
        "router_id": (router.get("id") or "").strip(),
        "router_name": label,
        "router_kind": (router.get("kind") or "").strip(),
        "host": (router.get("host") or "").strip(),
        "status": "error",
        "changed": False,
        "message": "",
        "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }
    if router.get("use_tls"):
        result["message"] = "TLS/API-SSL is not supported by the current RouterOS API client. Disable TLS or use port 8728."
        return result
    if not result["host"]:
        result["message"] = "Router host is missing."
        return result
    remote_host = (remote_host or "").strip()
    if not remote_host or remote_host == "0.0.0.0":
        result["message"] = "Auto setup requires a reachable server IP/hostname, not 0.0.0.0."
        return result

    topics = tuple(topics or MIKROTIK_LOG_TOPICS)
    client = RouterOSClient(
        result["host"],
        int(router.get("port") or 8728),
        router.get("username") or "",
        router.get("password") or "",
        timeout=max(int(timeout_seconds or 8), 1),
    )
    changed = False
    try:
        client.connect()
        source_aliases = _router_ipv4_aliases(client)
        action_rows = _routeros_rows(client, ["/system/logging/action/print", f"?name={MIKROTIK_LOG_ACTION_NAME}"])
        if action_rows:
            action_id = (action_rows[0].get(".id") or "").strip()
            action = action_rows[0]
            needs_update = (
                (action.get("target") or "").strip() != "remote"
                or (action.get("remote") or "").strip() != remote_host
                or str(action.get("remote-port") or "").strip() != str(int(remote_port))
            )
            if action_id and needs_update:
                _run_routeros(
                    client,
                    [
                        "/system/logging/action/set",
                        f"=.id={action_id}",
                        "=target=remote",
                        f"=remote={remote_host}",
                        f"=remote-port={int(remote_port)}",
                    ],
                )
                changed = True
        else:
            _run_routeros(
                client,
                [
                    "/system/logging/action/add",
                    f"=name={MIKROTIK_LOG_ACTION_NAME}",
                    "=target=remote",
                    f"=remote={remote_host}",
                    f"=remote-port={int(remote_port)}",
                ],
            )
            changed = True

        logging_rows = _routeros_rows(client, ["/system/logging/print"])
        existing_topics = {
            (row.get("topics") or "").strip()
            for row in logging_rows
            if (row.get("action") or "").strip() == MIKROTIK_LOG_ACTION_NAME
        }
        for topic in topics:
            topic = str(topic or "").strip()
            if not topic or topic in existing_topics:
                continue
            _run_routeros(client, ["/system/logging/add", f"=topics={topic}", f"=action={MIKROTIK_LOG_ACTION_NAME}"])
            changed = True

        result["status"] = "configured"
        result["changed"] = changed
        result["source_aliases"] = source_aliases
        result["message"] = "Updated router logging setup." if changed else "Router logging setup is already correct."
        return result
    except Exception as exc:
        result["message"] = str(exc)
        return result
    finally:
        client.close()


def auto_configure_mikrotik_logs(settings, remote_host=None, update_state=True):
    settings = settings if isinstance(settings, dict) else MIKROTIK_LOGS_DEFAULTS
    receiver = settings.get("receiver") if isinstance(settings.get("receiver"), dict) else {}
    auto_setup = settings.get("auto_setup") if isinstance(settings.get("auto_setup"), dict) else {}
    target_host = (remote_host or auto_setup.get("server_host") or receiver.get("host") or "").strip()
    target_port = int(receiver.get("port") or 5514)
    timeout_seconds = int(auto_setup.get("timeout_seconds") or 8)
    routers = get_mikrotik_log_setup_routers()
    results = []
    if routers:
        with ThreadPoolExecutor(max_workers=min(len(routers), 6)) as executor:
            futures = [
                executor.submit(apply_mikrotik_log_setup, router, target_host, target_port, timeout_seconds, MIKROTIK_LOG_TOPICS)
                for router in routers
            ]
            for future in as_completed(futures):
                results.append(future.result())
    results.sort(key=lambda item: ((item.get("router_kind") or ""), (item.get("router_name") or "").lower()))

    if update_state:
        state = get_state("mikrotik_logs_state", {})
        if not isinstance(state, dict):
            state = {}
        setup = state.get("setup") if isinstance(state.get("setup"), dict) else {}
        setup["last_checked_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        setup["target_host"] = target_host
        setup["target_port"] = target_port
        setup["results"] = results
        setup["configured"] = sum(1 for item in results if item.get("status") == "configured")
        setup["failed"] = sum(1 for item in results if item.get("status") != "configured")
        state["setup"] = setup
        save_state("mikrotik_logs_state", state)

    return results


def auto_configure_mikrotik_log_router(settings, router_id, router_kind="", remote_host=None, update_state=True):
    settings = settings if isinstance(settings, dict) else MIKROTIK_LOGS_DEFAULTS
    router_id = (router_id or "").strip()
    router_kind = (router_kind or "").strip()
    receiver = settings.get("receiver") if isinstance(settings.get("receiver"), dict) else {}
    auto_setup = settings.get("auto_setup") if isinstance(settings.get("auto_setup"), dict) else {}
    target_host = (remote_host or auto_setup.get("server_host") or receiver.get("host") or "").strip()
    target_port = int(receiver.get("port") or 5514)
    timeout_seconds = int(auto_setup.get("timeout_seconds") or 8)
    routers = get_mikrotik_log_setup_routers()
    router = next(
        (
            item
            for item in routers
            if (item.get("id") or "").strip() == router_id
            and (not router_kind or (item.get("kind") or "").strip() == router_kind)
        ),
        None,
    )
    if not router:
        result = {
            "router_id": router_id,
            "router_name": router_id or "Router",
            "router_kind": router_kind,
            "host": "",
            "status": "error",
            "changed": False,
            "message": "Router was not found in saved MikroTik routers.",
            "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        }
    else:
        result = apply_mikrotik_log_setup(router, target_host, target_port, timeout_seconds, MIKROTIK_LOG_TOPICS)

    if update_state:
        state = get_state("mikrotik_logs_state", {})
        if not isinstance(state, dict):
            state = {}
        setup = state.get("setup") if isinstance(state.get("setup"), dict) else {}
        existing = [
            item
            for item in (setup.get("results") or [])
            if not (
                isinstance(item, dict)
                and (item.get("router_id") or "").strip() == router_id
                and (not router_kind or (item.get("router_kind") or "").strip() == router_kind)
            )
        ]
        existing.append(result)
        existing.sort(key=lambda item: ((item.get("router_kind") or ""), (item.get("router_name") or "").lower()))
        setup["last_checked_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        setup["target_host"] = target_host
        setup["target_port"] = target_port
        setup["results"] = existing
        setup["configured"] = sum(1 for item in existing if item.get("status") == "configured")
        setup["failed"] = sum(1 for item in existing if item.get("status") != "configured")
        state["setup"] = setup
        save_state("mikrotik_logs_state", state)

    return result
