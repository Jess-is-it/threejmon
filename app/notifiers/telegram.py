import json
import urllib.parse
import urllib.request


class TelegramError(RuntimeError):
    pass


def _friendly_telegram_error(message):
    msg = (message or "").lower()
    if "chat not found" in msg or "chat_id" in msg or "chat id" in msg:
        return "Telegram ChatID error, Please check your ChatID."
    if "unauthorized" in msg or "not found" in msg or "token" in msg:
        return "Telegram Bot Token error, Please check your bot token."
    if msg:
        return f"Telegram error: {message}"
    return "Telegram error: Unknown response from Telegram."


def send_telegram(token, chat_id, text, timeout=20):
    if not token or not chat_id:
        raise TelegramError("Telegram settings missing: bot token or chat ID.")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(url, data=payload)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        description = ""
        try:
            data = json.loads(body)
            description = data.get("description", "")
        except Exception:
            description = body
        raise TelegramError(_friendly_telegram_error(description)) from exc
    except urllib.error.URLError as exc:
        raise TelegramError("Telegram network error, please check connectivity.") from exc
