def _command_help():
    return "\n".join(
        [
            "Telegram commands:",
            "/? or /help - show this list",
            "/status - show command module status",
        ]
    )


def handle_telegram_command(settings, text):
    raw = (text or "").strip()
    if not raw:
        return None
    command = raw.split()[0].split("@", 1)[0].lower()
    if command in ("/?", "/help", "/start"):
        return _command_help()
    if command == "/status":
        return "Telegram command module is active. ISP Pulsewatch commands were removed."
    return "Unknown command. Send /help for available commands."
