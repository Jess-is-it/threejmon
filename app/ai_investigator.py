import json
import socket
import time
import urllib.error
import urllib.request


class AIInvestigatorError(Exception):
    pass


def _extract_json_object(text):
    text = (text or "").strip()
    if not text:
        return None
    candidates = [text]
    if text.startswith("```"):
        body = text.strip("`").strip()
        if "\n" in body:
            body = body.split("\n", 1)[1]
        if body.endswith("```"):
            body = body[:-3].strip()
        if body:
            candidates.append(body)
    decoder = json.JSONDecoder()
    for candidate in candidates:
        candidate = (candidate or "").strip()
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        starts = [idx for idx, ch in enumerate(candidate) if ch == "{"]
        for start in starts:
            snippet = candidate[start:]
            try:
                parsed, _ = decoder.raw_decode(snippet)
            except Exception:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def _to_bool(value):
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "y", "recommend", "recommended"):
        return True
    if text in ("0", "false", "no", "n", "not_recommended", "not-recommended"):
        return False
    return None


def _normalize_structured_report(payload, fallback_text):
    fallback_text = (fallback_text or "").strip()
    payload = payload if isinstance(payload, dict) else {}
    report_markdown = (payload.get("report_markdown") or payload.get("report") or payload.get("markdown") or "").strip()
    if not report_markdown:
        report_markdown = fallback_text

    recommended_raw = payload.get("recommend_needs_manual_fix")
    if recommended_raw is None:
        recommended_raw = payload.get("recommended_for_needs_manual_fix")
    recommended = _to_bool(recommended_raw)
    if recommended is None:
        recommended = False

    recommendation_reason = (
        payload.get("recommendation_reason")
        or payload.get("escalation_reason")
        or payload.get("reason")
        or ""
    )
    recommendation_reason = str(recommendation_reason or "").strip()
    if not recommendation_reason:
        recommendation_reason = "No recommendation reason returned by the model."

    potential_problems = payload.get("potential_problems")
    if isinstance(potential_problems, str):
        items = [part.strip("-• ").strip() for part in potential_problems.splitlines() if part.strip()]
    elif isinstance(potential_problems, list):
        items = [str(item or "").strip() for item in potential_problems if str(item or "").strip()]
    else:
        items = []
    if not items:
        maybe_single = str(payload.get("potential_problem") or "").strip()
        if maybe_single:
            items = [maybe_single]
    items = items[:8]

    return {
        "text": report_markdown,
        "recommend_needs_manual_fix": bool(recommended),
        "recommendation_reason": recommendation_reason,
        "potential_problems": items,
    }


def _extract_chatgpt_text(payload):
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "").strip().lower() != "text":
                continue
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
        return "\n".join(parts).strip()
    return ""


def _extract_gemini_text(payload):
    if not isinstance(payload, dict):
        return ""
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ""
    first = candidates[0] if isinstance(candidates[0], dict) else {}
    content = first.get("content") if isinstance(first, dict) else {}
    parts = content.get("parts") if isinstance(content, dict) else []
    if not isinstance(parts, list):
        return ""
    texts = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str) and text.strip():
            texts.append(text.strip())
    return "\n".join(texts).strip()


def _json_request(url, headers, payload, timeout_seconds):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    timeout = max(int(timeout_seconds or 30), 5)
    last_exc = None
    for attempt in range(2):
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            try:
                return json.loads(raw)
            except Exception as exc:
                raise AIInvestigatorError("AI API returned invalid JSON") from exc
        except urllib.error.HTTPError as exc:
            if attempt == 0 and int(exc.code) in (429, 500, 502, 503, 504):
                time.sleep(0.6)
                continue
            raise AIInvestigatorError(f"AI API HTTP {exc.code}") from exc
        except Exception as exc:
            last_exc = exc
            lowered = str(exc or "").lower()
            is_timeout = isinstance(exc, socket.timeout) or "timed out" in lowered
            if attempt == 0 and is_timeout:
                time.sleep(0.4)
                continue
            raise AIInvestigatorError(f"AI API request failed: {exc}") from exc
    raise AIInvestigatorError(f"AI API request failed: {last_exc}")


def _build_prompt(context):
    payload = json.dumps(context or {}, ensure_ascii=False, indent=2)
    return (
        "You are an ISP field-investigation assistant.\n"
        "Analyze the account evidence and produce a practical report for network technicians.\n"
        "Return STRICT JSON only (no markdown wrapper, no code fences).\n\n"
        "Rules:\n"
        "1) Use only evidence in the payload; do not invent facts.\n"
        "2) If evidence is missing, state that clearly.\n"
        "3) Keep it concise and actionable.\n\n"
        "Output JSON schema:\n"
        "{\n"
        '  "recommend_needs_manual_fix": true|false,\n'
        '  "recommendation_reason": "one concise sentence",\n'
        '  "potential_problems": ["problem 1", "problem 2"],\n'
        '  "report_markdown": "markdown report with sections: Account Summary, Key Findings, Likely Root Causes, Field Technician Checklist, Recommended Next Steps (NOC)"\n'
        "}\n\n"
        "Evidence payload:\n"
        f"{payload}"
    )


def generate_investigation_report(ai_settings, context):
    ai_settings = ai_settings or {}
    provider = str(ai_settings.get("provider") or "").strip().lower()
    prompt = _build_prompt(context)

    if provider == "chatgpt":
        cfg = ai_settings.get("chatgpt") if isinstance(ai_settings.get("chatgpt"), dict) else {}
        api_key = str(cfg.get("api_key") or "").strip()
        model = str(cfg.get("model") or "gpt-4o-mini").strip() or "gpt-4o-mini"
        timeout_seconds = int(cfg.get("timeout_seconds") or 30)
        max_tokens = int(cfg.get("max_tokens") or 900)
        if not api_key:
            raise AIInvestigatorError("ChatGPT API key is not configured.")
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a precise ISP network incident investigator."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": max(200, min(max_tokens, 4000)),
        }
        response = _json_request(url, headers, payload, timeout_seconds)
        raw_text = _extract_chatgpt_text(response)
        if not raw_text:
            raise AIInvestigatorError("ChatGPT returned an empty report.")
        parsed = _extract_json_object(raw_text)
        normalized = _normalize_structured_report(parsed, raw_text)
        return {"provider": "chatgpt", "model": model, **normalized}

    if provider == "gemini":
        cfg = ai_settings.get("gemini") if isinstance(ai_settings.get("gemini"), dict) else {}
        api_key = str(cfg.get("api_key") or "").strip()
        model = str(cfg.get("model") or "gemini-2.5-flash-preview-09-2025").strip() or "gemini-2.5-flash-preview-09-2025"
        timeout_seconds = int(cfg.get("timeout_seconds") or 30)
        max_tokens = int(cfg.get("max_tokens") or 900)
        if not api_key:
            raise AIInvestigatorError("Gemini API key is not configured.")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": max(200, min(max_tokens, 4000)),
            },
        }
        response = _json_request(url, headers, payload, timeout_seconds)
        raw_text = _extract_gemini_text(response)
        if not raw_text:
            raise AIInvestigatorError("Gemini returned an empty report.")
        parsed = _extract_json_object(raw_text)
        normalized = _normalize_structured_report(parsed, raw_text)
        return {"provider": "gemini", "model": model, **normalized}

    raise AIInvestigatorError("Unsupported AI provider.")
