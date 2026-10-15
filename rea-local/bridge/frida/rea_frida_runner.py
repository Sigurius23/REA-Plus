#!/usr/bin/env python3
"""Small, bounded REA+-owned Frida adapter; caller code runs only on explicit request."""

import hashlib
import json
import math
import sys
import time

MAX_MESSAGES = 128
MAX_MESSAGE_TEXT_BYTES = 4096
MAX_TOTAL_MESSAGE_BYTES = 256 * 1024
MAX_DEVICE_COUNT = 128
MAX_PROCESS_COUNT = 512


def _bounded_text(value, limit=MAX_MESSAGE_TEXT_BYTES):
    text = str(value)
    prefix = text[:limit]
    encoded = prefix.encode("utf-8", errors="replace")
    if len(encoded) > limit:
        return encoded[:limit].decode("utf-8", errors="ignore"), True
    return prefix, len(text) > len(prefix)


def _plain_json(value, depth=0, state=None):
    if state is None:
        state = {"truncated": False}
    if depth > 12:
        state["truncated"] = True
        return "<maximum JSON depth reached>"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) <= (2**53 - 1) else str(value)
    if isinstance(value, str):
        text, truncated = _bounded_text(value)
        state["truncated"] = state["truncated"] or truncated
        return text
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            state["truncated"] = True
        return [_plain_json(item, depth + 1, state) for item in value[:256]]
    if isinstance(value, dict):
        if len(value) > 256:
            state["truncated"] = True
        result = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 256:
                break
            normalized_key, key_truncated = _bounded_text(key, 256)
            state["truncated"] = state["truncated"] or key_truncated
            result[normalized_key] = _plain_json(item, depth + 1, state)
        return result
    text, truncated = _bounded_text(value)
    state["truncated"] = state["truncated"] or truncated
    return text


def _device_record(device):
    return {
        "id": _bounded_text(device.id, 512)[0],
        "name": _bounded_text(device.name, 512)[0],
        "type": _bounded_text(device.type, 64)[0],
    }


def _select_device(frida, device_id):
    if device_id:
        return frida.get_device_manager().get_device(device_id, timeout=5000)
    return frida.get_local_device()


def _run(request):
    try:
        import frida
    except Exception as error:
        raise RuntimeError(
            "Frida Python bindings are unavailable in the configured interpreter"
        ) from error

    manager = frida.get_device_manager()
    operation = request.get("operation")
    base = {"frida_version": getattr(frida, "__version__", None)}

    if operation == "list_devices":
        devices = manager.enumerate_devices()
        base["devices"] = [_device_record(item) for item in devices[:MAX_DEVICE_COUNT]]
        base["omitted_device_count"] = max(0, len(devices) - MAX_DEVICE_COUNT)
        return base

    device = _select_device(frida, request.get("device_id"))
    base["device"] = _device_record(device)

    if operation == "list_processes":
        processes = device.enumerate_processes()
        records = []
        for item in processes[:MAX_PROCESS_COUNT]:
            records.append(
                {
                    "pid": int(item.pid),
                    "name": _bounded_text(item.name, 512)[0] or "<unnamed>",
                    "parameters": None,
                }
            )
        base["processes"] = records
        base["omitted_process_count"] = max(0, len(processes) - MAX_PROCESS_COUNT)
        return base

    if operation != "run_script":
        raise ValueError("Unsupported Frida operation")

    pid = int(request["pid"])
    process = next((item for item in device.enumerate_processes() if int(item.pid) == pid), None)
    if process is None:
        raise RuntimeError("The selected PID is not present on the selected Frida device")

    messages = []
    omitted = 0
    total_bytes = 0
    detached = False
    script_unloaded = False
    session = None
    script = None

    def on_message(message, data):
        nonlocal omitted, total_bytes
        if len(messages) >= MAX_MESSAGES:
            omitted += 1
            return
        kind = _bounded_text(message.get("type", "unknown"), 64)[0]
        record = {"type": kind}
        if kind == "send":
            projection = {"truncated": False}
            payload = _plain_json(message.get("payload"), state=projection)
            if projection["truncated"]:
                record["truncated"] = True
            try:
                payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except Exception:
                payload = _bounded_text(payload)[0]
                payload_bytes = str(payload).encode("utf-8", errors="replace")
            allowance = min(MAX_MESSAGE_TEXT_BYTES, max(0, MAX_TOTAL_MESSAGE_BYTES - total_bytes))
            if len(payload_bytes) > allowance:
                record["payload"] = payload_bytes[:allowance].decode("utf-8", errors="ignore")
                record["truncated"] = True
            else:
                record["payload"] = payload
            total_bytes += min(len(payload_bytes), allowance)
        elif kind in ("error", "log"):
            value = message.get("stack", message.get("description", message.get("message", "")))
            text, truncated = _bounded_text(value)
            record["text"] = text
            if message.get("stack"):
                record["stack"] = text
            if truncated:
                record["truncated"] = True
            total_bytes += len(text.encode("utf-8", errors="replace"))
        else:
            projection = {"truncated": False}
            record["payload"] = _plain_json(message, state=projection)
            if projection["truncated"]:
                record["truncated"] = True
        if data is not None:
            try:
                raw = bytes(data)
                record["data_bytes"] = len(raw)
                record["data_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
            except Exception:
                record["data_bytes"] = 0
        if total_bytes > MAX_TOTAL_MESSAGE_BYTES:
            omitted += 1
            return
        messages.append(record)

    try:
        session = device.attach(pid)
        script = session.create_script(request["script"])
        script.on("message", on_message)
        script.load()
        time.sleep(max(0.1, min(30.0, float(request["observation_ms"]) / 1000.0)))
    finally:
        if script is not None:
            try:
                script.unload()
                script_unloaded = True
            except Exception:
                script_unloaded = False
        if session is not None:
            try:
                session.detach()
                detached = True
            except Exception:
                detached = False

    base.update(
        {
            "process": {"pid": pid, "name": _bounded_text(process.name, 1024)[0] or "<unnamed>"},
            "observation_ms": int(request["observation_ms"]),
            "messages": messages,
            "omitted_message_count": omitted,
            "messages_truncated": omitted > 0 or total_bytes >= MAX_TOTAL_MESSAGE_BYTES,
            "script_unloaded": script_unloaded,
            "detached": detached,
        }
    )
    return base


def main():
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as request_file:
            request = json.load(request_file)
        result = _run(request)
        response = {"ok": True, "result": result}
        exit_code = 0
    except Exception as error:
        response = {
            "ok": False,
            "error": {
                "type": type(error).__name__,
                "message": _bounded_text(error, 2048)[0],
            },
        }
        exit_code = 1
    sys.stdout.write("__REA_FRIDA_JSON__")
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
